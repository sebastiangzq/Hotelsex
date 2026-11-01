-- =====================================================================
--  HotelSec · Ajustes para las rutas de negocio (idempotente)
-- =====================================================================

-- ---- A. CORRECCIÓN a evaluar_acceso (esquema original, paso 3 "recurso disponible") ----
-- El original bloqueaba TODA operación distinta de "leer" en modo de degradación segura.
-- Eso contradice la propia definición del proyecto (tabla operacion_sistema y pantalla de
-- Incidentes): en degradación deben seguir el check-in/out manual y la cuenta de emergencia, y
-- solo se bloquean las operaciones sensibles listadas. Además, con el bloqueo total el
-- Administrador no podría ni DESACTIVAR la degradación (configuracion/modificar).
-- Ahora la degradación la aplica el backend por operación (operacion_sistema.bloqueada_en_degradacion).
CREATE OR REPLACE FUNCTION evaluar_acceso(p_usuario uuid, p_recurso text, p_operacion text,
                               p_propietario_objeto uuid DEFAULT NULL)
RETURNS TABLE (permitido boolean, motivo text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    v_estado estado_identidad; v_rol text; v_rol_id smallint; v_permiso_id smallint;
BEGIN
    -- 1. identidad
    SELECT u.estado, r.nombre, u.rol_id INTO v_estado, v_rol, v_rol_id
      FROM usuario u JOIN rol r ON r.id = u.rol_id WHERE u.id = p_usuario;
    IF NOT FOUND OR v_estado <> 'activa' THEN
        motivo := 'Identidad inexistente o no activa'; permitido := false;
    ELSE
        -- 2. operación válida para el recurso
        SELECT p.id INTO v_permiso_id FROM permiso p
          JOIN recurso rc ON rc.id = p.recurso_id JOIN operacion op ON op.id = p.operacion_id
         WHERE rc.nombre = p_recurso AND op.nombre = p_operacion;
        IF v_permiso_id IS NULL THEN
            motivo := 'Operación no admitida para este recurso'; permitido := false;
        -- 3. (degradación segura: se aplica por operación en la tabla operacion_sistema, ver nota arriba)
        -- 4. permiso vigente para el rol
        ELSIF NOT EXISTS (SELECT 1 FROM rol_permiso rp
                           WHERE rp.rol_id = v_rol_id AND rp.permiso_id = v_permiso_id
                             AND rp.vigente_desde <= now()
                             AND (rp.vigente_hasta IS NULL OR rp.vigente_hasta > now())) THEN
            motivo := 'El rol ' || v_rol || ' no tiene un permiso vigente'; permitido := false;
        -- 5. contexto persona/objeto
        ELSIF v_rol = 'Recepcionista' AND p_operacion <> 'leer'
              AND p_propietario_objeto IS NOT NULL AND p_propietario_objeto <> p_usuario THEN
            motivo := 'Objeto ajeno a su asignación'; permitido := false;
        ELSIF v_rol = 'Auditor' AND p_operacion <> 'leer' THEN
            motivo := 'El Auditor solo puede observar'; permitido := false;
        ELSE
            motivo := 'Permiso concedido'; permitido := true;
        END IF;
    END IF;

    IF NOT permitido THEN
        INSERT INTO bitacora_auditoria (tipo, resultado, actor_id, actor_nombre, detalle)
        VALUES ('acceso_denegado', 'denegado', p_usuario,
                COALESCE((SELECT username FROM usuario WHERE id = p_usuario), 'desconocido'),
                p_operacion || ' · ' || p_recurso || ' → ' || motivo);
    END IF;
    RETURN NEXT;
END $$;

-- ---- B. Privilegios adicionales para que cada rol pueda hacer lo que la matriz le concede ----
-- (el esquema original daba al Administrador solo SELECT sobre huéspedes/estancias/pagos
--  aunque la matriz le concede crear/modificar)
GRANT INSERT, UPDATE ON huesped, estancia TO hotelsec_admin;
GRANT INSERT ON pago TO hotelsec_admin;
GRANT UPDATE (estado) ON habitacion TO hotelsec_admin;
GRANT UPDATE (fin) ON uso_cuenta_emergencia TO hotelsec_admin;
GRANT SELECT ON politica, control_verificable TO hotelsec_recepcion;   -- la pantalla Políticas es visible para todos los roles

CREATE SEQUENCE IF NOT EXISTS seq_codigo_estancia START 2041;
GRANT USAGE ON SEQUENCE seq_codigo_estancia TO hotelsec_admin, hotelsec_recepcion;

-- ---- C. Ejecución de los controles verificables (Parte 8) ----
-- Corre las consultas de control_verificable con privilegios del dueño: así el Auditor puede
-- verificar sin tener acceso directo a tablas sensibles. Las consultas no las puede modificar
-- ningún rol de la aplicación (solo tienen SELECT sobre control_verificable).
CREATE OR REPLACE FUNCTION ejecutar_controles()
RETURNS TABLE (control_id smallint, cumple boolean, filas_fallo bigint, error text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE c record; n bigint;
BEGIN
    FOR c IN SELECT id, prueba_sql FROM control_verificable ORDER BY id LOOP
        control_id := c.id;
        BEGIN
            EXECUTE 'SELECT count(*) FROM (' || c.prueba_sql || ') t' INTO n;
            cumple := (n = 0); filas_fallo := n; error := NULL;
        EXCEPTION WHEN others THEN
            cumple := false; filas_fallo := NULL; error := SQLERRM;
        END;
        RETURN NEXT;
    END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION ejecutar_controles() TO hotelsec_admin, hotelsec_auditor;

-- ---- D. El Auditor necesita mostrar NOMBRES de usuario en incidentes, usos de emergencia, etc. ----
-- Acceso por columnas: jamás password_hash, mfa_secreto_cifrado ni datos de contacto.
GRANT SELECT (id, codigo, username, estado) ON usuario TO hotelsec_auditor;
GRANT SELECT (id, codigo, alcance, activa, custodio_id) ON cuenta_emergencia TO hotelsec_auditor;
GRANT SELECT ON rol, restauracion TO hotelsec_auditor;
