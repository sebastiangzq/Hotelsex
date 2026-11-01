-- =====================================================================
--  CORRECCIÓN al esquema original (01): registrar_intento_login
--  Problema: ante un intento de login sobre una identidad REVOCADA, la función hacía
--  UPDATE usuario (contador de fallos) y el trigger fn_usuario_ciclo_vida lo rechaza
--  ("identidad revocada: inmutable"). Efectos: (1) el cliente recibía ese mensaje, que
--  revela que la cuenta existe; (2) el intento no quedaba registrado (rollback).
--  Solución: igual que antes, pero sin tocar el contador de una identidad revocada
--  (ya no puede iniciar sesión de todas formas). El intento SÍ se registra.
-- =====================================================================
CREATE OR REPLACE FUNCTION registrar_intento_login(p_username text, p_ip inet, p_exitoso boolean, p_motivo text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    u usuario%ROWTYPE;
    v_max int := (SELECT valor::int FROM configuracion_sistema WHERE clave = 'max_intentos_login');
    v_seg int := (SELECT valor::int FROM configuracion_sistema WHERE clave = 'bloqueo_segundos');
BEGIN
    SELECT * INTO u FROM usuario WHERE lower(username) = lower(p_username);
    INSERT INTO intento_autenticacion (username_intentado, usuario_id, ip_origen, exitoso, motivo_interno)
    VALUES (p_username, u.id, p_ip, p_exitoso,
            COALESCE(p_motivo, CASE WHEN u.id IS NULL THEN 'usuario inexistente'
                                    WHEN u.estado <> 'activa' THEN 'cuenta ' || u.estado
                                    WHEN NOT p_exitoso THEN 'contraseña incorrecta' END));
    INSERT INTO bitacora_auditoria (tipo, resultado, actor_id, actor_nombre, ip_origen, detalle)
    VALUES ('autenticacion', CASE WHEN p_exitoso THEN 'exito' ELSE 'fallo' END::resultado_evento, u.id,
            COALESCE(u.username, NULLIF(left(p_username, 64), ''), 'anonimo'), p_ip,
            CASE WHEN p_exitoso THEN 'Inicio de sesión correcto' ELSE COALESCE(p_motivo, 'Credenciales incorrectas') END);

    IF u.id IS NOT NULL AND u.estado <> 'revocada' THEN          -- <- única diferencia con el original
        IF p_exitoso THEN
            UPDATE usuario SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = u.id;
        ELSE
            UPDATE usuario
               SET intentos_fallidos = CASE WHEN intentos_fallidos + 1 >= v_max THEN 0 ELSE intentos_fallidos + 1 END,
                   bloqueado_hasta   = CASE WHEN intentos_fallidos + 1 >= v_max THEN now() + make_interval(secs => v_seg)
                                            ELSE bloqueado_hasta END
             WHERE id = u.id;
            IF u.intentos_fallidos + 1 >= v_max THEN
                INSERT INTO bitacora_auditoria (tipo, resultado, actor_id, actor_nombre, ip_origen, detalle)
                VALUES ('autenticacion', 'fallo', u.id, u.username, p_ip,
                        'Bloqueo temporal de ' || v_seg || ' s tras ' || v_max || ' intentos fallidos');
            END IF;
        END IF;
    END IF;
END $$;
