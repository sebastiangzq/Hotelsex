-- =====================================================================
--  HotelSec · Gestión Hotelera Segura
--  Base de datos relacional (PostgreSQL 13+)
--  Proyecto final · Seguridad de la Información
--
--  Roles de la aplicación: Administrador, Recepcionista, Auditor
--  Mapa Parte del proyecto -> secciones de este script
--    Parte 1  Identidades y ciclo de vida ......... sección 2
--    Parte 2  Autenticación ....................... sección 3
--    Parte 3  Autorización ........................ sección 4
--    Parte 4  Auditoría y trazabilidad ............ sección 6
--    Parte 5  Recuperación y continuidad .......... sección 7
--    Parte 6  Matriz de mínimo privilegio ......... sección 4 (+ vista)
--    Parte 7/8 Políticas y controles verificables . sección 8
--    Datos del negocio (huéspedes, estancias) ..... sección 5
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- digest() para la cadena de hashes
CREATE EXTENSION IF NOT EXISTS btree_gist;   -- evita reservas solapadas

-- ---------------------------------------------------------------------
-- 0. TIPOS
-- ---------------------------------------------------------------------
CREATE TYPE estado_identidad  AS ENUM ('activa', 'suspendida', 'revocada');
CREATE TYPE estado_solicitud  AS ENUM ('pendiente', 'aprobada', 'rechazada');
CREATE TYPE estado_estancia   AS ENUM ('reservada', 'hospedada', 'finalizada', 'anulada');
CREATE TYPE estado_habitacion AS ENUM ('libre', 'ocupada', 'limpieza');
CREATE TYPE metodo_pago       AS ENUM ('efectivo', 'tarjeta', 'transferencia', 'qr');
CREATE TYPE tipo_evento       AS ENUM ('autenticacion', 'autorizacion', 'cambio_rol', 'acceso_denegado',
                                       'cuenta_emergencia', 'configuracion', 'identidad', 'huesped', 'incidente');
CREATE TYPE resultado_evento  AS ENUM ('exito', 'fallo', 'denegado', 'solicitado');
CREATE TYPE severidad         AS ENUM ('baja', 'media', 'alta', 'critica');
CREATE TYPE estado_incidente  AS ENUM ('abierto', 'contenido', 'recuperado', 'cerrado');

-- ---------------------------------------------------------------------
-- 1. UTILIDADES GENERALES
-- ---------------------------------------------------------------------
-- Quién ejecuta la operación (la app lo fija por transacción con:
--   SELECT set_config('hotelsec.actor', '<uuid del usuario>', true);  )
CREATE FUNCTION actor_actual() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('hotelsec.actor', true), '')::uuid $$;

CREATE FUNCTION fn_rechazar_modificacion() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN
     RAISE EXCEPTION 'La tabla % es inalterable (append-only): operación % no permitida', TG_TABLE_NAME, TG_OP
       USING ERRCODE = 'insufficient_privilege';
   END $$;

-- Configuración del sistema (parámetros de seguridad y modo de degradación)
CREATE TABLE configuracion_sistema (
    clave           text PRIMARY KEY,
    valor           text NOT NULL,
    descripcion     text,
    actualizado_por uuid,
    actualizado_en  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO configuracion_sistema (clave, valor, descripcion) VALUES
 ('password_min_longitud',     '12',    'Longitud mínima de contraseña'),
 ('max_intentos_login',        '3',     'Intentos fallidos antes del bloqueo temporal'),
 ('bloqueo_segundos',          '30',    'Duración del bloqueo temporal tras superar los intentos'),
 ('sesion_duracion_minutos',   '30',    'Expiración de la sesión'),
 ('mfa_vigencia_minutos',      '5',     'Tiempo durante el cual vale una verificación 2FA para operaciones de alto riesgo'),
 ('modo_degradacion_segura',   'false', 'Si es true se bloquean las operaciones marcadas como degradables');

-- ---------------------------------------------------------------------
-- 2. PARTE 1 · IDENTIDADES Y CICLO DE VIDA
-- ---------------------------------------------------------------------
CREATE TABLE rol (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    nombre      text NOT NULL UNIQUE,
    descripcion text NOT NULL
);

CREATE SEQUENCE seq_codigo_usuario;

CREATE TABLE usuario (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo                 text NOT NULL UNIQUE DEFAULT 'USR-' || lpad(nextval('seq_codigo_usuario')::text, 3, '0'),
    username               text NOT NULL,
    nombre_completo        text NOT NULL,
    email                  text,
    rol_id                 smallint NOT NULL REFERENCES rol(id),
    -- Las identidades nuevas nacen "suspendidas" hasta que se les da de alta
    estado                 estado_identidad NOT NULL DEFAULT 'suspendida',
    estado_actualizado_en  timestamptz NOT NULL DEFAULT now(),
    -- Parte 2: credenciales (nunca texto plano)
    password_hash          text NOT NULL,
    password_cambiada_en   timestamptz NOT NULL DEFAULT now(),
    debe_cambiar_password  boolean NOT NULL DEFAULT true,
    intentos_fallidos      smallint NOT NULL DEFAULT 0 CHECK (intentos_fallidos >= 0),
    bloqueado_hasta        timestamptz,
    mfa_habilitado         boolean NOT NULL DEFAULT false,
    mfa_secreto_cifrado    bytea,                    -- secreto TOTP cifrado por la aplicación
    creado_por             uuid REFERENCES usuario(id),
    creado_en              timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT usuario_username_formato CHECK (username ~ '^[a-z0-9._-]{3,32}$'),
    -- Solo se aceptan hashes de funciones diseñadas para contraseñas (Argon2id / scrypt / bcrypt)
    CONSTRAINT usuario_hash_kdf CHECK (password_hash ~ '^\$(argon2id|scrypt|2[aby])\$'),
    CONSTRAINT usuario_mfa_coherente CHECK (NOT mfa_habilitado OR mfa_secreto_cifrado IS NOT NULL)
);
-- Identidad única sin distinguir mayúsculas
CREATE UNIQUE INDEX ux_usuario_username ON usuario (lower(username));
CREATE INDEX ix_usuario_rol ON usuario (rol_id);

-- Altas, bajas, suspensiones y reactivaciones (se llena sola vía trigger)
CREATE TABLE historial_estado_usuario (
    id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    usuario_id      uuid NOT NULL REFERENCES usuario(id),
    tipo_movimiento text NOT NULL CHECK (tipo_movimiento IN ('creacion','alta','suspension','reactivacion','baja')),
    estado_anterior estado_identidad,
    estado_nuevo    estado_identidad NOT NULL,
    realizado_por   uuid REFERENCES usuario(id),
    motivo          text,
    ocurrido_en     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_hist_estado_usuario ON historial_estado_usuario (usuario_id, ocurrido_en);

-- Cambios de rol: requieren solicitud + justificación + autorización de otra persona
CREATE TABLE solicitud_cambio_rol (
    id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    usuario_id      uuid NOT NULL REFERENCES usuario(id),
    rol_actual_id   smallint NOT NULL REFERENCES rol(id),
    rol_nuevo_id    smallint NOT NULL REFERENCES rol(id),
    justificacion   text NOT NULL CHECK (length(btrim(justificacion)) >= 5),
    solicitado_por  uuid NOT NULL REFERENCES usuario(id),
    solicitado_en   timestamptz NOT NULL DEFAULT now(),
    estado          estado_solicitud NOT NULL DEFAULT 'pendiente',
    resuelto_por    uuid REFERENCES usuario(id),
    resuelto_en     timestamptz,
    CONSTRAINT scr_roles_distintos   CHECK (rol_actual_id <> rol_nuevo_id),
    -- Separación de funciones: nadie aprueba su propio cambio de rol
    CONSTRAINT scr_no_autoaprobacion CHECK (resuelto_por IS NULL OR resuelto_por <> usuario_id),
    CONSTRAINT scr_resolucion_coherente CHECK (
        (estado = 'pendiente' AND resuelto_por IS NULL AND resuelto_en IS NULL) OR
        (estado <> 'pendiente' AND resuelto_por IS NOT NULL AND resuelto_en IS NOT NULL))
);
CREATE UNIQUE INDEX ux_scr_una_pendiente_por_usuario ON solicitud_cambio_rol (usuario_id) WHERE estado = 'pendiente';

-- 2.1 Trigger: al crear la identidad se deja constancia
CREATE FUNCTION fn_usuario_creacion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO historial_estado_usuario (usuario_id, tipo_movimiento, estado_anterior, estado_nuevo, realizado_por, motivo)
    VALUES (NEW.id, 'creacion', NULL, NEW.estado, COALESCE(NEW.creado_por, actor_actual()), 'Identidad creada');
    RETURN NEW;
END $$;
CREATE TRIGGER trg_usuario_creacion AFTER INSERT ON usuario
    FOR EACH ROW EXECUTE FUNCTION fn_usuario_creacion();

-- 2.2 Trigger: reglas del ciclo de vida
--   * una identidad revocada es irreversible e inmutable
--   * el rol solo cambia a través de una solicitud aprobada
--   * al suspender/revocar se cierran todas sus sesiones (no puede seguir operando)
CREATE FUNCTION fn_usuario_ciclo_vida() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v_tipo text;
BEGIN
    IF OLD.estado = 'revocada' THEN
        RAISE EXCEPTION 'La identidad % está revocada: es irreversible e inmutable', OLD.codigo
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF NEW.rol_id <> OLD.rol_id AND COALESCE(current_setting('hotelsec.cambio_rol_autorizado', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'El rol solo puede cambiar mediante una solicitud_cambio_rol aprobada'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF NEW.estado <> OLD.estado THEN
        NEW.estado_actualizado_en := now();
        v_tipo := CASE
            WHEN NEW.estado = 'revocada'   THEN 'baja'
            WHEN NEW.estado = 'suspendida' THEN 'suspension'
            WHEN EXISTS (SELECT 1 FROM historial_estado_usuario h
                          WHERE h.usuario_id = OLD.id AND h.estado_nuevo = 'activa') THEN 'reactivacion'
            ELSE 'alta' END;
        INSERT INTO historial_estado_usuario (usuario_id, tipo_movimiento, estado_anterior, estado_nuevo, realizado_por)
        VALUES (OLD.id, v_tipo, OLD.estado, NEW.estado, actor_actual());

        IF NEW.estado <> 'activa' THEN
            UPDATE sesion SET revocada_en = now(), motivo_revocacion = 'Identidad ' || NEW.estado
             WHERE usuario_id = OLD.id AND revocada_en IS NULL;
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Evita borrar identidades (se revocan, no se eliminan)
CREATE FUNCTION fn_usuario_no_borrar() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Las identidades no se eliminan: use estado = revocada' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER trg_usuario_no_borrar BEFORE DELETE ON usuario
    FOR EACH ROW EXECUTE FUNCTION fn_usuario_no_borrar();

-- 2.3 Trigger: aplicar el cambio de rol solo cuando se aprueba la solicitud
CREATE FUNCTION fn_aplicar_cambio_rol() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.estado = 'pendiente' AND NEW.estado = 'aprobada' THEN
        PERFORM set_config('hotelsec.cambio_rol_autorizado', 'on', true);
        UPDATE usuario SET rol_id = NEW.rol_nuevo_id WHERE id = NEW.usuario_id;
        PERFORM set_config('hotelsec.cambio_rol_autorizado', 'off', true);
        UPDATE sesion SET revocada_en = now(), motivo_revocacion = 'Cambio de rol'
         WHERE usuario_id = NEW.usuario_id AND revocada_en IS NULL;   -- obliga a re-autenticar con el nuevo rol
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_aplicar_cambio_rol AFTER UPDATE OF estado ON solicitud_cambio_rol
    FOR EACH ROW EXECUTE FUNCTION fn_aplicar_cambio_rol();

-- Una solicitud ya resuelta no se puede reabrir ni borrar
CREATE FUNCTION fn_solicitud_resuelta_inmutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.estado <> 'pendiente' THEN
        RAISE EXCEPTION 'Una solicitud de cambio de rol resuelta no puede modificarse ni eliminarse'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_solicitud_inmutable BEFORE UPDATE OR DELETE ON solicitud_cambio_rol
    FOR EACH ROW EXECUTE FUNCTION fn_solicitud_resuelta_inmutable();

-- ---------------------------------------------------------------------
-- 3. PARTE 2 · AUTENTICACIÓN (sesiones, intentos, cuentas de emergencia)
-- ---------------------------------------------------------------------
CREATE TABLE sesion (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id         uuid NOT NULL REFERENCES usuario(id),
    token_hash         bytea NOT NULL UNIQUE,              -- SHA-256 del token; el token nunca se guarda
    creada_en          timestamptz NOT NULL DEFAULT now(),
    expira_en          timestamptz NOT NULL,
    ultima_actividad   timestamptz NOT NULL DEFAULT now(),
    revocada_en        timestamptz,
    motivo_revocacion  text,
    mfa_verificado_en  timestamptz,                        -- último 2FA superado (operaciones de alto riesgo)
    ip_origen          inet,
    user_agent         text,
    CONSTRAINT sesion_expira_despues CHECK (expira_en > creada_en),
    CONSTRAINT sesion_token_sha256   CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX ix_sesion_usuario_vigente ON sesion (usuario_id) WHERE revocada_en IS NULL;

-- Solo identidades ACTIVAS pueden abrir sesión
CREATE FUNCTION fn_sesion_solo_activas() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF (SELECT estado FROM usuario WHERE id = NEW.usuario_id) <> 'activa' THEN
        RAISE EXCEPTION 'No se puede abrir sesión: la identidad no está activa' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_sesion_solo_activas BEFORE INSERT ON sesion
    FOR EACH ROW EXECUTE FUNCTION fn_sesion_solo_activas();

-- Validación de sesión: vigente + no revocada + identidad activa
CREATE FUNCTION sesion_valida(p_token_hash bytea) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT s.usuario_id
      FROM sesion s JOIN usuario u ON u.id = s.usuario_id
     WHERE s.token_hash = p_token_hash
       AND s.revocada_en IS NULL
       AND s.expira_en > now()
       AND u.estado = 'activa'
$$;

-- Registro de TODOS los intentos de autenticación. El motivo real queda aquí;
-- al usuario la aplicación siempre le muestra "Credenciales incorrectas".
CREATE TABLE intento_autenticacion (
    id                  bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    username_intentado  text NOT NULL,
    usuario_id          uuid REFERENCES usuario(id),     -- NULL si el usuario no existe
    ip_origen           inet,
    exitoso             boolean NOT NULL,
    motivo_interno      text,
    ocurrido_en         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_intento_ip_fecha ON intento_autenticacion (ip_origen, ocurrido_en);
CREATE INDEX ix_intento_usuario_fecha ON intento_autenticacion (usuario_id, ocurrido_en);

-- Cuentas de emergencia ("break-glass"): alcance acotado, uso siempre auditado y revisado
CREATE TABLE cuenta_emergencia (
    id             smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    codigo         text NOT NULL UNIQUE,
    password_hash  text NOT NULL CHECK (password_hash ~ '^\$(argon2id|scrypt|2[aby])\$'),
    alcance        text NOT NULL,
    activa         boolean NOT NULL DEFAULT false,       -- se habilita solo durante un incidente
    custodio_id    uuid NOT NULL REFERENCES usuario(id),
    creada_en      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE uso_cuenta_emergencia (
    id                  bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    cuenta_id           smallint NOT NULL REFERENCES cuenta_emergencia(id),
    usada_por_id        uuid NOT NULL REFERENCES usuario(id),
    incidente_id        bigint,                          -- FK se agrega tras crear "incidente"
    motivo              text NOT NULL CHECK (length(btrim(motivo)) >= 10),
    inicio              timestamptz NOT NULL DEFAULT now(),
    fin                 timestamptz,
    revisado_por        uuid REFERENCES usuario(id),     -- revisión posterior (debe ser Auditor; ver fn_validar_revision_emergencia)
    revisado_en         timestamptz,
    CONSTRAINT uce_fin_valido CHECK (fin IS NULL OR fin >= inicio),
    CONSTRAINT uce_revision_coherente CHECK ((revisado_por IS NULL) = (revisado_en IS NULL))
);

CREATE FUNCTION fn_validar_revision_emergencia() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.revisado_por IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM usuario u JOIN rol r ON r.id = u.rol_id
         WHERE u.id = NEW.revisado_por AND r.nombre = 'Auditor' AND u.estado = 'activa') THEN
        RAISE EXCEPTION 'El uso de una cuenta de emergencia solo puede ser revisado por un Auditor activo';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_validar_revision_emergencia BEFORE INSERT OR UPDATE ON uso_cuenta_emergencia
    FOR EACH ROW EXECUTE FUNCTION fn_validar_revision_emergencia();

-- ---------------------------------------------------------------------
-- 4. PARTES 3 y 6 · AUTORIZACIÓN Y MATRIZ DE MÍNIMO PRIVILEGIO
-- ---------------------------------------------------------------------
CREATE TABLE recurso (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    nombre      text NOT NULL UNIQUE,
    descripcion text
);
CREATE TABLE operacion (
    id     smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    nombre text NOT NULL UNIQUE
);

-- Catálogo de combinaciones válidas recurso × operación
-- (p. ej. la Bitácora solo admite "leer": no existe "bitácora/modificar")
CREATE TABLE permiso (
    id           smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    recurso_id   smallint NOT NULL REFERENCES recurso(id),
    operacion_id smallint NOT NULL REFERENCES operacion(id),
    UNIQUE (recurso_id, operacion_id)
);

-- Matriz rol × permiso. Lo que no está aquí se NIEGA (denegación por defecto)
CREATE TABLE rol_permiso (
    rol_id         smallint NOT NULL REFERENCES rol(id),
    permiso_id     smallint NOT NULL REFERENCES permiso(id),
    vigente_desde  timestamptz NOT NULL DEFAULT now(),
    vigente_hasta  timestamptz,
    concedido_por  uuid REFERENCES usuario(id),
    PRIMARY KEY (rol_id, permiso_id),
    CONSTRAINT rp_vigencia_valida CHECK (vigente_hasta IS NULL OR vigente_hasta > vigente_desde)
);

-- Operaciones críticas del sistema: riesgo, 2FA y comportamiento en degradación segura
CREATE TABLE operacion_sistema (
    clave                     text PRIMARY KEY,
    descripcion               text NOT NULL,
    riesgo                    text NOT NULL CHECK (riesgo IN ('bajo','alto')),
    requiere_2fa              boolean NOT NULL,
    bloqueada_en_degradacion  boolean NOT NULL,
    CONSTRAINT os_alto_riesgo_exige_2fa CHECK (riesgo <> 'alto' OR requiere_2fa)
);

-- Función de evaluación en el SERVIDOR con las 5 variables que pide el proyecto:
--   1 identidad autenticada · 2 operación solicitada · 3 recurso afectado
--   4 permisos vigentes     · 5 contexto (relación persona/objeto)
-- Si algo falla se deniega y se registra en la bitácora.
CREATE FUNCTION evaluar_acceso(p_usuario uuid, p_recurso text, p_operacion text,
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
        -- 3. recurso disponible (degradación segura: solo lectura)
        ELSIF p_operacion <> 'leer'
              AND (SELECT valor FROM configuracion_sistema WHERE clave = 'modo_degradacion_segura') = 'true' THEN
            motivo := 'Modo de degradación segura: el recurso está en solo lectura'; permitido := false;
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

-- ---------------------------------------------------------------------
-- 5. DATOS DEL NEGOCIO (huéspedes, habitaciones, estancias, pagos)
-- ---------------------------------------------------------------------
CREATE TABLE habitacion (
    id            smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    numero        text NOT NULL UNIQUE,
    tipo          text NOT NULL CHECK (tipo IN ('simple','doble','matrimonial','suite')),
    tarifa_noche  numeric(10,2) NOT NULL CHECK (tarifa_noche > 0),
    estado        estado_habitacion NOT NULL DEFAULT 'libre'
);

-- Protección de datos (Política 4): los datos personales se guardan CIFRADOS por la aplicación
-- (AES-256-GCM). La búsqueda de duplicados usa un HMAC del documento, no el documento.
CREATE TABLE huesped (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre_completo            text NOT NULL,
    documento_tipo             text NOT NULL DEFAULT 'CI' CHECK (documento_tipo IN ('CI','pasaporte','otro')),
    documento_cifrado          bytea,
    documento_hmac             bytea,                    -- HMAC-SHA256 con clave de la app
    documento_ultimos3         char(3),                  -- para mostrar "••••••123"
    nacionalidad               text NOT NULL DEFAULT 'Boliviana',
    telefono_cifrado           bytea,
    email_cifrado              bytea,
    fecha_nacimiento_cifrada   bytea,
    consentimiento_datos       boolean NOT NULL,
    consentimiento_en          timestamptz,
    datos_depurados            boolean NOT NULL DEFAULT false,
    depurado_en                timestamptz,
    registrado_por             uuid NOT NULL REFERENCES usuario(id),
    registrado_en              timestamptz NOT NULL DEFAULT now(),
    -- Sin consentimiento no se almacenan datos personales; al depurar solo queda lo mínimo
    CONSTRAINT huesped_consentimiento CHECK (datos_depurados OR (consentimiento_datos AND consentimiento_en IS NOT NULL)),
    CONSTRAINT huesped_depuracion_coherente CHECK (
        (NOT datos_depurados) OR
        (depurado_en IS NOT NULL AND documento_cifrado IS NULL AND telefono_cifrado IS NULL
         AND email_cifrado IS NULL AND fecha_nacimiento_cifrada IS NULL AND documento_hmac IS NULL))
);
CREATE INDEX ix_huesped_documento_hmac ON huesped (documento_hmac) WHERE documento_hmac IS NOT NULL;

CREATE TABLE estancia (
    id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    codigo          text NOT NULL UNIQUE,                -- p. ej. R-2041
    huesped_id      uuid NOT NULL REFERENCES huesped(id),
    habitacion_id   smallint NOT NULL REFERENCES habitacion(id),
    ingreso         date NOT NULL,
    salida          date NOT NULL,
    estado          estado_estancia NOT NULL DEFAULT 'reservada',
    registrada_por  uuid NOT NULL REFERENCES usuario(id),   -- "propietario" para el control de contexto
    registrada_en   timestamptz NOT NULL DEFAULT now(),
    anulada_por     uuid REFERENCES usuario(id),
    anulada_en      timestamptz,
    motivo_anulacion text,
    CONSTRAINT estancia_fechas CHECK (salida > ingreso),
    CONSTRAINT estancia_anulacion CHECK (
        (estado = 'anulada') = (anulada_por IS NOT NULL AND anulada_en IS NOT NULL AND motivo_anulacion IS NOT NULL)),
    -- Una habitación no puede tener dos estancias vigentes que se solapen
    CONSTRAINT estancia_sin_solape EXCLUDE USING gist (
        habitacion_id WITH =,
        daterange(ingreso, salida, '[)') WITH &&
    ) WHERE (estado IN ('reservada','hospedada'))
);
CREATE INDEX ix_estancia_huesped ON estancia (huesped_id);

-- Facturación: NUNCA se guarda el número de tarjeta, solo los últimos 4 dígitos
CREATE TABLE pago (
    id               bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    estancia_id      bigint NOT NULL REFERENCES estancia(id),
    metodo           metodo_pago NOT NULL,
    tarjeta_ultimos4 char(4),
    monto            numeric(10,2) NOT NULL CHECK (monto > 0),
    moneda           char(3) NOT NULL DEFAULT 'BOB',
    registrado_por   uuid NOT NULL REFERENCES usuario(id),
    pagado_en        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pago_tarjeta_ultimos4 CHECK (
        (metodo = 'tarjeta' AND tarjeta_ultimos4 ~ '^[0-9]{4}$') OR
        (metodo <> 'tarjeta' AND tarjeta_ultimos4 IS NULL))
);
CREATE INDEX ix_pago_estancia ON pago (estancia_id);
-- Los pagos son registros contables: no se editan ni se borran (una corrección es un nuevo registro)
CREATE TRIGGER trg_pago_inalterable BEFORE UPDATE OR DELETE ON pago
    FOR EACH ROW EXECUTE FUNCTION fn_rechazar_modificacion();

-- ---------------------------------------------------------------------
-- 6. PARTE 4 · AUDITORÍA Y TRAZABILIDAD (append-only + cadena de hashes)
-- ---------------------------------------------------------------------
CREATE TABLE bitacora_auditoria (
    id             bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    ocurrido_en    timestamptz NOT NULL DEFAULT clock_timestamp(),
    tipo           tipo_evento NOT NULL,
    resultado      resultado_evento NOT NULL,
    actor_id       uuid,                                  -- sin FK a propósito: la bitácora sobrevive a todo
    actor_nombre   text NOT NULL,                         -- copia (snapshot) del nombre de usuario
    ip_origen      inet,
    detalle        text NOT NULL,
    hash_previo    text NOT NULL,
    hash_registro  text NOT NULL UNIQUE
);
CREATE INDEX ix_bitacora_tipo_fecha ON bitacora_auditoria (tipo, ocurrido_en);
CREATE INDEX ix_bitacora_actor ON bitacora_auditoria (actor_id, ocurrido_en);

CREATE FUNCTION calcular_hash_bitacora(p_prev text, p_id bigint, p_ts timestamptz, p_tipo tipo_evento,
                                       p_res resultado_evento, p_actor uuid, p_actor_nombre text,
                                       p_ip inet, p_detalle text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(digest(convert_to(
        p_prev || '|' || p_id || '|' ||
        to_char(p_ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
        p_tipo || '|' || p_res || '|' || COALESCE(p_actor::text, '') || '|' ||
        p_actor_nombre || '|' || COALESCE(p_ip::text, '') || '|' || p_detalle, 'UTF8'), 'sha256'), 'hex')
$$;

CREATE FUNCTION fn_bitacora_encadenar() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_prev text;
BEGIN
    PERFORM pg_advisory_xact_lock(727001);                -- serializa inserciones: la cadena no se bifurca
    SELECT hash_registro INTO v_prev FROM bitacora_auditoria ORDER BY id DESC LIMIT 1;
    NEW.hash_previo   := COALESCE(v_prev, 'GENESIS');
    NEW.ocurrido_en   := clock_timestamp();
    NEW.hash_registro := calcular_hash_bitacora(NEW.hash_previo, NEW.id, NEW.ocurrido_en, NEW.tipo, NEW.resultado,
                                                NEW.actor_id, NEW.actor_nombre, NEW.ip_origen, NEW.detalle);
    RETURN NEW;
END $$;
CREATE TRIGGER trg_bitacora_encadenar BEFORE INSERT ON bitacora_auditoria
    FOR EACH ROW EXECUTE FUNCTION fn_bitacora_encadenar();

CREATE TRIGGER trg_bitacora_no_editar BEFORE UPDATE OR DELETE ON bitacora_auditoria
    FOR EACH ROW EXECUTE FUNCTION fn_rechazar_modificacion();
CREATE TRIGGER trg_bitacora_no_truncar BEFORE TRUNCATE ON bitacora_auditoria
    FOR EACH STATEMENT EXECUTE FUNCTION fn_rechazar_modificacion();

-- Verificación de integridad: devuelve el primer registro alterado (o 0 filas si todo es íntegro)
CREATE FUNCTION verificar_cadena_bitacora() RETURNS TABLE (id_alterado bigint, motivo text)
LANGUAGE plpgsql STABLE AS $$
DECLARE r record; v_prev text := 'GENESIS';
BEGIN
    FOR r IN SELECT * FROM bitacora_auditoria ORDER BY id LOOP
        IF r.hash_previo <> v_prev THEN
            id_alterado := r.id; motivo := 'Se rompió el encadenamiento (falta o cambió un registro anterior)'; RETURN NEXT; RETURN;
        END IF;
        IF r.hash_registro <> calcular_hash_bitacora(r.hash_previo, r.id, r.ocurrido_en, r.tipo, r.resultado,
                                                     r.actor_id, r.actor_nombre, r.ip_origen, r.detalle) THEN
            id_alterado := r.id; motivo := 'El contenido del registro no coincide con su hash'; RETURN NEXT; RETURN;
        END IF;
        v_prev := r.hash_registro;
    END LOOP;
END $$;

-- Registro de intentos de autenticación con control de fuerza bruta (Parte 2c)
CREATE FUNCTION registrar_intento_login(p_username text, p_ip inet, p_exitoso boolean, p_motivo text DEFAULT NULL)
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

    IF u.id IS NOT NULL THEN
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

-- ---------------------------------------------------------------------
-- 7. PARTE 5 · RECUPERACIÓN Y CONTINUIDAD
-- ---------------------------------------------------------------------
CREATE TABLE incidente (
    id                  bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tipo                text NOT NULL CHECK (tipo IN (
                          'compromiso_cuenta_privilegiada','indisponibilidad_servicio_identidad',
                          'alteracion_expedientes','perdida_corrupcion_registros','otro')),
    severidad           severidad NOT NULL,
    descripcion         text NOT NULL,
    estado              estado_incidente NOT NULL DEFAULT 'abierto',
    detectado_en        timestamptz NOT NULL DEFAULT now(),
    detectado_por       uuid REFERENCES usuario(id),
    responsable_id      uuid REFERENCES usuario(id),
    modo_degradacion    boolean NOT NULL DEFAULT false,   -- ¿se activó la degradación segura?
    respuesta_aplicada  text,
    cerrado_en          timestamptz,
    CONSTRAINT incidente_cierre CHECK ((estado = 'cerrado') = (cerrado_en IS NOT NULL))
);
ALTER TABLE uso_cuenta_emergencia
    ADD CONSTRAINT fk_uce_incidente FOREIGN KEY (incidente_id) REFERENCES incidente(id);

-- Respaldos verificables para restaurar tras corrupción o alteración
CREATE TABLE respaldo (
    id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    alcance         text NOT NULL CHECK (alcance IN ('completo','bitacora','expedientes','configuracion')),
    creado_en       timestamptz NOT NULL DEFAULT now(),
    ubicacion       text NOT NULL,
    sha256          char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    cifrado         boolean NOT NULL DEFAULT true,
    verificado_en   timestamptz,
    verificado_por  uuid REFERENCES usuario(id)
);

CREATE TABLE restauracion (
    id              bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    incidente_id    bigint NOT NULL REFERENCES incidente(id),
    respaldo_id     bigint NOT NULL REFERENCES respaldo(id),
    realizada_por   uuid NOT NULL REFERENCES usuario(id),
    autorizada_por  uuid NOT NULL REFERENCES usuario(id),
    realizada_en    timestamptz NOT NULL DEFAULT now(),
    resultado       text NOT NULL,
    CONSTRAINT restauracion_dos_personas CHECK (realizada_por <> autorizada_por)  -- control dual
);

-- ---------------------------------------------------------------------
-- 8. PARTES 7 y 8 · POLÍTICAS Y CONTROLES VERIFICABLES
-- ---------------------------------------------------------------------
CREATE TABLE politica (
    id          smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    codigo      text NOT NULL UNIQUE,
    titulo      text NOT NULL,
    regla       text NOT NULL
);
CREATE TABLE control_verificable (
    id              smallint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    politica_id     smallint NOT NULL REFERENCES politica(id),
    control         text NOT NULL,
    mecanismo       text NOT NULL,        -- dónde se implementa en la BD
    prueba_sql      text NOT NULL         -- consulta que devuelve filas SOLO si el control FALLA
);

-- ---------------------------------------------------------------------
-- 9. VISTAS
-- ---------------------------------------------------------------------
-- Matriz de mínimo privilegio (Parte 6): una fila por rol × recurso
CREATE VIEW v_matriz_minimo_privilegio AS
SELECT r.nombre AS rol, rc.nombre AS recurso,
       COALESCE(string_agg(op.nombre, ', ' ORDER BY op.id) FILTER (WHERE rp.permiso_id IS NOT NULL), '— (denegado)') AS operaciones
  FROM rol r CROSS JOIN recurso rc
  LEFT JOIN permiso p        ON p.recurso_id = rc.id
  LEFT JOIN operacion op     ON op.id = p.operacion_id
  LEFT JOIN rol_permiso rp   ON rp.permiso_id = p.id AND rp.rol_id = r.id
                            AND rp.vigente_desde <= now() AND (rp.vigente_hasta IS NULL OR rp.vigente_hasta > now())
 GROUP BY r.id, r.nombre, rc.id, rc.nombre
 ORDER BY r.id, rc.id;

-- El Auditor NO ve datos personales: solo datos no sensibles del huésped
CREATE VIEW v_huesped_auditor AS
SELECT id, nacionalidad, documento_tipo, '••••••' || documento_ultimos3 AS documento_enmascarado,
       datos_depurados, registrado_en
  FROM huesped;

CREATE VIEW v_usuarios_resumen AS
SELECT u.codigo, u.username, u.nombre_completo, r.nombre AS rol, u.estado, u.mfa_habilitado, u.bloqueado_hasta
  FROM usuario u JOIN rol r ON r.id = u.rol_id;

-- ---------------------------------------------------------------------
-- 10. TRIGGERS que dependen de tablas ya creadas
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_usuario_ciclo_vida BEFORE UPDATE ON usuario
    FOR EACH ROW EXECUTE FUNCTION fn_usuario_ciclo_vida();

-- ---------------------------------------------------------------------
-- 11. DATOS INICIALES (semilla)
-- ---------------------------------------------------------------------
INSERT INTO rol (nombre, descripcion) VALUES
 ('Administrador', 'Gestiona identidades, matriz de acceso y configuración; no edita la bitácora'),
 ('Recepcionista', 'Registra huéspedes, reservas y cobros en su operación diaria'),
 ('Auditor',       'Solo lectura: revisa reservas, facturación y bitácora; sin acceso a datos personales en claro');

INSERT INTO recurso (nombre, descripcion) VALUES
 ('reservas','Reservas y estancias'), ('expedientes_huespedes','Expedientes de huéspedes'),
 ('facturacion','Pagos y facturación'), ('configuracion','Parámetros del sistema'),
 ('bitacora','Bitácora de auditoría'), ('cuentas_emergencia','Cuentas break-glass');
INSERT INTO operacion (nombre) VALUES ('leer'), ('crear'), ('modificar'), ('eliminar');

-- Catálogo válido: todas las combinaciones salvo las que no tienen sentido
INSERT INTO permiso (recurso_id, operacion_id)
SELECT rc.id, op.id FROM recurso rc CROSS JOIN operacion op
 WHERE NOT (rc.nombre = 'bitacora' AND op.nombre <> 'leer');    -- la bitácora es inalterable

-- Matriz de mínimo privilegio (igual a la del prototipo HotelSec)
INSERT INTO rol_permiso (rol_id, permiso_id)
SELECT r.id, p.id
  FROM (VALUES
    ('Administrador','reservas','leer'),('Administrador','reservas','crear'),('Administrador','reservas','modificar'),('Administrador','reservas','eliminar'),
    ('Administrador','expedientes_huespedes','leer'),('Administrador','expedientes_huespedes','crear'),('Administrador','expedientes_huespedes','modificar'),('Administrador','expedientes_huespedes','eliminar'),
    ('Administrador','facturacion','leer'),('Administrador','facturacion','crear'),('Administrador','facturacion','modificar'),('Administrador','facturacion','eliminar'),
    ('Administrador','configuracion','leer'),('Administrador','configuracion','modificar'),
    ('Administrador','bitacora','leer'),
    ('Administrador','cuentas_emergencia','leer'),('Administrador','cuentas_emergencia','modificar'),
    ('Recepcionista','reservas','leer'),('Recepcionista','reservas','crear'),('Recepcionista','reservas','modificar'),
    ('Recepcionista','expedientes_huespedes','leer'),('Recepcionista','expedientes_huespedes','crear'),('Recepcionista','expedientes_huespedes','modificar'),
    ('Recepcionista','facturacion','leer'),('Recepcionista','facturacion','crear'),
    ('Auditor','reservas','leer'),('Auditor','expedientes_huespedes','leer'),
    ('Auditor','facturacion','leer'),('Auditor','bitacora','leer')
  ) AS m(rol, recurso, operacion)
  JOIN rol r        ON r.nombre = m.rol
  JOIN recurso rc   ON rc.nombre = m.recurso
  JOIN operacion op ON op.nombre = m.operacion
  JOIN permiso p    ON p.recurso_id = rc.id AND p.operacion_id = op.id;

INSERT INTO operacion_sistema (clave, descripcion, riesgo, requiere_2fa, bloqueada_en_degradacion) VALUES
 ('iniciar_sesion',      'Inicio de sesión con 2FA',                        'bajo', false, false),
 ('consultar_reservas',  'Consulta de reservas (solo lectura)',             'bajo', false, false),
 ('check_in_out_manual', 'Check-in / check-out manual',                     'bajo', false, false),
 ('cuenta_emergencia',   'Uso de cuenta de emergencia (break-glass)',       'bajo', false, false),
 ('registrar_bitacora',  'Registro en bitácora (siempre activo)',           'bajo', false, false),
 ('crear_identidad',     'Crear identidades',                               'alto', true,  true),
 ('cambiar_estado',      'Cambiar estado de identidades (revocar, etc.)',   'alto', true,  true),
 ('cambiar_rol',         'Solicitar / aprobar cambios de rol',              'alto', true,  true),
 ('modificar_matriz',    'Modificar la matriz de acceso',                   'alto', true,  true),
 ('exportar_bitacora',   'Exportar bitácora',                               'alto', true,  true),
 ('anular_reserva',      'Anular reservas',                                 'alto', true,  true);

-- Usuarios de demostración (contraseñas hasheadas con Argon2id: m=64MiB, t=3, p=4)
--   admin / Admin#2026 · recepcion / Recep#2026 · auditor / Audit#2026 · jperez y mvargas / Temp#2026
INSERT INTO usuario (username, nombre_completo, rol_id, estado, password_hash, debe_cambiar_password)
SELECT v.username, v.nombre, r.id, 'suspendida', v.hash, false
  FROM (VALUES
   ('admin',     'Carla Mendoza', 'Administrador', '$argon2id$v=19$m=65536,t=3,p=4$eLCtsrt2IsfGUHtK/rt+pw$x26979kvQAAX2q0bkRt1Lb/R8O+yTYjpw6H9rXWcS7E'),
   ('recepcion', 'Luis Quispe',   'Recepcionista', '$argon2id$v=19$m=65536,t=3,p=4$PvWCyl1iBR10Nh8LqgNBVw$2DoMpzdQPFoS0f7YL10mAug4OKmc83pjxGg//W9krhQ'),
   ('auditor',   'Ana Rojas',     'Auditor',       '$argon2id$v=19$m=65536,t=3,p=4$MrXJrenxMfLhBCb6N7RA3A$5sXEROEXY+jrR2zpzgruW40CVio1e0wjzcBJemzycjs'),
   ('jperez',    'Jorge Pérez',   'Recepcionista', '$argon2id$v=19$m=65536,t=3,p=4$8h6YuELWsg9xCFMJpYoIoA$z38SI3F8NINwbwFDO6xIy0QKyaHKb26QJYaRrTkFYqQ'),
   ('mvargas',   'María Vargas',  'Auditor',       '$argon2id$v=19$m=65536,t=3,p=4$8h6YuELWsg9xCFMJpYoIoA$z38SI3F8NINwbwFDO6xIy0QKyaHKb26QJYaRrTkFYqQ')
  ) AS v(username, nombre, rol, hash)
  JOIN rol r ON r.nombre = v.rol;
-- Alta de los tres usuarios de trabajo (pasa por el ciclo de vida: queda en historial)
UPDATE usuario SET estado = 'activa' WHERE username IN ('admin','recepcion','auditor');
UPDATE usuario SET estado = 'activa' WHERE username IN ('jperez','mvargas');
UPDATE usuario SET estado = 'suspendida' WHERE username = 'jperez';
UPDATE usuario SET estado = 'revocada'   WHERE username = 'mvargas';

INSERT INTO cuenta_emergencia (codigo, password_hash, alcance, activa, custodio_id)
SELECT 'breakglass-01',
       '$argon2id$v=19$m=65536,t=3,p=4$zbtkQU2B9ZxpChoFQ0hQgg$BOjIimrXN7ne8LG8au9E0UCsSoSiDjDqqapMwEB38qA',
       'Solo consulta de reservas y check-in/check-out manual durante caída del servicio de identidad',
       false, id
  FROM usuario WHERE username = 'admin';

INSERT INTO habitacion (numero, tipo, tarifa_noche, estado)
SELECT (100 + g)::text,
       (ARRAY['simple','doble','matrimonial','suite'])[1 + g % 4],
       (ARRAY[180,260,300,520])[1 + g % 4],
       (ARRAY['ocupada','libre','limpieza'])[1 + (g * 7 + 3) % 3]::estado_habitacion
  FROM generate_series(1, 18) g;

INSERT INTO politica (codigo, titulo, regla) VALUES
 ('P1','Gestión de identidades y cuentas','Cada persona tiene una identidad única; las altas, bajas y cambios quedan controlados; una identidad revocada no se reactiva.'),
 ('P2','Autenticación y protección de credenciales','Contraseñas con Argon2id, bloqueo por intentos, sesiones con expiración, 2FA en alto riesgo, mensajes que no revelan si la cuenta existe.'),
 ('P3','Autorización y mínimo privilegio','Cada rol solo tiene lo estrictamente necesario; todo lo no concedido se deniega y se evalúa en el servidor.'),
 ('P4','Protección de datos','Datos personales cifrados, consentimiento obligatorio, no se guarda el número de tarjeta, depuración al finalizar la estancia.'),
 ('P5','Registro, monitoreo y auditoría','Todo evento relevante va a una bitácora append-only encadenada por hash y verificable.'),
 ('P6','Desarrollo seguro y gestión de cambios','Los cambios de configuración y de rol se solicitan, justifican, autorizan y quedan registrados.'),
 ('P7','Continuidad operativa y respuesta a incidentes','Los incidentes se registran, se responde con degradación segura y se recupera desde respaldos verificados con control dual.'),
 ('P8','Excepciones y cuentas de emergencia','Las cuentas break-glass están desactivadas por defecto, su uso exige motivo y es revisado por un Auditor.');

INSERT INTO control_verificable (politica_id, control, mecanismo, prueba_sql)
SELECT p.id, c.control, c.mecanismo, c.prueba
  FROM (VALUES
   ('P1','Identificadores de usuario únicos','Índice único ux_usuario_username',
        'SELECT lower(username) FROM usuario GROUP BY 1 HAVING count(*) > 1'),
   ('P1','Nadie revocado vuelve a estar activo','Trigger fn_usuario_ciclo_vida + historial_estado_usuario',
        'SELECT usuario_id FROM historial_estado_usuario h WHERE h.estado_anterior = ''revocada'''),
   ('P1','Identidades no activas sin sesiones vigentes','Trigger que revoca sesiones al suspender/revocar',
        'SELECT s.id FROM sesion s JOIN usuario u ON u.id = s.usuario_id WHERE u.estado <> ''activa'' AND s.revocada_en IS NULL AND s.expira_en > now()'),
   ('P2','Todas las contraseñas usan una KDF de contraseñas','CHECK usuario_hash_kdf',
        'SELECT id FROM usuario WHERE password_hash !~ ''^\$(argon2id|scrypt|2[aby])\$'''),
   ('P2','Las sesiones expiran','CHECK sesion_expira_despues + función sesion_valida',
        'SELECT id FROM sesion WHERE expira_en <= creada_en'),
   ('P3','No existen permisos sobre la bitácora distintos de leer','Catálogo permiso sin bitácora/modificar',
        'SELECT p.id FROM permiso p JOIN recurso r ON r.id = p.recurso_id JOIN operacion o ON o.id = p.operacion_id WHERE r.nombre = ''bitacora'' AND o.nombre <> ''leer'''),
   ('P3','El Auditor no tiene permisos de escritura','Matriz rol_permiso',
        'SELECT 1 FROM rol_permiso rp JOIN rol r ON r.id = rp.rol_id JOIN permiso p ON p.id = rp.permiso_id JOIN operacion o ON o.id = p.operacion_id WHERE r.nombre = ''Auditor'' AND o.nombre <> ''leer'''),
   ('P3','Nadie aprobó su propio cambio de rol','CHECK scr_no_autoaprobacion',
        'SELECT id FROM solicitud_cambio_rol WHERE resuelto_por = usuario_id'),
   ('P4','No hay datos personales sin consentimiento','CHECK huesped_consentimiento',
        'SELECT id FROM huesped WHERE NOT datos_depurados AND NOT consentimiento_datos'),
   ('P4','Pagos con tarjeta solo guardan 4 dígitos','CHECK pago_tarjeta_ultimos4',
        'SELECT id FROM pago WHERE tarjeta_ultimos4 IS NOT NULL AND tarjeta_ultimos4 !~ ''^[0-9]{4}$'''),
   ('P4','Estancias finalizadas sin datos personales en claro','CHECK huesped_depuracion_coherente',
        'SELECT h.id FROM huesped h JOIN estancia e ON e.huesped_id = h.id WHERE e.estado = ''finalizada'' AND NOT h.datos_depurados AND NOT EXISTS (SELECT 1 FROM estancia e2 WHERE e2.huesped_id = h.id AND e2.estado IN (''reservada'',''hospedada''))'),
   ('P5','La cadena de hashes de la bitácora es íntegra','Función verificar_cadena_bitacora()',
        'SELECT * FROM verificar_cadena_bitacora()'),
   ('P5','La bitácora no admite UPDATE/DELETE/TRUNCATE','Triggers trg_bitacora_no_editar / no_truncar',
        'SELECT 1 FROM pg_trigger WHERE tgrelid = ''bitacora_auditoria''::regclass AND tgname IN (''trg_bitacora_no_editar'',''trg_bitacora_no_truncar'') HAVING count(*) < 2'),
   ('P6','Todo cambio de estado de identidad quedó en el historial','Trigger fn_usuario_ciclo_vida',
        'SELECT u.id FROM usuario u WHERE NOT EXISTS (SELECT 1 FROM historial_estado_usuario h WHERE h.usuario_id = u.id)'),
   ('P7','Las restauraciones usan un respaldo verificado y dos personas distintas','CHECK restauracion_dos_personas',
        'SELECT r.id FROM restauracion r JOIN respaldo b ON b.id = r.respaldo_id WHERE b.verificado_en IS NULL OR r.realizada_por = r.autorizada_por'),
   ('P8','Las cuentas de emergencia están desactivadas por defecto','cuenta_emergencia.activa DEFAULT false',
        'SELECT id FROM cuenta_emergencia WHERE activa AND NOT EXISTS (SELECT 1 FROM incidente i WHERE i.estado IN (''abierto'',''contenido''))'),
   ('P8','Todo uso de emergencia tiene motivo y revisión de un Auditor','CHECK uce + trigger fn_validar_revision_emergencia',
        'SELECT id FROM uso_cuenta_emergencia WHERE revisado_por IS NULL AND inicio < now() - interval ''72 hours''')
  ) AS c(pol, control, mecanismo, prueba)
  JOIN politica p ON p.codigo = c.pol;

-- Eventos iniciales de configuración en la bitácora
INSERT INTO bitacora_auditoria (tipo, resultado, actor_nombre, detalle) VALUES
 ('configuracion', 'exito', 'sistema', 'Esquema HotelSec instalado y matriz de mínimo privilegio cargada');

-- ---------------------------------------------------------------------
-- 12. ROLES DE BASE DE DATOS (defensa en profundidad)
--     La aplicación se conecta con una cuenta de servicio distinta según el rol del usuario
--     autenticado o, como mínimo, nunca con un superusuario. Cambie las contraseñas.
-- ---------------------------------------------------------------------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotelsec_admin')     THEN CREATE ROLE hotelsec_admin     NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotelsec_recepcion') THEN CREATE ROLE hotelsec_recepcion NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotelsec_auditor')   THEN CREATE ROLE hotelsec_auditor   NOLOGIN; END IF;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Administrador: gestiona identidades/configuración/incidentes; la bitácora solo se lee e inserta
GRANT SELECT, INSERT, UPDATE ON usuario, rol_permiso, configuracion_sistema, cuenta_emergencia,
      solicitud_cambio_rol, incidente, respaldo TO hotelsec_admin;
GRANT SELECT, INSERT ON historial_estado_usuario, restauracion, uso_cuenta_emergencia, sesion,
      intento_autenticacion, bitacora_auditoria, politica, control_verificable TO hotelsec_admin;
GRANT SELECT ON rol, recurso, operacion, permiso, operacion_sistema, habitacion, huesped, estancia, pago,
      v_matriz_minimo_privilegio, v_usuarios_resumen TO hotelsec_admin;
GRANT UPDATE ON sesion TO hotelsec_admin;

-- Recepcionista: opera huéspedes, estancias y cobros; sin acceso a identidades ni bitácora
GRANT SELECT, INSERT, UPDATE ON huesped, estancia TO hotelsec_recepcion;
GRANT SELECT, INSERT ON pago TO hotelsec_recepcion;
GRANT SELECT ON habitacion TO hotelsec_recepcion;
GRANT UPDATE (estado) ON habitacion TO hotelsec_recepcion;
GRANT INSERT ON bitacora_auditoria TO hotelsec_recepcion;
GRANT SELECT ON rol, recurso, operacion, permiso, rol_permiso, operacion_sistema TO hotelsec_recepcion;

-- Auditor: solo lectura; los datos personales solo a través de la vista enmascarada
GRANT SELECT ON bitacora_auditoria, estancia, pago, habitacion, v_huesped_auditor, v_matriz_minimo_privilegio,
      v_usuarios_resumen, historial_estado_usuario, solicitud_cambio_rol, uso_cuenta_emergencia,
      incidente, respaldo, politica, control_verificable TO hotelsec_auditor;
GRANT UPDATE (revisado_por, revisado_en) ON uso_cuenta_emergencia TO hotelsec_auditor;   -- revisar el uso de break-glass
GRANT INSERT ON bitacora_auditoria TO hotelsec_auditor;
-- (Las secuencias IDENTITY necesitan USAGE para insertar; con GENERATED ALWAYS AS IDENTITY no hace falta.)
GRANT USAGE ON SEQUENCE seq_codigo_usuario TO hotelsec_admin;

GRANT EXECUTE ON FUNCTION verificar_cadena_bitacora(), evaluar_acceso(uuid,text,text,uuid),
      registrar_intento_login(text,inet,boolean,text), sesion_valida(bytea) TO hotelsec_admin, hotelsec_auditor;
GRANT EXECUTE ON FUNCTION evaluar_acceso(uuid,text,text,uuid), registrar_intento_login(text,inet,boolean,text),
      sesion_valida(bytea) TO hotelsec_recepcion;
