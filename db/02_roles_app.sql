-- =====================================================================
--  HotelSec · Roles de conexión de la aplicación (idempotente)
--  Modelo: la app se conecta con UNA cuenta de login sin privilegios propios
--  (hotelsec_app, NOINHERIT) y en cada transacción hace SET LOCAL ROLE al rol
--  de BD que corresponde al usuario autenticado. Así la base de datos hace
--  cumplir el mínimo privilegio aunque el código de la app tenga un error.
-- =====================================================================
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotelsec_auth') THEN
    CREATE ROLE hotelsec_auth NOLOGIN;      -- identidad "previa a autenticar": login y sesiones
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotelsec_app') THEN
    CREATE ROLE hotelsec_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END $$;

GRANT hotelsec_auth, hotelsec_admin, hotelsec_recepcion, hotelsec_auditor TO hotelsec_app;
GRANT USAGE ON SCHEMA public TO hotelsec_app, hotelsec_auth, hotelsec_admin, hotelsec_recepcion, hotelsec_auditor;

-- hotelsec_auth: solo lo necesario para autenticar y gestionar sesiones/2FA
GRANT SELECT ON usuario, rol, configuracion_sistema, operacion_sistema, cuenta_emergencia,
                intento_autenticacion, sesion, rol_permiso, permiso, recurso, operacion TO hotelsec_auth;
GRANT INSERT ON sesion, bitacora_auditoria TO hotelsec_auth;
GRANT UPDATE (ultima_actividad, expira_en, revocada_en, motivo_revocacion, mfa_verificado_en) ON sesion TO hotelsec_auth;
GRANT UPDATE (password_hash, password_cambiada_en, debe_cambiar_password,
              mfa_habilitado, mfa_secreto_cifrado) ON usuario TO hotelsec_auth;
GRANT EXECUTE ON FUNCTION registrar_intento_login(text, inet, boolean, text),
                          sesion_valida(bytea) TO hotelsec_auth;
