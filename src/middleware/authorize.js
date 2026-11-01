// Parte 3 · Control de acceso EN EL SERVIDOR. Evalúa, en este orden y denegando por defecto:
//   identidad -> operación válida -> degradación segura -> permiso vigente -> contexto persona/objeto -> 2FA
// Las denegaciones quedan en la bitácora (las inserta evaluar_acceso) y se confirman en su
// propia transacción, de modo que no se pierden cuando la petición termina en error.
const { withRole, leerConfig, AUTH } = require('../db');
const { wrap } = require('../util');

/**
 * guard({ recurso, operacion, sistema, propietario })
 *  recurso/operacion : nombres de la matriz (p. ej. 'expedientes_huespedes', 'crear')
 *  sistema           : clave de operacion_sistema (2FA / degradación), opcional
 *  propietario(req)  : async -> uuid del dueño del objeto (contexto persona/objeto), opcional
 */
function guard({ recurso, operacion, sistema, propietario }) {
  return wrap(async (req, res, next) => {
    const u = req.user;
    const dueno = propietario ? await propietario(req) : null;

    // 1-5. evaluar_acceso (función de la BD con las 5 variables del proyecto)
    const ev = await withRole(u.dbRole, u.id, (c) =>
      c.query('SELECT permitido, motivo FROM evaluar_acceso($1, $2, $3, $4)', [u.id, recurso, operacion, dueno]));
    if (!ev.rows[0].permitido) {
      return res.status(403).json({ error: 'Acceso denegado', codigo: 'DENEGADO' });   // el motivo detallado queda solo en la bitácora
    }

    // Operaciones del sistema: degradación segura y segundo factor
    if (sistema) {
      const info = await withRole(AUTH, null, async (c) => {
        const os = await c.query('SELECT * FROM operacion_sistema WHERE clave = $1', [sistema]);
        const cfg = await leerConfig(c);
        const mfa = await c.query(
          `SELECT 1 FROM sesion WHERE id = $1 AND mfa_verificado_en > now() - make_interval(mins => $2::int)`,
          [u.sesionId, parseInt(cfg.mfa_vigencia_minutos, 10) || 5]);
        return { os: os.rows[0], degradado: cfg.modo_degradacion_segura === 'true', mfaVigente: mfa.rowCount > 0 };
      });
      if (!info.os) throw new Error('Operación del sistema no definida: ' + sistema);

      if (info.os.bloqueada_en_degradacion && info.degradado) {
        await req.audit('acceso_denegado', 'denegado', `“${info.os.descripcion}” bloqueada por modo de degradación segura`);
        return res.status(423).json({ error: 'Operación bloqueada por el modo de degradación segura', codigo: 'DEGRADACION_ACTIVA' });
      }
      if (info.os.requiere_2fa && !info.mfaVigente) {
        return res.status(403).json({
          error: u.mfaHabilitado ? 'Se requiere verificar el segundo factor' : 'Debe configurar el segundo factor (2FA) para esta operación',
          codigo: u.mfaHabilitado ? 'MFA_REQUERIDO' : 'MFA_NO_CONFIGURADO',
          operacion: info.os.descripcion,
        });
      }
    }
    next();
  });
}

module.exports = { guard };
