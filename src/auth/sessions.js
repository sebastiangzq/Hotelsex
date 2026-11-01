// Parte 2d · Sesiones. El token viaja en una cookie HttpOnly; en la BD solo se guarda su SHA-256.
const config = require('../config');
const { withRole, leerConfig, AUTH, ROL_BD } = require('../db');
const { sha256, tokenAleatorio } = require('../crypto');

async function crear(client, { usuarioId, ip, userAgent, minutos }) {
  const token = tokenAleatorio();
  await client.query(
    `INSERT INTO sesion (usuario_id, token_hash, expira_en, ip_origen, user_agent)
     VALUES ($1, $2, now() + make_interval(mins => $3::int), $4::inet, $5)`,
    [usuarioId, sha256(token), minutos, ip || null, (userAgent || '').slice(0, 300)]);
  return token;
}

/** Valida el token (vigente, no revocado, identidad ACTIVA) y renueva por inactividad. Devuelve null si no vale. */
function buscar(token) {
  return withRole(AUTH, null, async (c) => {
    const h = sha256(token);
    const v = await c.query('SELECT sesion_valida($1) AS uid', [h]);
    if (!v.rows[0].uid) return null;
    const { rows } = await c.query(
      `SELECT s.id AS sesion_id, s.creada_en, u.id, u.codigo, u.username, u.nombre_completo AS nombre,
              r.nombre AS rol, u.debe_cambiar_password, u.mfa_habilitado
         FROM sesion s JOIN usuario u ON u.id = s.usuario_id JOIN rol r ON r.id = u.rol_id
        WHERE s.token_hash = $1`, [h]);
    const s = rows[0];
    if (!s || !ROL_BD[s.rol]) return null;
    if (Date.now() - s.creada_en.getTime() > config.sesionAbsolutaHoras * 3600 * 1000) {
      await c.query(`UPDATE sesion SET revocada_en = now(), motivo_revocacion = 'Vida máxima de la sesión' WHERE id = $1`, [s.sesion_id]);
      return null;
    }
    const cfg = await leerConfig(c);
    await c.query(
      `UPDATE sesion SET ultima_actividad = now(),
              expira_en = LEAST(now() + make_interval(mins => $2::int), creada_en + make_interval(hours => $3::int))
        WHERE id = $1 AND ultima_actividad < now() - interval '15 seconds'`,
      [s.sesion_id, parseInt(cfg.sesion_duracion_minutos, 10) || 30, config.sesionAbsolutaHoras]);
    return s;
  });
}

const revocar = (sesionId, motivo) => withRole(AUTH, null, (c) =>
  c.query(`UPDATE sesion SET revocada_en = now(), motivo_revocacion = $2 WHERE id = $1 AND revocada_en IS NULL`, [sesionId, motivo]));

/** Cierra todas las sesiones del usuario salvo (opcionalmente) la actual */
const revocarOtras = (client, usuarioId, exceptoId, motivo) =>
  client.query(`UPDATE sesion SET revocada_en = now(), motivo_revocacion = $3
                 WHERE usuario_id = $1 AND revocada_en IS NULL AND ($2::uuid IS NULL OR id <> $2::uuid)`,
               [usuarioId, exceptoId || null, motivo]);

module.exports = { crear, buscar, revocar, revocarOtras };
