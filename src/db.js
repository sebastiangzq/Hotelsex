// Acceso a PostgreSQL. La app entra como "hotelsec_app" (sin privilegios propios) y en cada
// transacción asume el rol de BD del usuario autenticado con SET LOCAL ROLE.
const { Pool } = require('pg');
const config = require('./config');

const ROL_BD = Object.freeze({
  Administrador: 'hotelsec_admin',
  Recepcionista: 'hotelsec_recepcion',
  Auditor: 'hotelsec_auditor',
});
const AUTH = 'hotelsec_auth';
const PERMITIDOS = new Set([AUTH, ...Object.values(ROL_BD)]);

const pool = new Pool({
  connectionString: config.databaseUrl,
  max: 10,
  idleTimeoutMillis: 30000,
  application_name: 'hotelsec-backend',
  statement_timeout: 15000,
});
pool.on('error', (e) => console.error('[db] error en conexión inactiva:', e.message));

/**
 * Ejecuta `fn(client)` en una transacción con el rol de BD indicado.
 * - COMMIT si fn termina bien, ROLLBACK si lanza.
 * - `actorId` queda disponible para los triggers (actor_actual()).
 * IMPORTANTE: lo que debe quedar registrado aunque la operación falle (denegaciones,
 * intentos de login) se ejecuta en SU PROPIA transacción, no dentro de la de negocio.
 */
async function withRole(rolBd, actorId, fn) {
  if (!PERMITIDOS.has(rolBd)) throw new Error('Rol de BD no permitido: ' + rolBd);   // lista blanca
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL ROLE ${rolBd}`);
    await client.query("SELECT set_config('hotelsec.actor', $1, true)", [actorId || '']);
    const r = await fn(client);
    await client.query('COMMIT');
    return r;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) { /* conexión ya caída */ }
    throw e;
  } finally {
    client.release();
  }
}

/** Parámetros de seguridad vigentes (tabla configuracion_sistema) */
async function leerConfig(client) {
  const { rows } = await client.query('SELECT clave, valor FROM configuracion_sistema');
  return Object.fromEntries(rows.map((r) => [r.clave, r.valor]));
}

module.exports = { pool, withRole, leerConfig, ROL_BD, AUTH };
