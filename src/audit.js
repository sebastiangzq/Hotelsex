// Parte 4 · Auditoría. La bitácora la encadena por hash el propio trigger de la BD.
const { withRole, AUTH } = require('./db');

const limpiar = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500);  // evita inyección de líneas en logs

const SQL = `INSERT INTO bitacora_auditoria (tipo, resultado, actor_id, actor_nombre, ip_origen, detalle)
             VALUES ($1::tipo_evento, $2::resultado_evento, $3, $4, $5::inet, $6)`;
const params = (e) => [e.tipo, e.resultado, e.actorId || null, limpiar(e.actorNombre || 'anonimo').slice(0, 64), e.ip || null, limpiar(e.detalle)];

/** Registro independiente (su propia transacción: sobrevive aunque la operación falle) */
function registrar(e) {
  return withRole(AUTH, null, (c) => c.query(SQL, params(e)));
}
/** Registro dentro de la transacción de negocio (se confirma o se revierte junto con ella) */
function registrarEn(client, e) {
  return client.query(SQL, params(e));
}

module.exports = { registrar, registrarEn };
