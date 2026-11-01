// Parte 1 · Identidades y su ciclo de vida (crear, estados, cambio de rol con aprobación)
// Todas las operaciones sensibles exigen: permiso en la matriz + 2FA vigente + no estar en degradación.
const express = require('express');
const { withRole, ROL_BD } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto, enumerado, entero } = require('../validar');
const audit = require('../audit');
const pw = require('../auth/password');
const { passwordTemporal } = require('../crypto');

const router = express.Router();
router.use(requireSession());

const LECTURA = guard({ recurso: 'configuracion', operacion: 'leer' });
const mod = (sistema) => guard({ recurso: 'configuracion', operacion: 'modificar', sistema });
const SELECT_USR = `SELECT u.id, u.codigo, u.username, u.nombre_completo AS nombre, u.email, r.nombre AS rol, u.estado,
                           u.mfa_habilitado, u.bloqueado_hasta, u.creado_en, u.estado_actualizado_en
                      FROM usuario u JOIN rol r ON r.id = u.rol_id`;
const publico = ({ id, ...r }) => r;                     // el UUID interno no sale al navegador

/** Nunca puede quedar el sistema sin un Administrador activo */
async function otrosAdminsActivos(c, excluirId) {
  const r = await c.query(`SELECT count(*)::int AS n FROM usuario u JOIN rol r ON r.id = u.rol_id
                            WHERE r.nombre = 'Administrador' AND u.estado = 'activa' AND u.id <> $1`, [excluirId]);
  return r.rows[0].n;
}

// ---------------------------------------------------------------- listado
router.get('/', LECTURA, wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, (c) => c.query(SELECT_USR + ' ORDER BY u.creado_en, u.codigo'));
  res.json({ usuarios: r.rows.map(publico) });
}));

// ---------------------------------------------------------------- alta (nace SUSPENDIDA y con contraseña temporal)
router.post('/', mod('crear_identidad'), wrap(async (req, res) => {
  const b = req.body || {};
  const username = texto(b.username, 'Usuario', { min: 3, max: 32 }).toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw new HttpError(422, 'El usuario solo admite minúsculas, números, punto, guion y guion bajo (3 a 32)');
  const nombre = texto(b.nombre, 'Nombre completo', { min: 3, max: 100 });
  const rol = enumerado(b.rol, 'Rol', Object.keys(ROL_BD));
  const email = texto(b.email, 'Correo', { max: 120, opcional: true });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new HttpError(422, 'Correo no válido');

  const temporal = passwordTemporal();                 // aleatoria, se muestra UNA sola vez
  const hash = await pw.hash(temporal);
  const u = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const ins = await c.query(
      `INSERT INTO usuario (username, nombre_completo, email, rol_id, password_hash, debe_cambiar_password, creado_por)
       VALUES ($1, $2, $3, (SELECT id FROM rol WHERE nombre = $4), $5, true, $6) RETURNING codigo`,
      [username, nombre, email, rol, hash, req.user.id]);
    await audit.registrarEn(c, { tipo: 'identidad', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Alta de identidad ${ins.rows[0].codigo} (${username}) con rol ${rol}, estado suspendida` });
    return ins.rows[0];
  });
  res.status(201).json({ codigo: u.codigo, username, rol, estado: 'suspendida', password_temporal: temporal,
    aviso: 'Entregue esta contraseña por un canal seguro. No se volverá a mostrar y deberá cambiarse en el primer ingreso.' });
}));

// ---------------------------------------------------------------- activar / suspender / revocar
router.post('/:codigo/estado', mod('cambiar_estado'), wrap(async (req, res) => {
  const estado = enumerado((req.body || {}).estado, 'Estado', ['activa', 'suspendida', 'revocada']);
  const motivo = texto((req.body || {}).motivo, 'Motivo', { max: 200, opcional: true });
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const f = (await c.query(SELECT_USR + ' WHERE u.codigo = $1 FOR UPDATE OF u', [req.params.codigo])).rows[0];
    if (!f) throw new HttpError(404, 'Identidad no encontrada');
    if (f.id === req.user.id) throw new HttpError(409, 'No puede cambiar el estado de su propia identidad');
    if (f.estado === 'revocada') throw new HttpError(409, 'Una identidad revocada es irreversible');
    if (f.estado === estado) throw new HttpError(409, `La identidad ya está ${estado}`);
    if (f.rol === 'Administrador' && f.estado === 'activa' && estado !== 'activa' && (await otrosAdminsActivos(c, f.id)) === 0) {
      throw new HttpError(409, 'No puede dejar el sistema sin ningún Administrador activo');
    }
    // El trigger de la BD registra el historial y revoca las sesiones abiertas de la identidad
    await c.query('UPDATE usuario SET estado = $2, intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = $1', [f.id, estado]);
    await audit.registrarEn(c, { tipo: 'identidad', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `${f.codigo} (${f.username}): ${f.estado} → ${estado}${motivo ? ' · ' + motivo : ''}` });
    return { codigo: f.codigo, estado };
  });
  res.json(r);
}));

router.get('/solicitudes-rol', LECTURA, wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, (c) => c.query(
    `SELECT s.id, u.codigo AS usuario, u.username, ra.nombre AS rol_actual, rn.nombre AS rol_nuevo, s.justificacion,
            sp.username AS solicitado_por, s.solicitado_en, s.estado, rp.username AS resuelto_por, s.resuelto_en
       FROM solicitud_cambio_rol s JOIN usuario u ON u.id = s.usuario_id JOIN rol ra ON ra.id = s.rol_actual_id
       JOIN rol rn ON rn.id = s.rol_nuevo_id JOIN usuario sp ON sp.id = s.solicitado_por
       LEFT JOIN usuario rp ON rp.id = s.resuelto_por ORDER BY s.id DESC LIMIT 100`));
  res.json({ solicitudes: r.rows });
}));

// ---------------------------------------------------------------- cambio de rol: solicitar -> aprobar (otra persona)
router.post('/:codigo/cambio-rol', mod('cambiar_rol'), wrap(async (req, res) => {
  const rolNuevo = enumerado((req.body || {}).rol, 'Rol', Object.keys(ROL_BD));
  const just = texto((req.body || {}).justificacion, 'Justificación', { min: 5, max: 300 });
  const s = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const f = (await c.query(SELECT_USR + ' WHERE u.codigo = $1', [req.params.codigo])).rows[0];
    if (!f) throw new HttpError(404, 'Identidad no encontrada');
    if (f.estado === 'revocada') throw new HttpError(409, 'No se puede cambiar el rol de una identidad revocada');
    if (f.rol === rolNuevo) throw new HttpError(409, 'La identidad ya tiene ese rol');
    const dup = await c.query(`SELECT 1 FROM solicitud_cambio_rol WHERE usuario_id = $1 AND estado = 'pendiente'`, [f.id]);
    if (dup.rowCount) throw new HttpError(409, 'Ya existe una solicitud pendiente para esta identidad');
    const i = await c.query(
      `INSERT INTO solicitud_cambio_rol (usuario_id, rol_actual_id, rol_nuevo_id, justificacion, solicitado_por)
       VALUES ($1, (SELECT id FROM rol WHERE nombre = $2), (SELECT id FROM rol WHERE nombre = $3), $4, $5) RETURNING id`,
      [f.id, f.rol, rolNuevo, just, req.user.id]);
    await audit.registrarEn(c, { tipo: 'cambio_rol', resultado: 'solicitado', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `${f.codigo}: ${f.rol} → ${rolNuevo} · ${just}` });
    return { id: i.rows[0].id, usuario: f.codigo, rol_actual: f.rol, rol_nuevo: rolNuevo, estado: 'pendiente' };
  });
  res.status(201).json(s);
}));

router.post('/solicitudes-rol/:id/resolver', mod('cambiar_rol'), wrap(async (req, res) => {
  const id = entero(req.params.id, 'Solicitud');
  const aprobar = (req.body || {}).aprobar === true;
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const s = (await c.query(
      `SELECT s.id, s.estado, s.usuario_id, u.codigo, u.username, ra.nombre AS actual, rn.nombre AS nuevo
         FROM solicitud_cambio_rol s JOIN usuario u ON u.id = s.usuario_id JOIN rol ra ON ra.id = s.rol_actual_id
         JOIN rol rn ON rn.id = s.rol_nuevo_id WHERE s.id = $1 FOR UPDATE OF s`, [id])).rows[0];
    if (!s) throw new HttpError(404, 'Solicitud no encontrada');
    if (s.estado !== 'pendiente') throw new HttpError(409, 'La solicitud ya fue resuelta');
    if (s.usuario_id === req.user.id) {                      // Parte 1e: nadie aprueba su propio cambio de rol
      return { autoaprobacion: true, s };
    }
    if (aprobar && s.actual === 'Administrador' && (await otrosAdminsActivos(c, s.usuario_id)) === 0) {
      throw new HttpError(409, 'No puede dejar el sistema sin ningún Administrador activo');
    }
    // El trigger fn_aplicar_cambio_rol aplica el rol y revoca las sesiones del usuario afectado
    await c.query(`UPDATE solicitud_cambio_rol SET estado = $2, resuelto_por = $3, resuelto_en = now() WHERE id = $1`,
      [id, aprobar ? 'aprobada' : 'rechazada', req.user.id]);
    await audit.registrarEn(c, { tipo: 'cambio_rol', resultado: aprobar ? 'exito' : 'denegado', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `${s.codigo}: ${s.actual} → ${s.nuevo} ${aprobar ? 'APROBADO' : 'RECHAZADO'}` });
    return { id, estado: aprobar ? 'aprobada' : 'rechazada' };
  });
  if (r.autoaprobacion) {
    await req.audit('acceso_denegado', 'denegado', `Intento de resolver su propio cambio de rol (${r.s.codigo})`);
    throw new HttpError(403, 'No puede aprobar ni rechazar su propio cambio de rol');
  }
  res.json(r);
}));

// ---------------------------------------------------------------- historial de una identidad
router.get('/:codigo/historial', LECTURA, wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, (c) => c.query(
    `SELECT h.tipo_movimiento, h.estado_anterior, h.estado_nuevo, a.username AS realizado_por, h.motivo, h.ocurrido_en
       FROM historial_estado_usuario h JOIN usuario u ON u.id = h.usuario_id LEFT JOIN usuario a ON a.id = h.realizado_por
      WHERE u.codigo = $1 ORDER BY h.id DESC`, [req.params.codigo]));
  res.json({ historial: r.rows });
}));

module.exports = router;
