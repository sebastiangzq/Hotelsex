// Parte 4 de la política (protección de datos) aplicada a huéspedes:
//  · documento, teléfono, correo y nacimiento se guardan CIFRADOS (AES-256-GCM, el cifrado lo hace esta app)
//  · el documento se busca por HMAC (detecta duplicados sin guardarlo en claro)
//  · al terminar la estancia se DEPURAN los datos personales
const crypto = require('crypto');
const express = require('express');
const { withRole } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto, fecha, enumerado } = require('../validar');
const { cifrar, descifrar, hmacDocumento } = require('../crypto');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());

const hoy = () => new Date().toISOString().slice(0, 10);
const iniciales = (n) => n.split(/\s+/).filter(Boolean).map((p) => p[0].toUpperCase() + '.').join(' ');
const aad = (campo, id) => `huesped:${campo}:${id}`;       // el cifrado queda atado a su fila y columna

// "Propietario" del objeto para el control de contexto persona/objeto de evaluar_acceso
const propietario = async (req) => (await withRole(req.user.dbRole, req.user.id, (c) =>
  c.query('SELECT registrada_por FROM estancia WHERE codigo = $1', [req.params.codigo]))).rows[0]?.registrada_por || null;

const PAGO = `LEFT JOIN LATERAL (SELECT (array_agg(metodo ORDER BY id DESC))[1] AS metodo,
                                      (array_agg(tarjeta_ultimos4 ORDER BY id DESC))[1] AS tarjeta_ultimos4, sum(monto) AS total
                                 FROM pago WHERE estancia_id = e.id) p ON true`;

// ---------------------------------------------------------------- listado
router.get('/', guard({ recurso: 'expedientes_huespedes', operacion: 'leer' }), wrap(async (req, res) => {
  const auditor = req.user.rol === 'Auditor';
  const filas = await withRole(req.user.dbRole, req.user.id, async (c) => {
    // El Auditor no puede tocar la tabla huesped: solo la vista sin nombres ni datos cifrados
    const sql = auditor
      ? `SELECT e.codigo, e.estado, e.ingreso::text, e.salida::text, hab.numero AS habitacion, h.id AS hid, NULL::text AS nombre_completo,
                h.documento_tipo, NULL::bytea AS documento_cifrado, h.documento_enmascarado, h.nacionalidad,
                NULL::bytea AS telefono_cifrado, NULL::bytea AS email_cifrado, NULL::bytea AS fecha_nacimiento_cifrada,
                h.datos_depurados, p.metodo, p.tarjeta_ultimos4, p.total, u.username AS registrada_por, false AS propia
           FROM estancia e JOIN v_huesped_auditor h ON h.id = e.huesped_id JOIN habitacion hab ON hab.id = e.habitacion_id
           JOIN usuario u ON u.id = e.registrada_por ${PAGO} ORDER BY e.id DESC LIMIT 300`
      : `SELECT e.codigo, e.estado, e.ingreso::text, e.salida::text, hab.numero AS habitacion, h.id AS hid, h.nombre_completo,
                h.documento_tipo, h.documento_cifrado, '••••••' || coalesce(h.documento_ultimos3, '') AS documento_enmascarado, h.nacionalidad,
                h.telefono_cifrado, h.email_cifrado, h.fecha_nacimiento_cifrada, h.datos_depurados, p.metodo, p.tarjeta_ultimos4, p.total,
                NULL::text AS registrada_por, (e.registrada_por = $1::uuid) AS propia
           FROM estancia e JOIN huesped h ON h.id = e.huesped_id JOIN habitacion hab ON hab.id = e.habitacion_id
           ${PAGO} ORDER BY e.id DESC LIMIT 300`;
    return (await c.query(sql, auditor ? [] : [req.user.id])).rows;
  });
  const huespedes = filas.map((f) => {
    const pii = !auditor && !f.datos_depurados;
    return {
      codigo: f.codigo, estado: f.estado, ingreso: f.ingreso, salida: f.salida, habitacion: f.habitacion,
      nombre: f.nombre_completo, documento_tipo: f.documento_tipo, documento_enmascarado: f.documento_enmascarado,
      documento: pii ? descifrar(f.documento_cifrado, aad('documento', f.hid)) : null,
      nacionalidad: f.nacionalidad,
      telefono: pii ? descifrar(f.telefono_cifrado, aad('telefono', f.hid)) : null,
      email: pii ? descifrar(f.email_cifrado, aad('email', f.hid)) : null,
      fecha_nacimiento: pii ? descifrar(f.fecha_nacimiento_cifrada, aad('nacimiento', f.hid)) : null,
      datos_depurados: f.datos_depurados, pago: f.metodo ? { metodo: f.metodo, tarjeta_ultimos4: f.tarjeta_ultimos4, total: f.total } : null,
      registrada_por: f.registrada_por, propia: f.propia,
    };
  });
  res.json({ huespedes });
}));

// ---------------------------------------------------------------- check-in (o reserva si el ingreso es futuro)
router.post('/', [guard({ recurso: 'expedientes_huespedes', operacion: 'crear' }), guard({ recurso: 'reservas', operacion: 'crear' }),
  guard({ recurso: 'facturacion', operacion: 'crear' })], wrap(async (req, res) => {
  const b = req.body || {};
  const nombre = texto(b.nombre, 'Nombre completo', { min: 3, max: 100 });
  const docTipo = enumerado(b.documento_tipo || 'CI', 'Tipo de documento', ['CI', 'pasaporte', 'otro']);
  const documento = texto(b.documento, 'Documento', { min: 5, max: 30 });
  const nacionalidad = texto(b.nacionalidad || 'Boliviana', 'Nacionalidad', { max: 60 });
  const telefono = texto(b.telefono, 'Teléfono', { max: 30, opcional: true });
  const email = texto(b.email, 'Correo', { max: 120, opcional: true });
  const nacimiento = fecha(b.fecha_nacimiento, 'Fecha de nacimiento', true);
  const ingreso = fecha(b.ingreso || hoy(), 'Ingreso'), salida = fecha(b.salida, 'Salida');
  if (salida <= ingreso) throw new HttpError(422, 'La salida debe ser posterior al ingreso');
  if (b.consentimiento !== true) throw new HttpError(422, 'Se requiere el consentimiento del huésped para tratar sus datos');
  const metodo = enumerado(b.metodo_pago, 'Método de pago', ['efectivo', 'tarjeta', 'transferencia', 'qr']);
  const monto = Number(b.monto);
  if (!(monto > 0) || monto > 1e7) throw new HttpError(422, 'Monto no válido');
  let ultimos4 = null;
  if (metodo === 'tarjeta') {
    ultimos4 = String(b.tarjeta_ultimos4 || '');
    if (!/^\d{4}$/.test(ultimos4)) throw new HttpError(422, 'Indique solo los ÚLTIMOS 4 dígitos de la tarjeta (nunca el número completo)');
  }
  const numHab = texto(b.habitacion, 'Habitación', { max: 10 });

  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const hmac = hmacDocumento(documento);
    const dup = await c.query(`SELECT e.codigo FROM huesped h JOIN estancia e ON e.huesped_id = h.id
                                WHERE h.documento_hmac = $1 AND e.estado IN ('reservada','hospedada')`, [hmac]);
    if (dup.rowCount) throw new HttpError(409, `Ese documento ya tiene una estancia vigente (${dup.rows[0].codigo})`);
    const hab = (await c.query('SELECT id, estado FROM habitacion WHERE numero = $1', [numHab])).rows[0];
    if (!hab) throw new HttpError(404, 'Habitación inexistente');

    const hid = crypto.randomUUID();
    const norm = documento.replace(/[\s.\-]/g, '');
    await c.query(
      `INSERT INTO huesped (id, nombre_completo, documento_tipo, documento_cifrado, documento_hmac, documento_ultimos3, nacionalidad,
                            telefono_cifrado, email_cifrado, fecha_nacimiento_cifrada, consentimiento_datos, consentimiento_en, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,now(),$11)`,
      [hid, nombre, docTipo, cifrar(documento, aad('documento', hid)), hmac, norm.slice(-3), nacionalidad,
        telefono && cifrar(telefono, aad('telefono', hid)), email && cifrar(email, aad('email', hid)),
        nacimiento && cifrar(nacimiento, aad('nacimiento', hid)), req.user.id]);
    const estado = ingreso <= hoy() ? 'hospedada' : 'reservada';
    const e = (await c.query(
      `INSERT INTO estancia (codigo, huesped_id, habitacion_id, ingreso, salida, estado, registrada_por)
       VALUES ('R-' || nextval('seq_codigo_estancia'), $1, $2, $3, $4, $5, $6) RETURNING id, codigo`,   // el solape de fechas lo rechaza la BD (EXCLUDE)
      [hid, hab.id, ingreso, salida, estado, req.user.id])).rows[0];
    await c.query(`INSERT INTO pago (estancia_id, metodo, tarjeta_ultimos4, monto, registrado_por) VALUES ($1,$2,$3,$4,$5)`,
      [e.id, metodo, ultimos4, monto.toFixed(2), req.user.id]);
    if (estado === 'hospedada') await c.query(`UPDATE habitacion SET estado = 'ocupada' WHERE id = $1`, [hab.id]);
    await audit.registrarEn(c, { tipo: 'huesped', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `${estado === 'hospedada' ? 'Check-in' : 'Reserva'} ${e.codigo} · hab. ${numHab} · pago ${metodo}${ultimos4 ? ' ••••' + ultimos4 : ''} · datos personales cifrados` });
    return { codigo: e.codigo, estado, habitacion: numHab };
  });
  res.status(201).json(r);
}));

/** Depura los datos personales del huésped si ya no tiene otra estancia vigente */
async function depurar(c, hid) {
  const otra = await c.query(`SELECT 1 FROM estancia WHERE huesped_id = $1 AND estado IN ('reservada','hospedada')`, [hid]);
  if (otra.rowCount) return false;
  const h = (await c.query('SELECT nombre_completo FROM huesped WHERE id = $1', [hid])).rows[0];
  await c.query(`UPDATE huesped SET nombre_completo = $2, documento_cifrado = NULL, documento_hmac = NULL, telefono_cifrado = NULL,
                        email_cifrado = NULL, fecha_nacimiento_cifrada = NULL, datos_depurados = true, depurado_en = now() WHERE id = $1`,
    [hid, iniciales(h.nombre_completo)]);
  return true;
}
async function cargar(c, codigo) {
  const e = (await c.query(`SELECT e.id, e.estado, e.huesped_id, e.habitacion_id, hab.numero FROM estancia e
                             JOIN habitacion hab ON hab.id = e.habitacion_id WHERE e.codigo = $1 FOR UPDATE OF e`, [codigo])).rows[0];
  if (!e) throw new HttpError(404, 'Estancia no encontrada');
  return e;
}

// ---------------------------------------------------------------- check-in de una reserva (reservada -> hospedada)
router.post('/:codigo/checkin', guard({ recurso: 'expedientes_huespedes', operacion: 'modificar', propietario }), wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const e = await cargar(c, req.params.codigo);
    if (e.estado !== 'reservada') throw new HttpError(409, 'Solo se puede hacer check-in de una reserva');
    const f = (await c.query('SELECT ingreso::text AS ingreso FROM estancia WHERE id = $1', [e.id])).rows[0];
    if (f.ingreso > hoy()) throw new HttpError(409, `La reserva ingresa el ${f.ingreso}: aún no se puede hacer el check-in`);
    const hab = (await c.query('SELECT estado FROM habitacion WHERE id = $1 FOR UPDATE', [e.habitacion_id])).rows[0];
    if (hab.estado === 'ocupada') throw new HttpError(409, 'La habitación todavía está ocupada');
    await c.query(`UPDATE estancia SET estado = 'hospedada' WHERE id = $1`, [e.id]);
    await c.query(`UPDATE habitacion SET estado = 'ocupada' WHERE id = $1`, [e.habitacion_id]);
    await audit.registrarEn(c, { tipo: 'huesped', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Check-in de la reserva ${req.params.codigo} · hab. ${e.numero}` });
    return { codigo: req.params.codigo, estado: 'hospedada' };
  });
  res.json(r);
}));

// ---------------------------------------------------------------- check-out
router.post('/:codigo/checkout', guard({ recurso: 'expedientes_huespedes', operacion: 'modificar', propietario }), wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const e = await cargar(c, req.params.codigo);
    if (e.estado !== 'hospedada') throw new HttpError(409, 'Solo se puede hacer check-out de una estancia hospedada');
    await c.query(`UPDATE estancia SET estado = 'finalizada' WHERE id = $1`, [e.id]);
    await c.query(`UPDATE habitacion SET estado = 'limpieza' WHERE id = $1`, [e.habitacion_id]);
    const depurado = await depurar(c, e.huesped_id);
    await audit.registrarEn(c, { tipo: 'huesped', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Check-out ${req.params.codigo} · hab. ${e.numero}${depurado ? ' · datos personales depurados' : ''}` });
    return { codigo: req.params.codigo, estado: 'finalizada', datos_depurados: depurado };
  });
  res.json(r);
}));

// ---------------------------------------------------------------- anulación (alto riesgo: 2FA y bloqueada en degradación)
router.post('/:codigo/anular', [guard({ recurso: 'reservas', operacion: 'modificar', sistema: 'anular_reserva', propietario })], wrap(async (req, res) => {
  const motivo = texto((req.body || {}).motivo, 'Motivo', { min: 5, max: 200 });
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const e = await cargar(c, req.params.codigo);
    if (!['reservada', 'hospedada'].includes(e.estado)) throw new HttpError(409, 'Solo se anulan reservas o estancias vigentes');
    await c.query(`UPDATE estancia SET estado = 'anulada', anulada_por = $2, anulada_en = now(), motivo_anulacion = $3 WHERE id = $1`,
      [e.id, req.user.id, motivo]);
    if (e.estado === 'hospedada') await c.query(`UPDATE habitacion SET estado = 'limpieza' WHERE id = $1`, [e.habitacion_id]);
    const depurado = await depurar(c, e.huesped_id);
    await audit.registrarEn(c, { tipo: 'huesped', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Anulación de ${req.params.codigo} (hab. ${e.numero}) · ${motivo}${depurado ? ' · datos depurados' : ''}` });
    return { codigo: req.params.codigo, estado: 'anulada' };
  });
  res.json(r);
}));

module.exports = router;
