// Parte 5 · Respuesta a incidentes y modo de degradación segura
const express = require('express');
const { withRole, AUTH, leerConfig } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { enumerado, entero, texto } = require('../validar');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());
const LEER = guard({ recurso: 'bitacora', operacion: 'leer' });
const GESTIONAR = guard({ recurso: 'configuracion', operacion: 'modificar' });

const ESCENARIOS = {
  a: { tipo: 'compromiso_cuenta_privilegiada', sev: 'critica', txt: 'Compromiso de una cuenta privilegiada' },
  b: { tipo: 'indisponibilidad_servicio_identidad', sev: 'alta', txt: 'Indisponibilidad del servicio de identidad' },
  c: { tipo: 'alteracion_expedientes', sev: 'critica', txt: 'Alteración no autorizada de expedientes' },
  d: { tipo: 'perdida_corrupcion_registros', sev: 'alta', txt: 'Pérdida o corrupción de registros' },
};
const ORDEN = ['abierto', 'contenido', 'recuperado', 'cerrado'];

router.get('/', LEER, wrap(async (req, res) => {
  const d = await withRole(AUTH, null, async (c) => {
    const cfg = await leerConfig(c);
    const ops = (await c.query('SELECT clave, descripcion, riesgo, requiere_2fa, bloqueada_en_degradacion FROM operacion_sistema ORDER BY bloqueada_en_degradacion DESC, clave')).rows;
    return { cfg, ops };
  });
  const lista = await withRole(req.user.dbRole, req.user.id, (c) => c.query(
    `SELECT i.id, i.tipo, i.severidad, i.descripcion, i.estado, i.detectado_en, d.username AS detectado_por, i.modo_degradacion, i.respuesta_aplicada, i.cerrado_en
       FROM incidente i LEFT JOIN usuario d ON d.id = i.detectado_por ORDER BY i.id DESC LIMIT 100`));
  const activos = Object.fromEntries(Object.entries(ESCENARIOS).map(([k, v]) => [k, lista.rows.find((i) => i.tipo === v.tipo && i.estado !== 'cerrado')?.id ?? null]));
  res.json({
    incidentes: lista.rows, activos, escenarios: ESCENARIOS, degradacion: d.cfg.modo_degradacion_segura === 'true',
    operaciones_bloqueadas: d.ops.filter((o) => o.bloqueada_en_degradacion), operaciones_continuan: d.ops.filter((o) => !o.bloqueada_en_degradacion),
  });
}));

router.post('/', GESTIONAR, wrap(async (req, res) => {
  const k = enumerado((req.body || {}).escenario, 'Escenario', Object.keys(ESCENARIOS));
  const e = ESCENARIOS[k];
  const desc = texto((req.body || {}).descripcion, 'Descripción', { max: 300, opcional: true }) || e.txt;
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const ya = await c.query(`SELECT id FROM incidente WHERE tipo = $1 AND estado <> 'cerrado'`, [e.tipo]);
    if (ya.rowCount) throw new HttpError(409, 'Ya hay un incidente abierto de este tipo');
    const i = (await c.query(`INSERT INTO incidente (tipo, severidad, descripcion, detectado_por, responsable_id, modo_degradacion)
        VALUES ($1, $2, $3, $4, $4, (SELECT valor = 'true' FROM configuracion_sistema WHERE clave = 'modo_degradacion_segura')) RETURNING id`,
      [e.tipo, e.sev, desc, req.user.id])).rows[0];
    await audit.registrarEn(c, { tipo: 'incidente', resultado: 'fallo', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Incidente #${i.id} detectado: ${desc} (${e.sev.toUpperCase()})` });
    return { id: i.id, estado: 'abierto', severidad: e.sev };
  });
  res.status(201).json(r);
}));

router.patch('/:id', GESTIONAR, wrap(async (req, res) => {
  const id = entero(req.params.id, 'Incidente');
  const estado = enumerado((req.body || {}).estado, 'Estado', ORDEN.slice(1));
  const resp = texto((req.body || {}).respuesta_aplicada, 'Respuesta aplicada', { max: 500, opcional: true });
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const i = (await c.query('SELECT id, estado, descripcion FROM incidente WHERE id = $1 FOR UPDATE', [id])).rows[0];
    if (!i) throw new HttpError(404, 'Incidente no encontrado');
    if (ORDEN.indexOf(estado) <= ORDEN.indexOf(i.estado)) throw new HttpError(409, `El incidente ya está ${i.estado}; el estado solo avanza`);
    await c.query(`UPDATE incidente SET estado = $2::estado_incidente, respuesta_aplicada = coalesce($3, respuesta_aplicada),
                          cerrado_en = CASE WHEN $4::boolean THEN now() END WHERE id = $1`, [id, estado, resp, estado === 'cerrado']);
    await audit.registrarEn(c, { tipo: 'incidente', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Incidente #${id} (${i.descripcion}): ${i.estado} → ${estado}${resp ? ' · ' + resp : ''}` });
    return { id, estado };
  });
  res.json(r);
}));

// Activar/desactivar degradación: sin 2FA a propósito (en una emergencia no debe haber fricción) pero siempre auditado
router.post('/degradacion', GESTIONAR, wrap(async (req, res) => {
  const activo = (req.body || {}).activo === true;
  await withRole(req.user.dbRole, req.user.id, async (c) => {
    await c.query(`UPDATE configuracion_sistema SET valor = $1, actualizado_por = $2, actualizado_en = now() WHERE clave = 'modo_degradacion_segura'`,
      [String(activo), req.user.id]);
    if (activo) await c.query(`UPDATE incidente SET modo_degradacion = true WHERE estado <> 'cerrado'`);
    await audit.registrarEn(c, { tipo: 'configuracion', resultado: activo ? 'fallo' : 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Modo de degradación segura ${activo ? 'ACTIVADO' : 'desactivado'}` });
  });
  res.json({ degradacion: activo });
}));

module.exports = router;
