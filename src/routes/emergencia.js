// Parte 4e / Política 8 · Cuentas de emergencia: solo con incidente abierto, con motivo, y revisión posterior del Auditor
const express = require('express');
const { withRole } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto, entero } = require('../validar');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());
const GESTIONAR = guard({ recurso: 'cuentas_emergencia', operacion: 'modificar', sistema: 'cuenta_emergencia' });
const AUDITAR = guard({ recurso: 'bitacora', operacion: 'leer' });

router.get('/', guard({ recurso: 'cuentas_emergencia', operacion: 'leer' }), wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, (c) => c.query(
    `SELECT c.codigo, c.alcance, c.activa, u.username AS custodio FROM cuenta_emergencia c JOIN usuario u ON u.id = c.custodio_id ORDER BY c.id`));
  res.json({ cuentas: r.rows });
}));

router.get('/usos', AUDITAR, wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, (c) => c.query(
    `SELECT x.id, c.codigo AS cuenta, u.username AS usada_por, x.incidente_id, x.motivo, x.inicio, x.fin, rv.username AS revisado_por, x.revisado_en
       FROM uso_cuenta_emergencia x JOIN cuenta_emergencia c ON c.id = x.cuenta_id JOIN usuario u ON u.id = x.usada_por_id
       LEFT JOIN usuario rv ON rv.id = x.revisado_por ORDER BY x.id DESC LIMIT 100`));
  res.json({ usos: r.rows });
}));

// Habilita la cuenta (solo su custodio, solo con un incidente vigente) y abre el registro de uso
router.post('/:codigo/activar', GESTIONAR, wrap(async (req, res) => {
  const motivo = texto((req.body || {}).motivo, 'Motivo', { min: 10, max: 300 });
  const incidente = entero((req.body || {}).incidente_id, 'Incidente');
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const cta = (await c.query('SELECT id, activa, custodio_id FROM cuenta_emergencia WHERE codigo = $1 FOR UPDATE', [req.params.codigo])).rows[0];
    if (!cta) throw new HttpError(404, 'Cuenta de emergencia inexistente');
    if (cta.custodio_id !== req.user.id) throw new HttpError(403, 'Solo el custodio designado puede habilitar esta cuenta');
    if (cta.activa) throw new HttpError(409, 'La cuenta ya está habilitada');
    const inc = await c.query(`SELECT 1 FROM incidente WHERE id = $1 AND estado <> 'cerrado'`, [incidente]);
    if (!inc.rowCount) throw new HttpError(409, 'Una cuenta de emergencia solo se habilita con un incidente vigente');
    await c.query('UPDATE cuenta_emergencia SET activa = true WHERE id = $1', [cta.id]);
    const u = (await c.query(`INSERT INTO uso_cuenta_emergencia (cuenta_id, usada_por_id, incidente_id, motivo) VALUES ($1,$2,$3,$4) RETURNING id`,
      [cta.id, req.user.id, incidente, motivo])).rows[0];
    await audit.registrarEn(c, { tipo: 'cuenta_emergencia', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `${req.params.codigo} HABILITADA por ${req.user.username} · incidente #${incidente} · ${motivo}` });
    return { uso_id: u.id, cuenta: req.params.codigo, activa: true };
  });
  res.status(201).json(r);
}));

router.post('/usos/:id/cerrar', GESTIONAR, wrap(async (req, res) => {
  const id = entero(req.params.id, 'Uso');
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const x = (await c.query(`SELECT x.id, x.cuenta_id, c.codigo, x.fin FROM uso_cuenta_emergencia x JOIN cuenta_emergencia c ON c.id = x.cuenta_id WHERE x.id = $1 FOR UPDATE OF x`, [id])).rows[0];
    if (!x) throw new HttpError(404, 'Uso no encontrado');
    if (x.fin) throw new HttpError(409, 'El uso ya estaba cerrado');
    await c.query('UPDATE uso_cuenta_emergencia SET fin = now() WHERE id = $1', [id]);
    await c.query('UPDATE cuenta_emergencia SET activa = false WHERE id = $1', [x.cuenta_id]);
    await audit.registrarEn(c, { tipo: 'cuenta_emergencia', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip, detalle: `${x.codigo} DESHABILITADA (uso #${id} cerrado)` });
    return { uso_id: id, activa: false };
  });
  res.json(r);
}));

// Revisión posterior: la BD exige que quien revisa tenga el rol Auditor
router.post('/usos/:id/revisar', AUDITAR, wrap(async (req, res) => {
  const id = entero(req.params.id, 'Uso');
  if (req.user.rol !== 'Auditor') throw new HttpError(403, 'La revisión de cuentas de emergencia corresponde al Auditor');
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const u = await c.query(`UPDATE uso_cuenta_emergencia SET revisado_por = $2, revisado_en = now() WHERE id = $1 AND revisado_por IS NULL AND fin IS NOT NULL RETURNING id`, [id, req.user.id]);
    if (!u.rowCount) throw new HttpError(409, 'El uso no existe, sigue abierto o ya fue revisado');
    await audit.registrarEn(c, { tipo: 'cuenta_emergencia', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip, detalle: `Uso #${id} de cuenta de emergencia REVISADO por el Auditor` });
    return { uso_id: id, revisado: true };
  });
  res.json(r);
}));

module.exports = router;
