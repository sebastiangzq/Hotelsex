// Parte 4 · Auditoría y trazabilidad. La bitácora es de solo-inserción y está encadenada por hash.
const express = require('express');
const { withRole } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { enumerado } = require('../validar');
const { cifrar, sha256 } = require('../crypto');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());
const LEER = guard({ recurso: 'bitacora', operacion: 'leer' });          // Administrador y Auditor

const TIPOS = ['autenticacion', 'autorizacion', 'cambio_rol', 'acceso_denegado', 'cuenta_emergencia', 'configuracion', 'identidad', 'huesped', 'incidente'];
const COLS = `id, ocurrido_en, tipo, resultado, actor_nombre, host(ip_origen) AS ip_origen, detalle, hash_previo, hash_registro`;

router.get('/', LEER, wrap(async (req, res) => {
  const q = req.query;
  const tipo = q.tipo ? enumerado(q.tipo, 'Tipo', TIPOS) : null;
  const resultado = q.resultado ? enumerado(q.resultado, 'Resultado', ['exito', 'fallo', 'denegado', 'solicitado']) : null;
  const limite = Math.min(Math.max(parseInt(q.limite, 10) || 100, 1), 500);
  const desde = Math.max(parseInt(q.desde, 10) || 0, 0);
  const d = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const filas = await c.query(`SELECT ${COLS} FROM bitacora_auditoria WHERE ($1::tipo_evento IS NULL OR tipo = $1) AND ($2::resultado_evento IS NULL OR resultado = $2)
                                  ORDER BY id DESC LIMIT $3 OFFSET $4`, [tipo, resultado, limite, desde]);
    const total = await c.query('SELECT count(*)::int AS n FROM bitacora_auditoria');
    return { registros: filas.rows, total: total.rows[0].n };
  });
  res.json(d);
}));

router.get('/verificar', LEER, wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const bad = (await c.query('SELECT id_alterado, motivo FROM verificar_cadena_bitacora()')).rows[0];
    const n = (await c.query('SELECT count(*)::int AS n FROM bitacora_auditoria')).rows[0].n;
    return { integra: !bad, registros: n, id_alterado: bad?.id_alterado ?? null, motivo: bad?.motivo ?? null };
  });
  await req.audit('configuracion', r.integra ? 'exito' : 'fallo',
    r.integra ? `Verificación de integridad de la bitácora: ÍNTEGRA (${r.registros} registros)` : `Verificación de integridad: ALTERACIÓN en el registro ${r.id_alterado}`);
  res.json(r);
}));

// Demostración del control "bitácora inalterable": el intento real de UPDATE lo rechaza la propia base de datos
router.post('/intento-edicion', LEER, wrap(async (req, res) => {
  let bloqueado = false;
  try {
    await withRole(req.user.dbRole, req.user.id, (c) => c.query(`UPDATE bitacora_auditoria SET detalle = detalle WHERE id = (SELECT max(id) FROM bitacora_auditoria)`));
  } catch (e) { bloqueado = true; }
  await req.audit('acceso_denegado', 'denegado', bloqueado ? 'Intento de alterar la bitácora bloqueado por la base de datos (inmutable)' : 'ALERTA: se logró modificar la bitácora');
  if (!bloqueado) throw new Error('La bitácora admitió una modificación: revise los privilegios');
  res.status(403).json({ error: 'Operación rechazada por la base de datos: la bitácora es inalterable', bloqueado: true });
}));

// Exportación cifrada (alto riesgo: 2FA, y bloqueada en degradación). Se descifra con scripts/descifrar.js
router.get('/exportar', guard({ recurso: 'bitacora', operacion: 'leer', sistema: 'exportar_bitacora' }), wrap(async (req, res) => {
  const paquete = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const bad = (await c.query('SELECT id_alterado FROM verificar_cadena_bitacora()')).rows[0];
    const filas = (await c.query(`SELECT ${COLS} FROM bitacora_auditoria ORDER BY id`)).rows;
    return { formato: 'hotelsec-bitacora-v1', generado_en: new Date().toISOString(), generado_por: req.user.username,
      cadena_integra: !bad, registros: filas.length, ultimo_hash: filas.at(-1)?.hash_registro ?? null, datos: filas };
  });
  const cifrado = cifrar(JSON.stringify(paquete), 'bitacora-export', 'export');
  const huella = sha256(cifrado).toString('hex');
  await req.audit('configuracion', 'exito', `Bitácora exportada y cifrada (AES-256-GCM): ${paquete.registros} registros · sha256 ${huella.slice(0, 16)}…`);
  res.set({ 'Content-Type': 'application/octet-stream', 'X-Huella-SHA256': huella,
    'Content-Disposition': `attachment; filename="bitacora_${paquete.registros}_registros.enc"` });
  res.send(cifrado);
}));

module.exports = router;
