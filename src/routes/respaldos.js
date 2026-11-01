// Parte 5 · Respaldos y restauración con CONTROL DUAL (quien restaura necesita que otro administrador lo autorice con su 2FA)
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const { withRole, AUTH } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto, entero } = require('../validar');
const { sha256, descifrar } = require('../crypto');
const totp = require('../auth/totp');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());
const DIR = path.resolve(process.env.BACKUP_DIR || path.join(__dirname, '..', '..', 'backups'));
const GESTIONAR = guard({ recurso: 'configuracion', operacion: 'modificar' });

router.get('/', guard({ recurso: 'bitacora', operacion: 'leer' }), wrap(async (req, res) => {
  const d = await withRole(req.user.dbRole, req.user.id, async (c) => ({
    respaldos: (await c.query(`SELECT r.id, r.alcance, r.creado_en, r.sha256, r.cifrado, r.verificado_en, u.username AS verificado_por
                                 FROM respaldo r LEFT JOIN usuario u ON u.id = r.verificado_por ORDER BY r.id DESC LIMIT 50`)).rows,
    restauraciones: (await c.query(`SELECT x.id, x.incidente_id, x.respaldo_id, a.username AS realizada_por, b.username AS autorizada_por, x.realizada_en, x.resultado
                                      FROM restauracion x JOIN usuario a ON a.id = x.realizada_por JOIN usuario b ON b.id = x.autorizada_por ORDER BY x.id DESC LIMIT 50`)).rows,
  }));
  res.json(d);
}));

// Recalcula el SHA-256 del archivo y lo compara con el registrado: detecta copias alteradas o corruptas
router.post('/:id/verificar', GESTIONAR, wrap(async (req, res) => {
  const id = entero(req.params.id, 'Respaldo');
  const r = (await withRole(req.user.dbRole, req.user.id, (c) => c.query('SELECT ubicacion, sha256 FROM respaldo WHERE id = $1', [id]))).rows[0];
  if (!r) throw new HttpError(404, 'Respaldo no encontrado');
  const ruta = path.resolve(r.ubicacion);
  if (!ruta.startsWith(DIR + path.sep)) throw new HttpError(409, 'El archivo está fuera de la carpeta de respaldos autorizada');
  let huella;
  try { huella = sha256(await fs.readFile(ruta)).toString('hex'); } catch { throw new HttpError(409, 'No se pudo leer el archivo del respaldo'); }
  const ok = huella === r.sha256;
  await withRole(req.user.dbRole, req.user.id, async (c) => {
    if (ok) await c.query('UPDATE respaldo SET verificado_en = now(), verificado_por = $2 WHERE id = $1', [id, req.user.id]);
    await audit.registrarEn(c, { tipo: 'incidente', resultado: ok ? 'exito' : 'fallo', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: ok ? `Respaldo #${id} verificado: huella SHA-256 coincide` : `ALERTA: el respaldo #${id} NO coincide con su huella (alterado o corrupto)` });
  });
  res.status(ok ? 200 : 409).json({ id, integro: ok });
}));

// Registro de una restauración. El autorizador demuestra su identidad con su propio código TOTP.
router.post('/restauraciones', GESTIONAR, wrap(async (req, res) => {
  const b = req.body || {};
  const incidente = entero(b.incidente_id, 'Incidente'), respaldo = entero(b.respaldo_id, 'Respaldo');
  const autorizador = texto(b.autorizador, 'Autorizador', { max: 32 }).toLowerCase();
  const resultado = texto(b.resultado, 'Resultado', { min: 5, max: 300 });
  const a = (await withRole(AUTH, null, (c) => c.query(
    `SELECT u.id, u.estado, u.mfa_habilitado, u.mfa_secreto_cifrado, r.nombre AS rol FROM usuario u JOIN rol r ON r.id = u.rol_id WHERE lower(u.username) = $1`, [autorizador]))).rows[0];
  const valido = a && a.id !== req.user.id && a.estado === 'activa' && a.rol === 'Administrador' && a.mfa_habilitado
    && totp.verificar(a.id, descifrar(a.mfa_secreto_cifrado, 'mfa:' + a.id, 'mfa'), String(b.codigo || ''));
  if (!valido) {
    await req.audit('acceso_denegado', 'denegado', `Restauración rechazada: autorización dual inválida (autorizador ${autorizador})`);
    throw new HttpError(403, 'La autorización del segundo administrador no es válida (otro administrador activo, con su código 2FA vigente)');
  }
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const rp = (await c.query('SELECT verificado_en FROM respaldo WHERE id = $1', [respaldo])).rows[0];
    if (!rp) throw new HttpError(404, 'Respaldo no encontrado');
    if (!rp.verificado_en) throw new HttpError(409, 'Solo se restaura desde un respaldo cuya integridad esté verificada');
    const inc = await c.query(`SELECT 1 FROM incidente WHERE id = $1 AND estado <> 'cerrado'`, [incidente]);
    if (!inc.rowCount) throw new HttpError(409, 'La restauración debe estar asociada a un incidente vigente');
    const x = (await c.query(`INSERT INTO restauracion (incidente_id, respaldo_id, realizada_por, autorizada_por, resultado) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [incidente, respaldo, req.user.id, a.id, resultado])).rows[0];
    await audit.registrarEn(c, { tipo: 'incidente', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Restauración #${x.id} desde respaldo #${respaldo} (incidente #${incidente}) autorizada por ${autorizador} · ${resultado}` });
    return { id: x.id };
  });
  res.status(201).json(r);
}));

module.exports = router;
