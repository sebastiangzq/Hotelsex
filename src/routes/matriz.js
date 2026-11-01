// Parte 6 · Matriz de mínimo privilegio (consulta, modificación y simulador de la decisión de acceso)
const crypto = require('crypto');
const express = require('express');
const { withRole, AUTH } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto, enumerado } = require('../validar');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());

const VER = guard({ recurso: 'bitacora', operacion: 'leer' });          // Administrador y Auditor
const MODIFICAR = [guard({ recurso: 'configuracion', operacion: 'modificar', sistema: 'modificar_matriz' })];

const SQL_VIGENTE = `rp.vigente_desde <= now() AND (rp.vigente_hasta IS NULL OR rp.vigente_hasta > now())`;

router.get('/', VER, wrap(async (req, res) => {
  const d = await withRole(AUTH, null, async (c) => ({
    roles: (await c.query('SELECT nombre FROM rol ORDER BY id')).rows.map((r) => r.nombre),
    catalogo: (await c.query(`SELECT rc.nombre AS recurso, op.nombre AS operacion FROM permiso p
                               JOIN recurso rc ON rc.id = p.recurso_id JOIN operacion op ON op.id = p.operacion_id ORDER BY rc.id, op.id`)).rows,
    vigentes: (await c.query(`SELECT r.nombre AS rol, rc.nombre AS recurso, op.nombre AS operacion FROM rol_permiso rp
                               JOIN rol r ON r.id = rp.rol_id JOIN permiso p ON p.id = rp.permiso_id
                               JOIN recurso rc ON rc.id = p.recurso_id JOIN operacion op ON op.id = p.operacion_id WHERE ${SQL_VIGENTE}`)).rows,
  }));
  const matriz = {};
  for (const r of d.roles) matriz[r] = {};
  for (const v of d.vigentes) (matriz[v.rol][v.recurso] ||= []).push(v.operacion);
  const recursos = [...new Set(d.catalogo.map((x) => x.recurso))];
  res.json({ roles: d.roles, recursos, operaciones: ['leer', 'crear', 'modificar', 'eliminar'], catalogo: d.catalogo, matriz });
}));

// Identidades para el simulador (el Auditor no puede leer la tabla de usuarios completa: aquí solo código, usuario, rol y estado)
router.get('/usuarios', VER, wrap(async (req, res) => {
  const r = await withRole(AUTH, null, (c) => c.query(
    `SELECT u.codigo, u.username, r.nombre AS rol, u.estado FROM usuario u JOIN rol r ON r.id = u.rol_id ORDER BY u.creado_en, u.codigo`));
  res.json({ usuarios: r.rows });
}));

// Conceder / revocar un permiso. No se borra nada: se cierra la vigencia (queda el rastro)
router.put('/', ...MODIFICAR, wrap(async (req, res) => {
  const b = req.body || {};
  const rol = texto(b.rol, 'Rol', { max: 40 }), recurso = texto(b.recurso, 'Recurso', { max: 40 }), operacion = texto(b.operacion, 'Operación', { max: 20 });
  const conceder = b.conceder === true;
  if (recurso === 'bitacora' && operacion !== 'leer') throw new HttpError(422, 'La bitácora es inalterable: no admite crear, modificar ni eliminar para ningún rol');
  if (rol === 'Administrador' && recurso === 'configuracion' && !conceder && ['leer', 'modificar'].includes(operacion)) {
    throw new HttpError(409, 'No puede quitarle al Administrador la gestión de la configuración (el sistema quedaría sin administración)');
  }
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const p = (await c.query(
      `SELECT r.id AS rol_id, p.id AS permiso_id FROM rol r, permiso p JOIN recurso rc ON rc.id = p.recurso_id JOIN operacion op ON op.id = p.operacion_id
        WHERE r.nombre = $1 AND rc.nombre = $2 AND op.nombre = $3`, [rol, recurso, operacion])).rows[0];
    if (!p) throw new HttpError(422, 'Combinación de rol, recurso y operación inexistente');
    if (conceder) {
      await c.query(`INSERT INTO rol_permiso (rol_id, permiso_id, concedido_por) VALUES ($1, $2, $3)
                     ON CONFLICT (rol_id, permiso_id) DO UPDATE
                        SET vigente_desde = now(), vigente_hasta = NULL, concedido_por = EXCLUDED.concedido_por
                      WHERE rol_permiso.vigente_hasta IS NOT NULL AND rol_permiso.vigente_hasta <= now()`, [p.rol_id, p.permiso_id, req.user.id]);
    } else {
      await c.query(`UPDATE rol_permiso SET vigente_hasta = now() WHERE rol_id = $1 AND permiso_id = $2
                      AND (vigente_hasta IS NULL OR vigente_hasta > now())`, [p.rol_id, p.permiso_id]);
    }
    await audit.registrarEn(c, { tipo: 'configuracion', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Matriz: ${rol} · ${recurso} · ${operacion} ${conceder ? 'CONCEDIDO' : 'REVOCADO'}` });
  });
  res.json({ rol, recurso, operacion, conceder });
}));

// Simulador: usa la MISMA función evaluar_acceso que protege al sistema real y explica en qué paso falla
const PASOS = ['Identidad autenticada', 'Operación solicitada', 'Recurso afectado', 'Permisos vigentes', 'Contexto persona/objeto'];
router.post('/evaluar', VER, wrap(async (req, res) => {
  const b = req.body || {};
  const codigo = texto(b.usuario, 'Usuario', { max: 20 });
  const recurso = texto(b.recurso, 'Recurso', { max: 40 }), operacion = texto(b.operacion, 'Operación', { max: 20 });
  const contexto = enumerado(b.contexto || 'propio', 'Contexto', ['propio', 'ajeno']);
  const sujeto = (await withRole(AUTH, null, (c) => c.query('SELECT id, username FROM usuario WHERE codigo = $1', [codigo]))).rows[0];
  if (!sujeto) throw new HttpError(404, 'Identidad no encontrada');
  const dueno = contexto === 'propio' ? sujeto.id : crypto.randomUUID();
  const ev = (await withRole(req.user.dbRole, req.user.id, (c) =>
    c.query('SELECT permitido, motivo FROM evaluar_acceso($1, $2, $3, $4)', [sujeto.id, recurso, operacion, dueno]))).rows[0];

  const m = ev.motivo || '';
  const falla = ev.permitido ? -1 : /Identidad/.test(m) ? 0 : /Operaci[oó]n/.test(m) ? 1 : /permiso vigente/.test(m) ? 3 : 4;
  const pasos = PASOS.map((nombre, i) => ({ nombre, estado: falla === -1 || i < falla ? 'ok' : i === falla ? 'falla' : 'omitido',
    detalle: i === falla ? m : null }));
  if (ev.permitido) await req.audit('autorizacion', 'exito', `Simulación: ${sujeto.username} · ${recurso} · ${operacion} (${contexto}) → PERMITIDO`);
  res.json({ permitido: ev.permitido, motivo: ev.motivo, pasos });
}));

module.exports = router;
