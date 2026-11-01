// Partes 7 y 8 · Políticas de seguridad y controles verificables (cada regla se prueba contra la BD real)
const express = require('express');
const { withRole } = require('../db');
const { wrap } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());

router.get('/', guard({ recurso: 'reservas', operacion: 'leer' }), wrap(async (req, res) => {
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => ({
    politicas: (await c.query('SELECT id, codigo, titulo, regla FROM politica ORDER BY id')).rows,
    controles: (await c.query('SELECT id, politica_id, control, mecanismo FROM control_verificable ORDER BY id')).rows,   // la prueba_sql no se expone
  }));
  res.json({ politicas: r.politicas.map((p) => ({ ...p, controles: r.controles.filter((x) => x.politica_id === p.id).map(({ politica_id, ...x }) => x) })) });
}));

// Ejecuta TODAS las pruebas. Devuelve cumple=true cuando la consulta de control no encuentra ninguna violación.
router.post('/verificar', guard({ recurso: 'bitacora', operacion: 'leer' }), wrap(async (req, res) => {
  const filas = await withRole(req.user.dbRole, req.user.id, async (c) => (await c.query(
    `SELECT cv.id, p.codigo AS politica, cv.control, cv.mecanismo, e.cumple, e.filas_fallo, e.error
       FROM ejecutar_controles() e JOIN control_verificable cv ON cv.id = e.control_id JOIN politica p ON p.id = cv.politica_id ORDER BY cv.id`)).rows);
  const cumplen = filas.filter((f) => f.cumple).length;
  await req.audit('configuracion', cumplen === filas.length ? 'exito' : 'fallo', `Verificación de controles: ${cumplen}/${filas.length} cumplen`);
  res.json({ resumen: { total: filas.length, cumplen, fallan: filas.length - cumplen }, controles: filas });
}));

module.exports = router;
