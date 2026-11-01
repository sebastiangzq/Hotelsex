// Habitaciones: tras el check-out la habitación queda en "limpieza"; recepción la devuelve a "libre".
const express = require('express');
const { withRole } = require('../db');
const { wrap, HttpError } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');
const { texto } = require('../validar');
const audit = require('../audit');

const router = express.Router();
router.use(requireSession());

router.post('/:numero/liberar', guard({ recurso: 'reservas', operacion: 'modificar' }), wrap(async (req, res) => {
  const numero = texto(req.params.numero, 'Habitación', { max: 10 });
  const r = await withRole(req.user.dbRole, req.user.id, async (c) => {
    const h = (await c.query('SELECT id, estado FROM habitacion WHERE numero = $1 FOR UPDATE', [numero])).rows[0];
    if (!h) throw new HttpError(404, 'Habitación inexistente');
    if (h.estado !== 'limpieza') throw new HttpError(409, 'Solo se libera una habitación que está en limpieza');
    await c.query(`UPDATE habitacion SET estado = 'libre' WHERE id = $1`, [h.id]);
    await audit.registrarEn(c, { tipo: 'huesped', resultado: 'exito', actorId: req.user.id, actorNombre: req.user.username, ip: req.ip,
      detalle: `Habitación ${numero}: limpieza → libre` });
    return { numero, estado: 'libre' };
  });
  res.json(r);
}));

module.exports = router;
