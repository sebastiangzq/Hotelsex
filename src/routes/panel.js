// Tablero principal: habitaciones, ocupación y señales de seguridad
const express = require('express');
const { withRole } = require('../db');
const { wrap } = require('../util');
const { requireSession } = require('../middleware/session');
const { guard } = require('../middleware/authorize');

const router = express.Router();
router.use(requireSession());

router.get('/', guard({ recurso: 'reservas', operacion: 'leer' }), wrap(async (req, res) => {
  const u = req.user;
  const privilegiado = u.rol === 'Administrador' || u.rol === 'Auditor';
  const d = await withRole(u.dbRole, u.id, async (c) => {
    const habs = (await c.query(`SELECT h.numero, h.tipo, h.tarifa_noche, h.estado,
        (SELECT e.codigo FROM estancia e WHERE e.habitacion_id = h.id AND e.estado = 'hospedada' LIMIT 1) AS estancia
        FROM habitacion h ORDER BY h.numero`)).rows;
    const hoy = (await c.query(`SELECT count(*)::int AS n FROM estancia WHERE ingreso = current_date AND estado IN ('reservada','hospedada')`)).rows[0].n;
    // Eventos e incidentes solo para quien tiene permiso de lectura (Administrador y Auditor): mínimo privilegio
    let eventos = null, incidentes = null, fallos24h = null;
    if (privilegiado) {
      eventos = (await c.query(`SELECT id, ocurrido_en, tipo, resultado, actor_nombre, detalle FROM bitacora_auditoria ORDER BY id DESC LIMIT 6`)).rows;
      incidentes = (await c.query(`SELECT count(*)::int AS n FROM incidente WHERE estado <> 'cerrado'`)).rows[0].n;
      fallos24h = (await c.query(`SELECT count(*)::int AS n FROM bitacora_auditoria WHERE resultado IN ('fallo','denegado') AND ocurrido_en > now() - interval '24 hours'`)).rows[0].n;
    }
    return { habs, hoy, eventos, incidentes, fallos24h };
  });
  const ocupadas = d.habs.filter((h) => h.estado === 'ocupada').length;
  res.json({
    habitaciones: d.habs, ocupacion_pct: d.habs.length ? Math.round((ocupadas / d.habs.length) * 100) : 0,
    ocupadas, total: d.habs.length, ingresos_hoy: d.hoy,
    incidentes_activos: d.incidentes, fallos_24h: d.fallos24h, eventos_recientes: d.eventos,
  });
}));

module.exports = router;
