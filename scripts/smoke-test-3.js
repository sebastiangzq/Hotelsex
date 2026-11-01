// Prueba del Paso 3 contra un servidor levantado y una BD con la semilla (npm run setup:db -- --reset --yes).
//   node scripts/smoke-test-3.js
// Cubre: frontend servido con CSP estricta, rutas añadidas en este paso (check-in de reserva, liberar habitación, usuarios del simulador).
require('dotenv').config();
const BASE = process.env.BASE || 'http://localhost:3000';
let ok = 0, mal = 0;
const check = (n, c, x = '') => { c ? ok++ : mal++; console.log((c ? '  ✔ ' : '  ✘ ') + n + (c ? '' : '   → ' + String(x).slice(0, 300))); };
async function api(m, r, body, ck) {
  const res = await fetch(BASE + r, { method: m, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hotelsec', ...(ck ? { Cookie: ck } : {}) }, body: body ? JSON.stringify(body) : undefined });
  let j = {}; try { j = await res.json(); } catch { /* no JSON */ }
  const set = res.headers.get('set-cookie');
  return { s: res.status, j, cookie: set ? set.split(';')[0] : null };
}
const login = async (u, p) => (await api('POST', '/api/auth/login', { username: u, password: p })).cookie;
const mas = (d) => new Date(Date.now() + d * 864e5).toISOString().slice(0, 10);

(async () => {
  console.log('\n1) Frontend estático y cabeceras');
  const idx = await fetch(BASE + '/');
  const csp = idx.headers.get('content-security-policy') || '';
  check('GET / entrega index.html', idx.status === 200 && (await idx.text()).includes('id="root"'));
  check("CSP estricta: script-src 'self' y sin 'unsafe-inline'", /script-src 'self'/.test(csp) && !/unsafe-inline|unsafe-eval/.test(csp), csp);
  for (const f of ['/app.js', '/app.css', '/theme.js']) check('GET ' + f, (await fetch(BASE + f)).status === 200);

  console.log('\n2) Rutas nuevas');
  const R = await login('recepcion', 'Recep#2026'), A = await login('auditor', 'Audit#2026');
  check('inicio de sesión de recepción y auditor', R && A);
  const panel = (await api('GET', '/api/panel', null, R)).j;
  const limpieza = panel.habitaciones.find((h) => h.estado === 'limpieza');
  const lib = await api('POST', `/api/habitaciones/${limpieza.numero}/liberar`, null, R);
  check('recepción libera una habitación en limpieza', lib.s === 200 && lib.j.estado === 'libre', JSON.stringify(lib.j));
  check('liberar otra vez → 409', (await api('POST', `/api/habitaciones/${limpieza.numero}/liberar`, null, R)).s === 409);
  check('el Auditor no puede liberar habitaciones → 403', (await api('POST', `/api/habitaciones/${limpieza.numero}/liberar`, null, A)).s === 403);

  const libre = (await api('GET', '/api/panel', null, R)).j.habitaciones.find((h) => h.estado === 'libre');
  const futura = await api('POST', '/api/huespedes', { nombre: 'Prueba Reserva Futura', documento: 'SMK3-' + Date.now().toString().slice(-6), nacionalidad: 'Boliviana', consentimiento: true,
    ingreso: mas(20), salida: mas(22), habitacion: libre.numero, metodo_pago: 'efectivo', monto: 300 }, R);
  check('reserva a futuro se crea como «reservada»', futura.s === 201 && futura.j.estado === 'reservada', JSON.stringify(futura.j));
  const ci = await api('POST', `/api/huespedes/${futura.j.codigo}/checkin`, null, R);
  check('check-in antes de la fecha de ingreso → 409', ci.s === 409, JSON.stringify(ci.j));

  console.log('\n3) Simulador de la matriz: usuarios');
  const us = await api('GET', '/api/matriz/usuarios', null, A);
  check('el Auditor obtiene la lista mínima de identidades (sin hashes)', us.s === 200 && us.j.usuarios.length >= 5 && !JSON.stringify(us.j).includes('argon2'));
  check('recepción NO puede consultarla → 403', (await api('GET', '/api/matriz/usuarios', null, R)).s === 403);

  console.log(`\n${ok} correctas, ${mal} con fallo`);
  process.exit(mal ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
