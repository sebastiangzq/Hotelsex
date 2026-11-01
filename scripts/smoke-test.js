// Prueba rápida del Paso 1 contra un servidor ya levantado:  node scripts/smoke-test.js
// Requiere la BD recién creada (npm run setup:db). Cambia el estado de 'admin' (activa su 2FA).
const { authenticator } = require('otplib');
const BASE = process.env.BASE || 'http://localhost:3000';
let ok = 0, mal = 0;
const check = (nombre, cond, extra = '') => { cond ? ok++ : mal++; console.log((cond ? '  ✔ ' : '  ✘ ') + nombre + (cond ? '' : '  ' + extra)); };

async function api(metodo, ruta, cuerpo, cookie) {
  const r = await fetch(BASE + ruta, {
    method: metodo,
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hotelsec', ...(cookie ? { Cookie: cookie } : {}) },
    body: cuerpo ? JSON.stringify(cuerpo) : undefined,
  });
  const set = r.headers.get('set-cookie');
  return { s: r.status, j: await r.json().catch(() => ({})), cookie: set ? set.split(';')[0] : null, h: r.headers };
}

(async () => {
  console.log('1) Cabeceras y CSRF');
  let r = await api('GET', '/api/salud');
  check('CSP presente', /default-src 'self'/.test(r.h.get('content-security-policy') || ''));
  const sin = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  check('POST sin X-Requested-With es rechazado (CSRF)', sin.status === 403);
  const otro = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hotelsec', Origin: 'https://malo.com' }, body: '{}' });
  check('Origin ajeno es rechazado', otro.status === 403);

  console.log('2) Mensajes que no revelan si la cuenta existe');
  const a = await api('POST', '/api/auth/login', { username: 'recepcion', password: 'mala' });
  const b = await api('POST', '/api/auth/login', { username: 'noexiste', password: 'mala' });
  const c = await api('POST', '/api/auth/login', { username: 'jperez', password: 'Temp#2026' });   // suspendida, clave correcta
  const d = await api('POST', '/api/auth/login', { username: 'mvargas', password: 'Temp#2026' });  // revocada, clave correcta
  check('existente / inexistente / suspendida / revocada → mismo 401 y mismo mensaje',
    [a, b, c, d].every((x) => x.s === 401 && x.j.error === 'Credenciales incorrectas'), JSON.stringify([a.j, b.j, c.j, d.j]));

  console.log('3) Bloqueo tras 3 fallos (igual para cuenta real e inexistente)');
  let x = await api('POST', '/api/auth/login', { username: 'recepcion', password: 'mala' });
  x = await api('POST', '/api/auth/login', { username: 'recepcion', password: 'mala' });
  check('3.er fallo de usuario real → 429 con segundos', x.s === 429 && x.j.reintentar_en_s > 0, JSON.stringify(x.j));
  let y = await api('POST', '/api/auth/login', { username: 'noexiste', password: 'mala' });
  y = await api('POST', '/api/auth/login', { username: 'noexiste', password: 'mala' });
  check('3.er fallo de usuario inexistente → 429 también', y.s === 429 && y.j.reintentar_en_s > 0, JSON.stringify(y.j));
  const bloq = await api('POST', '/api/auth/login', { username: 'recepcion', password: 'Recep#2026' });
  check('con la clave CORRECTA sigue bloqueado mientras dura el bloqueo', bloq.s === 429, JSON.stringify(bloq.j));

  console.log('4) Login correcto, cookie y sesión');
  const L = await api('POST', '/api/auth/login', { username: 'admin', password: 'Admin#2026' });
  check('login admin → 200', L.s === 200 && L.j.usuario?.rol === 'Administrador', JSON.stringify(L.j));
  const ck = L.cookie;
  check('cookie con token', !!ck && ck.startsWith('hs_session='));
  const setc = (await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hotelsec' }, body: JSON.stringify({ username: 'admin', password: 'Admin#2026' }) })).headers.get('set-cookie') || '';
  check('cookie HttpOnly + SameSite=Strict', /HttpOnly/i.test(setc) && /SameSite=Strict/i.test(setc), setc);
  const yo = await api('GET', '/api/auth/yo', null, ck);
  check('/yo devuelve rol y permisos del Administrador', yo.s === 200 && yo.j.permisos?.bitacora?.join() === 'leer' && yo.j.permisos?.configuracion?.includes('modificar'), JSON.stringify(yo.j));
  check('sin cookie → 401', (await api('GET', '/api/auth/yo')).s === 401);
  check('token falso → 401', (await api('GET', '/api/auth/yo', null, 'hs_session=' + 'a'.repeat(43))).s === 401);

  console.log('5) Segundo factor TOTP');
  const mal0 = await api('POST', '/api/auth/2fa/iniciar', { password: 'incorrecta' }, ck);
  check('iniciar 2FA con contraseña mala → 401', mal0.s === 401);
  const ini = await api('POST', '/api/auth/2fa/iniciar', { password: 'Admin#2026' }, ck);
  if (ini.s === 409) { console.log('  · el 2FA de admin ya estaba habilitado, se omite el resto de la sección'); }
  else {
    check('iniciar → secreto + QR', ini.s === 200 && ini.j.secreto && ini.j.qr?.startsWith('data:image/png'), JSON.stringify(ini.j).slice(0, 120));
    const mal1 = await api('POST', '/api/auth/2fa/activar', { codigo: '000000' }, ck);
    check('activar con código malo → 401', mal1.s === 401);
    const act = await api('POST', '/api/auth/2fa/activar', { codigo: authenticator.generate(ini.j.secreto) }, ck);
    check('activar con código bueno → 200', act.s === 200, JSON.stringify(act.j));
    require('fs').writeFileSync('/tmp/admin_totp.txt', ini.j.secreto);
    const ver = await api('POST', '/api/auth/2fa/verificar', { codigo: authenticator.generate(ini.j.secreto) }, ck);
    check('reusar el MISMO código es rechazado (anti-replay)', ver.s === 401, JSON.stringify(ver.j));
  }

  console.log('6) Cierre de sesión');
  const out = await api('POST', '/api/auth/logout', null, ck);
  check('logout → 200', out.s === 200);
  check('el token revocado ya no sirve', (await api('GET', '/api/auth/yo', null, ck)).s === 401);

  console.log(`\nResultado: ${ok} correctas, ${mal} fallidas`);
  process.exit(mal ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
