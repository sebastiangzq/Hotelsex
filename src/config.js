// Carga y valida la configuración. Si falta algo crítico, la app NO arranca.
require('dotenv').config();

function exigir(nombre) {
  const v = process.env[nombre];
  if (!v) { console.error(`[config] Falta la variable ${nombre}. Revise su archivo .env`); process.exit(1); }
  return v;
}
function parseProxy(v) {
  if (!v || v === 'false') return false;
  if (v === 'true') return true;
  return /^\d+$/.test(v) ? parseInt(v, 10) : v;
}

const master = Buffer.from(exigir('MASTER_KEY'), 'base64');
if (master.length !== 32) {
  console.error('[config] MASTER_KEY debe ser de 32 bytes en base64. Genere una con: npm run gen:key');
  process.exit(1);
}
const env = process.env.NODE_ENV || 'development';

module.exports = {
  env,
  port: parseInt(process.env.PORT || '3000', 10),
  databaseUrl: exigir('DATABASE_URL'),
  master,
  cookieSecure: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : env === 'production',
  trustProxy: parseProxy(process.env.TRUST_PROXY),
  appOrigin: process.env.APP_ORIGIN || null,
  sesionAbsolutaHoras: parseInt(process.env.SESSION_ABS_HOURS || '8', 10),
  maxFallosPorIp: parseInt(process.env.MAX_FALLOS_POR_IP || '20', 10),
  loginRateMax: parseInt(process.env.RATE_LOGIN_MAX || '30', 10),
  totpEmisor: 'HotelSec',
  cookieNombre: 'hs_session',
};
