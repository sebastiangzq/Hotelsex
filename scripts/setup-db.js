// Prepara la base de datos: esquema (db/01), roles de la app (db/02...) y clave del rol hotelsec_app.
//   npm run setup:db            -> aplica lo que falte (no toca datos existentes)
//   npm run setup:db -- --reset --yes -> BORRA el esquema "public" y lo recrea desde cero
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

(async () => {
  const url = process.env.OWNER_DATABASE_URL, clave = process.env.APP_DB_PASSWORD;
  if (!url || !clave) { console.error('Faltan OWNER_DATABASE_URL y/o APP_DB_PASSWORD en .env'); process.exit(1); }
  if (clave.length < 12 || /CAMBIE/i.test(clave)) { console.error('APP_DB_PASSWORD debe ser una clave real de al menos 12 caracteres.'); process.exit(1); }
  const c = new Client({ connectionString: url });
  await c.connect();
  const reset = process.argv.includes('--reset');
  if (reset) {
    if (!process.argv.includes('--yes')) { console.error('--reset borra TODOS los datos. Repita con --reset --yes para confirmar.'); process.exit(1); }
    await c.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT USAGE ON SCHEMA public TO PUBLIC;');
    console.log('Esquema public recreado.');
  }
  const existe = (await c.query("SELECT to_regclass('public.usuario') IS NOT NULL AS ok")).rows[0].ok;
  const dir = path.join(__dirname, '..', 'db');
  for (const f of fs.readdirSync(dir).filter((x) => /^\d+_.*\.sql$/.test(x)).sort()) {
    if (f.startsWith('01_') && existe) { console.log('· ' + f + ' (ya aplicado, se omite)'); continue; }
    await c.query(fs.readFileSync(path.join(dir, f), 'utf8'));     // cada archivo corre como una sola transacción
    console.log('✔ ' + f);
  }
  const q = await c.query("SELECT format('ALTER ROLE hotelsec_app PASSWORD %L', $1::text) AS q", [clave]);
  await c.query(q.rows[0].q);
  console.log('✔ Clave de hotelsec_app establecida. Listo.');
  await c.end();
})().catch((e) => { console.error('Error:', e.message); process.exit(1); });
