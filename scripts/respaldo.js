// Crea un respaldo COMPLETO cifrado (AES-256-GCM) y lo registra en la tabla "respaldo".
//   npm run respaldo        (requiere pg_dump instalado y OWNER_DATABASE_URL en .env)
// Restaurar: node scripts/descifrar.js backups/<archivo>.enc backups/restaurar.dump
//            pg_restore --clean --if-exists --no-owner -d <base> backups/restaurar.dump   (con control dual y un incidente vigente)
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { Client } = require('pg');
const { cifrar, sha256 } = require('../src/crypto');

(async () => {
  const url = process.env.OWNER_DATABASE_URL;
  if (!url) throw new Error('Falta OWNER_DATABASE_URL en .env');
  const dir = path.resolve(process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups'));
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const d = spawnSync('pg_dump', ['--format=custom', '--no-owner', '--dbname', url], { maxBuffer: 1 << 30 });
  if (d.status !== 0) throw new Error('pg_dump falló: ' + (d.stderr || d.error || '').toString());
  const cifrado = cifrar(d.stdout, 'respaldo', 'export');
  const sello = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const archivo = path.join(dir, `hotelsec_${sello}.dump.enc`);
  fs.writeFileSync(archivo, cifrado, { mode: 0o600 });
  const huella = sha256(cifrado).toString('hex');
  const c = new Client({ connectionString: url });
  await c.connect();
  const r = await c.query(`INSERT INTO respaldo (alcance, ubicacion, sha256, cifrado) VALUES ('completo', $1, $2, true) RETURNING id`, [archivo, huella]);
  await c.query(`INSERT INTO bitacora_auditoria (tipo, resultado, actor_nombre, detalle) VALUES ('configuracion', 'exito', 'sistema', $1)`,
    [`Respaldo completo #${r.rows[0].id} creado y cifrado · sha256 ${huella.slice(0, 16)}…`]);
  await c.end();
  console.log(`✔ Respaldo #${r.rows[0].id}: ${archivo}\n  SHA-256: ${huella}`);
})().catch((e) => { console.error('Error:', e.message); process.exit(1); });
