// Descifra un archivo .enc de HotelSec (exportación de bitácora o respaldo). Requiere la MASTER_KEY del .env.
//   node scripts/descifrar.js <archivo.enc> [salida]
require('dotenv').config();
const fs = require('fs');
const { descifrarBuffer } = require('../src/crypto');
const [, , entrada, salida] = process.argv;
if (!entrada) { console.error('Uso: node scripts/descifrar.js <archivo.enc> [salida]'); process.exit(1); }
const datos = fs.readFileSync(entrada);
for (const aad of ['bitacora-export', 'respaldo']) {
  try {
    const claro = descifrarBuffer(datos, aad, 'export');
    if (salida) { fs.writeFileSync(salida, claro); console.log(`✔ Descifrado (${aad}) -> ${salida}`); } else process.stdout.write(claro);
    process.exit(0);
  } catch { /* probar el siguiente contexto */ }
}
console.error('No se pudo descifrar: clave incorrecta o archivo alterado (el cifrado autenticado lo detecta).');
process.exit(1);
