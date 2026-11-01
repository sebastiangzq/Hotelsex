// Compila el frontend a ../public (sin CDN, sin Babel en el navegador, sin scripts ni estilos en línea).
//   npm run build:front
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const req = createRequire(import.meta.url);
const { build } = req('esbuild');
const aqui = dirname(fileURLToPath(import.meta.url));
const out = join(aqui, '..', 'public');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

await build({
  entryPoints: [join(aqui, 'src/main.jsx')], outfile: join(out, 'app.js'),
  bundle: true, minify: true, format: 'iife', target: ['es2020'], jsx: 'automatic',
  define: { 'process.env.NODE_ENV': '"production"' }, legalComments: 'none', nodePaths: (process.env.NODE_PATH || '').split(':').filter(Boolean), logLevel: 'info',
});

const twBin = join(dirname(req.resolve('tailwindcss/package.json')), 'lib', 'cli.js');
execFileSync(process.execPath, [twBin, '-c', join(aqui, 'tailwind.config.js'), '-i', join(aqui, 'styles.css'), '-o', join(out, 'app.css'), '--minify'], { stdio: 'inherit', cwd: aqui });

cpSync(join(aqui, 'index.html'), join(out, 'index.html'));
cpSync(join(aqui, 'theme.js'), join(out, 'theme.js'));
const js = readFileSync(join(out, 'app.js'), 'utf8');
console.log(`✔ public/ generado · app.js ${(js.length / 1024).toFixed(0)} KB · sin dependencias externas`);
