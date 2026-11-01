// Comprueba que el frontend compilado (public/) cumple la CSP estricta del servidor:
//   sin scripts ni estilos en línea, sin atributos style="", sin recursos de otros orígenes.
const fs = require('fs'), path = require('path');
const dir = path.join(__dirname, '..', 'public');
let mal = 0;
const check = (n, ok, x = '') => { if (!ok) mal++; console.log((ok ? '  ✔ ' : '  ✘ ') + n + (ok ? '' : '  → ' + x)); };
const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
check('index.html: todos los <script> son archivos propios (src="/…")', scripts.every((s) => /src="\/[^"]+"/.test(s[1]) && !s[2].trim()));
check('index.html: sin <style> en línea ni atributos style=""', !/<style\b/i.test(html) && !/\sstyle\s*=/i.test(html));
check('index.html: sin manejadores en línea (onclick=…)', !/\son[a-z]+\s*=/i.test(html));
check('index.html: ningún recurso externo (http/https/CDN)', !/(src|href)\s*=\s*"https?:/i.test(html));
const css = fs.readFileSync(path.join(dir, 'app.css'), 'utf8');
check('app.css: sin @import ni url() remotos', !/@import|url\(\s*["']?https?:/i.test(css));
const js = fs.readFileSync(path.join(dir, 'app.js'), 'utf8');
check('app.js: sin eval ni new Function', !/\beval\(|new Function\(/.test(js));
check('app.js: no referencia CDNs conocidos', !/cdn\.tailwindcss|cdnjs\.cloudflare|unpkg\.com|jsdelivr|googleapis|babel-standalone/i.test(js));
process.exit(mal ? 1 : 0);
