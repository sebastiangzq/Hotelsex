// Aplica el tema antes de pintar (evita el parpadeo). Va como archivo propio porque la CSP no admite scripts en línea.
(function () {
  var t = null;
  try { t = localStorage.getItem('hs-tema'); } catch (e) { /* sin almacenamiento */ }
  if (t === 'dark' || (t !== 'light' && window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches)) document.documentElement.classList.add('dark');
})();
