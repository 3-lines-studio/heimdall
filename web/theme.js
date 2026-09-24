(() => {
  const clave = 'heimdall-tema';
  const raiz = document.documentElement;
  const sistema = matchMedia('(prefers-color-scheme: light)');
  const elegido = localStorage.getItem(clave);

  raiz.dataset.theme = elegido || (sistema.matches ? 'light' : 'dark');

  function pintar() {
    const claro = raiz.dataset.theme === 'light';
    const boton = document.getElementById('tema');
    if (boton) {
      boton.textContent = claro ? '☾' : '☀';
      boton.title = claro ? 'pasar al tema oscuro' : 'pasar al tema claro';
      boton.setAttribute('aria-label', boton.title);
    }
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = getComputedStyle(raiz).getPropertyValue('--fondo').trim();
  }

  addEventListener('DOMContentLoaded', () => {
    document.getElementById('tema')?.addEventListener('click', () => {
      raiz.dataset.theme = raiz.dataset.theme === 'light' ? 'dark' : 'light';
      localStorage.setItem(clave, raiz.dataset.theme);
      pintar();
    });
    pintar();
  });

  sistema.addEventListener('change', (evento) => {
    if (localStorage.getItem(clave)) return;
    raiz.dataset.theme = evento.matches ? 'light' : 'dark';
    pintar();
  });
})();
