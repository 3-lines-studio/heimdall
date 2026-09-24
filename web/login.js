const formulario = document.getElementById('form');
const aviso = document.getElementById('aviso');

if (new URLSearchParams(location.search).has('error')) {
  aviso.textContent = 'Ese link ya no sirve: vencen a los quince minutos y sirven una sola vez.';
}

formulario.addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const email = document.getElementById('email').value.trim();
  aviso.textContent = 'Mandando…';
  try {
    const respuesta = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const datos = await respuesta.json();
    if (datos.link) {
      const enlace = document.createElement('a');
      enlace.href = datos.link;
      enlace.textContent = datos.link;
      aviso.replaceChildren('En dev, entrá con ', enlace);
    } else {
      aviso.textContent = 'Listo. Revisá tu correo.';
    }
  } catch (error) {
    aviso.textContent = 'No pude pedir el link: ' + error.message;
  }
});
