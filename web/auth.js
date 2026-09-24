const token = new URLSearchParams(location.hash.slice(1)).get('token');
const aviso = document.getElementById('aviso');

async function entrar() {
  if (!token) {
    location.replace('/login?error=1');
    return;
  }
  try {
    const respuesta = await fetch('/api/enter', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (respuesta.ok) location.replace('/');
    else location.replace('/login?error=1');
  } catch {
    aviso.textContent = 'No pude entrar. Probá de nuevo.';
  }
}

entrar();
