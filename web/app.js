const estado = { project: null, env: null, secretos: {}, revelados: new Set() };

const $ = (id) => document.getElementById(id);

async function api(method, ruta, cuerpo) {
  const opciones = { method, headers: {} };
  if (cuerpo !== undefined) {
    opciones.headers['Content-Type'] = 'application/json';
    opciones.body = JSON.stringify(cuerpo);
  }
  const respuesta = await fetch(ruta, opciones);
  const texto = await respuesta.text();
  const datos = texto ? JSON.parse(texto) : {};
  if (!respuesta.ok) throw new Error(datos.error || `falló con ${respuesta.status}`);
  return datos;
}

function nodo(etiqueta, texto, clase) {
  const elemento = document.createElement(etiqueta);
  if (texto !== undefined && texto !== null) elemento.textContent = texto;
  if (clase) elemento.className = clase;
  return elemento;
}

function boton(texto, clase, accion) {
  const elemento = nodo('button', texto, clase);
  elemento.type = 'button';
  elemento.addEventListener('click', accion);
  return elemento;
}

let avisoTimer = null;
function aviso(texto) {
  const caja = $('aviso');
  caja.textContent = texto;
  caja.hidden = false;
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(() => { caja.hidden = true; }, 2500);
}

async function copiar(texto) {
  try {
    await navigator.clipboard.writeText(texto);
    aviso('Copiado.');
  } catch {
    aviso('El navegador no me dejó copiar.');
  }
}

const fecha = (cuando) => new Date(cuando * 1000).toLocaleString();

async function cargarEntornos() {
  const lista = await api('GET', '/v1/environments');
  const nav = $('entornos');
  nav.replaceChildren();
  nav.append(boton('+ nuevo', 'fantasma', empezar));
  if (!lista.length) {
    nav.append(nodo('p', 'Todavía no hay secretos.', 'tenue'));
    return lista;
  }
  for (const nombre of lista) {
    const [project, env] = nombre.split('/');
    const activo = project === estado.project && env === estado.env;
    const elemento = boton(nombre, activo ? 'entorno activo' : 'entorno', () => abrir(project, env));
    nav.append(elemento);
  }
  return lista;
}

function empezar() {
  $('contenido').hidden = true;
  $('vacio').hidden = true;
  $('primer').hidden = false;
  $('primer-project').focus();
}

async function abrir(project, env) {
  estado.project = project;
  estado.env = env;
  estado.revelados.clear();
  try {
    estado.secretos = await api('GET', urlDeClaves(project, env));
  } catch (error) {
    aviso(error.message);
    return;
  }
  $('vacio').hidden = true;
  $('primer').hidden = true;
  $('contenido').hidden = false;
  $('titulo').textContent = `${project} / ${env}`;
  renderSecretos();
  await cargarEntornos();
  await cargarTokens();
  await cargarAuditoria();
}

function renderSecretos() {
  const filas = $('filas');
  filas.replaceChildren();
  const claves = Object.keys(estado.secretos).sort();
  if (!claves.length) {
    const fila = nodo('tr');
    const celda = nodo('td', 'Vacío: agregá una clave abajo.', 'tenue');
    celda.colSpan = 3;
    fila.append(celda);
    filas.append(fila);
    return;
  }
  for (const clave of claves) {
    const valor = estado.secretos[clave];
    const revelado = estado.revelados.has(clave);
    const fila = nodo('tr');
    fila.append(nodo('td', clave, 'clave'));
    const celda = nodo('td');
    celda.append(nodo('code', revelado ? valor : '••••••••'));
    fila.append(celda);
    const acciones = nodo('td', null, 'acciones');
    acciones.append(boton(revelado ? 'Ocultar' : 'Ver', 'fantasma', () => {
      if (revelado) estado.revelados.delete(clave); else estado.revelados.add(clave);
      renderSecretos();
    }));
    acciones.append(boton('Copiar', 'fantasma', () => copiar(valor)));
    acciones.append(boton('Borrar', 'peligro', async () => {
      try {
        await api('DELETE', '/v1/secrets', { project: estado.project, env: estado.env, key: clave });
        delete estado.secretos[clave];
        renderSecretos();
        aviso(`${clave} borrada.`);
      } catch (error) {
        aviso(error.message);
      }
    }));
    fila.append(acciones);
    filas.append(fila);
  }
}

async function cargarTokens() {
  const caja = $('tokens');
  caja.replaceChildren();
  const lista = await api('GET', '/v1/tokens');
  if (!lista.length) {
    caja.append(nodo('p', 'No hay tokens.', 'tenue'));
    return;
  }
  for (const token of lista) {
    const fila = nodo('div', null, 'fila');
    const detalles = [alcanceDeToken(token)];
    if (token.expires_at) detalles.push(`vence ${fecha(token.expires_at)}`);
    detalles.push(token.last_used ? `último uso ${fecha(token.last_used)}` : 'sin uso');
    const texto = nodo('div');
    texto.append(nodo('strong', token.name));
    texto.append(nodo('span', ' ' + detalles.join(' · '), 'tenue'));
    fila.append(texto);
    fila.append(boton('Revocar', 'peligro', async () => {
      try {
        await api('DELETE', `/v1/tokens?id=${encodeURIComponent(token.id)}`);
        await cargarTokens();
        aviso(`${token.name} revocado.`);
      } catch (error) {
        aviso(error.message);
      }
    }));
    caja.append(fila);
  }
}

async function cargarAuditoria() {
  const caja = $('auditoria');
  caja.replaceChildren();
  const lista = await api('GET', '/v1/audit?limit=50');
  if (!lista.length) {
    caja.append(nodo('p', 'Sin movimientos.', 'tenue'));
    return;
  }
  for (const entrada of lista) {
    const donde = entrada.project ? ` ${entrada.project}/${entrada.env}` : '';
    const clave = entrada.key ? ` ${entrada.key}` : '';
    caja.append(nodo('div', `${fecha(entrada.at)} · ${entrada.actor} · ${entrada.action}${donde}${clave}`, 'renglon'));
  }
}

$('primer').addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const project = $('primer-project').value.trim();
  const env = $('primer-env').value.trim();
  const clave = $('primer-clave').value.trim();
  const valor = $('primer-valor').value;
  try {
    await api('PUT', '/v1/secrets', { project, env, key: clave, value: valor });
  } catch (error) {
    aviso(error.message);
    return;
  }
  $('primer').hidden = true;
  for (const id of ['primer-project', 'primer-env', 'primer-clave', 'primer-valor']) $(id).value = '';
  await abrir(project, env);
  aviso(`${clave} guardada en ${project}/${env}.`);
});

$('alta').addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const clave = $('clave').value.trim();
  const valor = $('valor').value;
  try {
    await api('PUT', '/v1/secrets', { project: estado.project, env: estado.env, key: clave, value: valor });
    estado.secretos[clave] = valor;
    $('clave').value = '';
    $('valor').value = '';
    renderSecretos();
    aviso(`${clave} guardada.`);
  } catch (error) {
    aviso(error.message);
  }
});

$('env').addEventListener('click', () => copiar(comoEnv(estado.secretos)));

$('refrescar').addEventListener('click', () => abrir(estado.project, estado.env));

$('token-nuevo').addEventListener('submit', async (evento) => {
  evento.preventDefault();
  const cuerpo = {
    name: $('token-nombre').value.trim(),
    project: estado.project,
    env: estado.env,
  };
  const claves = clavesDe($('token-claves').value);
  if (claves.length) cuerpo.keys = claves;
  const ttl = $('token-ttl').value.trim();
  if (ttl) {
    const vencimiento = segundos(ttl);
    if (vencimiento === null) {
      aviso('El vencimiento va como 30m, 2h o 7d.');
      return;
    }
    cuerpo.ttl = vencimiento;
  }
  try {
    const creado = await api('POST', '/v1/tokens', cuerpo);
    $('token-nombre').value = '';
    $('token-claves').value = '';
    $('token-ttl').value = '';
    await cargarTokens();
    aviso('Guardalo ahora, no se vuelve a mostrar.');
    const caja = nodo('div', null, 'nuevo');
    caja.append(nodo('div', 'Este token no se vuelve a mostrar:'));
    caja.append(nodo('code', creado.token));
    caja.append(boton('Copiar', 'fantasma', () => copiar(creado.token)));
    $('tokens').prepend(caja);
  } catch (error) {
    aviso(error.message);
  }
});

$('salir').addEventListener('click', async () => {
  await api('POST', '/api/logout');
  location.href = '/login';
});

async function arrancar() {
  try {
    const yo = await api('GET', '/api/me');
    $('quien').textContent = yo.email;
  } catch {
    location.href = '/login';
    return;
  }
  if (!(await cargarEntornos()).length) empezar();
}

arrancar();
