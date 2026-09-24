const estado = {
  project: null,
  env: null,
  secretos: {},
  proyectos: {},
  abiertos: new Set(leer('abiertos', [])),
  revelados: new Set(),
  editando: null,
};

const $ = (id) => document.getElementById(id);

function leer(clave, porDefecto) {
  try {
    return JSON.parse(localStorage.getItem(clave)) ?? porDefecto;
  } catch {
    return porDefecto;
  }
}

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

function boton(texto, clase, accion, titulo) {
  const elemento = nodo('button', texto, clase);
  elemento.type = 'button';
  if (titulo) elemento.title = titulo;
  elemento.addEventListener('click', accion);
  return elemento;
}

let avisoTimer = null;
function aviso(texto) {
  const caja = $('aviso');
  caja.textContent = texto;
  caja.hidden = false;
  clearTimeout(avisoTimer);
  avisoTimer = setTimeout(() => {
    caja.hidden = true;
  }, 3000);
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

function guardarAbiertos() {
  localStorage.setItem('abiertos', JSON.stringify([...estado.abiertos]));
}

async function cargar() {
  estado.proyectos = agrupar(await api('GET', '/v1/environments'));
  const nombres = Object.keys(estado.proyectos);
  if (!estado.abiertos.size) nombres.forEach((proyecto) => estado.abiertos.add(proyecto));
  if (estado.project && !estado.proyectos[estado.project]?.includes(estado.env)) soltar();
  render();
}

function soltar() {
  estado.project = null;
  estado.env = null;
  estado.secretos = {};
  estado.revelados.clear();
}

function render() {
  renderArbol();
  renderPanel();
}

function renderArbol() {
  const nav = $('proyectos');
  nav.replaceChildren();
  const nombres = Object.keys(estado.proyectos).sort();
  if (!nombres.length && estado.editando?.tipo !== 'proyecto') {
    nav.append(nodo('p', 'Todavía no hay proyectos.', 'tenue'));
  }
  for (const proyecto of nombres) nav.append(bloqueProyecto(proyecto));
  if (estado.editando?.tipo === 'proyecto') nav.append(bloqueNuevoProyecto());
}

function editar(tipo, project, env) {
  estado.editando = { tipo, project, env };
  render();
}

function bloqueProyecto(proyecto) {
  const caja = nodo('div', null, 'proyecto');
  const fila = nodo('div', null, 'titulo');
  const abierto = estado.abiertos.has(proyecto);
  const renombrando = estado.editando?.tipo === 'renombrar-proyecto' && estado.editando.project === proyecto;

  fila.append(
    boton(abierto ? '▾' : '▸', 'plegar', () => {
      if (abierto) estado.abiertos.delete(proyecto);
      else estado.abiertos.add(proyecto);
      guardarAbiertos();
      render();
    })
  );

  if (renombrando) {
    fila.append(campo(proyecto, (nombre) => renombrarProyecto(proyecto, nombre)));
  } else {
    fila.append(nodo('span', proyecto, 'nombre'));
    fila.append(
      boton('+', 'chico', () => editar('entorno', proyecto), 'entorno nuevo'),
      boton('✎', 'chico', () => editar('renombrar-proyecto', proyecto), 'renombrar'),
      boton('✕', 'chico peligro', () => borrarProyecto(proyecto), 'borrar')
    );
  }
  caja.append(fila);

  if (!abierto) return caja;

  const lista = nodo('div', null, 'entornos');
  for (const env of estado.proyectos[proyecto]) {
    const renombrandoEste =
      estado.editando?.tipo === 'renombrar-entorno' &&
      estado.editando.project === proyecto &&
      estado.editando.env === env;
    if (renombrandoEste) {
      const fila = nodo('div', null, 'fila-entorno');
      fila.append(campo(env, (nombre) => renombrarEntorno(proyecto, env, nombre)));
      lista.append(fila);
      continue;
    }
    const activo = proyecto === estado.project && env === estado.env;
    lista.append(boton(env, activo ? 'entorno activo' : 'entorno', () => abrir(proyecto, env)));
  }
  if (estado.editando?.tipo === 'entorno' && estado.editando.project === proyecto) {
    const fila = nodo('div', null, 'fila-entorno');
    fila.append(campo('', (nombre) => crearEntorno(proyecto, nombre)));
    lista.append(fila);
  }
  caja.append(lista);
  return caja;
}

function bloqueNuevoProyecto() {
  const caja = nodo('div', null, 'proyecto nuevo');
  const proyecto = nodo('input', null, 'chico');
  proyecto.placeholder = 'proyecto';
  const entorno = nodo('input', null, 'chico');
  entorno.placeholder = 'entorno';

  const listo = async () => {
    const nombre = proyecto.value.trim();
    const env = entorno.value.trim();
    if (!nombre || !env) return;
    if (!esSlug(nombre) || !esSlug(env)) {
      aviso('El proyecto y el entorno van en minúsculas, sin espacios ni tildes.');
      return;
    }
    try {
      await api('POST', '/v1/environments', { project: nombre, env });
      estado.editando = null;
      estado.abiertos.add(nombre);
      guardarAbiertos();
      await cargar();
      await abrir(nombre, env);
    } catch (error) {
      aviso(error.message);
    }
  };

  for (const input of [proyecto, entorno]) {
    input.addEventListener('keydown', (evento) => {
      if (evento.key === 'Enter') {
        evento.preventDefault();
        listo();
      }
      if (evento.key === 'Escape') {
        estado.editando = null;
        render();
      }
    });
  }

  const fila = nodo('div', null, 'titulo');
  fila.append(proyecto, entorno, boton('✓', 'chico', listo));
  caja.append(fila);
  setTimeout(() => proyecto.focus(), 0);
  return caja;
}

function campo(valor, guardar) {
  const input = nodo('input', null, 'chico');
  input.value = valor;
  const listo = () => {
    const texto = input.value.trim();
    if (!texto) return;
    if (!esSlug(texto)) {
      aviso('El nombre va en minúsculas, sin espacios ni tildes.');
      return;
    }
    guardar(texto);
  };
  input.addEventListener('keydown', (evento) => {
    if (evento.key === 'Enter') {
      evento.preventDefault();
      listo();
    }
    if (evento.key === 'Escape') {
      estado.editando = null;
      render();
    }
  });
  setTimeout(() => input.focus(), 0);
  return input;
}

async function crearEntorno(proyecto, env) {
  try {
    await api('POST', '/v1/environments', { project: proyecto, env });
    estado.editando = null;
    await cargar();
    await abrir(proyecto, env);
  } catch (error) {
    aviso(error.message);
  }
}

async function renombrarEntorno(proyecto, env, nuevo) {
  try {
    await api('POST', '/v1/rename-environment', { project: proyecto, env, to: nuevo });
    estado.editando = null;
    if (estado.project === proyecto && estado.env === env) estado.env = nuevo;
    await cargar();
    render();
  } catch (error) {
    aviso(error.message);
  }
}

async function renombrarProyecto(proyecto, nuevo) {
  try {
    await api('POST', '/v1/rename-project', { project: proyecto, to: nuevo });
    estado.editando = null;
    estado.abiertos.delete(proyecto);
    estado.abiertos.add(nuevo);
    guardarAbiertos();
    if (estado.project === proyecto) estado.project = nuevo;
    await cargar();
    render();
  } catch (error) {
    aviso(error.message);
  }
}

async function borrarEntorno(proyecto, env) {
  const cuantos = Object.keys(estado.secretos).length;
  const bien = await confirmar(
    `Vas a borrar ${proyecto}/${env}${cuantos ? ` y sus ${cuantos} secretos` : ''}. No se puede deshacer.`
  );
  if (!bien) return;
  try {
    await api('DELETE', '/v1/environments', { project: proyecto, env });
    if (estado.project === proyecto && estado.env === env) soltar();
    await cargar();
    aviso(`${proyecto}/${env} borrado.`);
  } catch (error) {
    aviso(error.message);
  }
}

async function borrarProyecto(proyecto) {
  const entornos = estado.proyectos[proyecto].length;
  const bien = await confirmar(
    `Vas a borrar ${proyecto} con sus ${entornos} ${entornos === 1 ? 'entorno' : 'entornos'}, todos sus secretos y sus tokens. No se puede deshacer.`,
    proyecto
  );
  if (!bien) return;
  try {
    await api('DELETE', '/v1/projects', { project: proyecto });
    estado.abiertos.delete(proyecto);
    guardarAbiertos();
    if (estado.project === proyecto) soltar();
    await cargar();
    aviso(`${proyecto} borrado.`);
  } catch (error) {
    aviso(error.message);
  }
}

function confirmar(texto, esperado) {
  return new Promise((resolve) => {
    const dialogo = $('confirmar');
    const campo = $('confirmar-nombre');
    const etiqueta = $('confirmar-etiqueta');
    $('confirmar-texto').textContent = texto;
    campo.hidden = !esperado;
    etiqueta.hidden = !esperado;
    campo.value = '';
    campo.placeholder = esperado || '';

    let respuesta = false;
    $('confirmar-si').onclick = () => {
      if (esperado && campo.value.trim() !== esperado) {
        aviso('El nombre no coincide.');
        return;
      }
      respuesta = true;
      dialogo.close();
    };
    $('confirmar-no').onclick = () => {
      respuesta = false;
      dialogo.close();
    };
    dialogo.addEventListener('close', () => resolve(respuesta), { once: true });
    dialogo.showModal();
    if (esperado) setTimeout(() => campo.focus(), 0);
  });
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
  render();
  await cargarTokens();
  await cargarAuditoria();
}

function renderPanel() {
  const elegido = estado.project && estado.env;
  $('vacio').hidden = Boolean(elegido);
  $('contenido').hidden = !elegido;
  if (!elegido) {
    $('vacio').textContent = Object.keys(estado.proyectos).length
      ? 'Elegí un entorno.'
      : 'Todavía no hay nada: creá un proyecto.';
    return;
  }
  $('titulo').textContent = `${estado.project} / ${estado.env}`;
  renderSecretos();
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
    acciones.append(
      boton(revelado ? 'Ocultar' : 'Ver', 'fantasma', () => {
        if (revelado) estado.revelados.delete(clave);
        else estado.revelados.add(clave);
        renderSecretos();
      }),
      boton('Copiar', 'fantasma', () => copiar(valor)),
      boton('Borrar', 'peligro', async () => {
        const bien = await confirmar(`Vas a borrar ${clave} de ${estado.project}/${estado.env}.`);
        if (!bien) return;
        try {
          await api('DELETE', '/v1/secrets', { project: estado.project, env: estado.env, key: clave });
          delete estado.secretos[clave];
          renderSecretos();
          aviso(`${clave} borrada.`);
        } catch (error) {
          aviso(error.message);
        }
      })
    );
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
    fila.append(
      boton('Revocar', 'peligro', async () => {
        const bien = await confirmar(`Vas a revocar el token ${token.name}.`);
        if (!bien) return;
        try {
          await api('DELETE', `/v1/tokens?id=${encodeURIComponent(token.id)}`);
          await cargarTokens();
          aviso(`${token.name} revocado.`);
        } catch (error) {
          aviso(error.message);
        }
      })
    );
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

$('nuevo-proyecto').addEventListener('click', () => editar('proyecto', null, null));

$('renombrar-entorno').addEventListener('click', () => editar('renombrar-entorno', estado.project, estado.env));

$('borrar-entorno').addEventListener('click', () => borrarEntorno(estado.project, estado.env));

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
    const caja = nodo('div', null, 'nuevo');
    caja.append(nodo('div', 'Este token no se vuelve a mostrar:'));
    caja.append(nodo('code', creado.token));
    caja.append(boton('Copiar', 'fantasma', () => copiar(creado.token)));
    $('tokens').prepend(caja);
    aviso('Guardalo ahora, no se vuelve a mostrar.');
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
  await cargar();
}

arrancar();
