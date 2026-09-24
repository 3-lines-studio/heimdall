/* Lo que se puede probar sin un navegador: cuentas, textos y URLs. */

function segundos(texto) {
  const unidades = { s: 1, m: 60, h: 3600, d: 86400 };
  const escrito = String(texto).trim();
  const numero = Number(escrito.slice(0, -1));
  const unidad = unidades[escrito.slice(-1)];
  if (!unidad || !Number.isFinite(numero) || numero <= 0) return null;
  return numero * unidad;
}

const ACCIONES = {
  set: ["guardó", "escritura"],
  unset: ["borró", "borrado"],
  "get-secrets": ["leyó", "lectura"],
  "get-keys": ["listó", "lectura"],
  "get-tokens": ["listó los tokens", "lectura"],
  "get-environments": ["listó los entornos", "lectura"],
  "token-create": ["creó un token", "estructura"],
  "token-revoke": ["revocó un token", "borrado"],
  "env-create": ["creó el entorno", "estructura"],
  "env-drop": ["borró el entorno", "borrado"],
  "env-rename": ["renombró el entorno", "estructura"],
  "project-drop": ["borró el proyecto", "borrado"],
  "project-rename": ["renombró el proyecto", "estructura"],
};

function describir(accion) {
  const [texto, clase] = ACCIONES[accion] || [accion, "lectura"];
  return { texto, clase };
}

function hace(cuando, ahora) {
  const segundos = ahora - cuando;
  if (segundos < 60) return "recién";
  if (segundos < 3600) return `hace ${Math.floor(segundos / 60)} min`;
  if (segundos < 86400) return `hace ${Math.floor(segundos / 3600)} h`;
  if (segundos < 604800) return `hace ${Math.floor(segundos / 86400)} d`;
  return new Date(cuando * 1000).toLocaleDateString();
}

function falta(cuando, ahora) {
  const segundos = cuando - ahora;
  if (segundos <= 0) return "venció";
  if (segundos < 3600) return `vence en ${Math.max(1, Math.floor(segundos / 60))} min`;
  if (segundos < 86400) return `vence en ${Math.floor(segundos / 3600)} h`;
  return `vence en ${Math.floor(segundos / 86400)} d`;
}

function agrupar(nombres) {
  const proyectos = {};
  for (const nombre of nombres) {
    const [project, env] = nombre.split("/");
    if (!proyectos[project]) proyectos[project] = [];
    proyectos[project].push(env);
  }
  for (const entornos of Object.values(proyectos)) entornos.sort();
  return proyectos;
}

function esSlug(texto) {
  return /^[a-z0-9_-]{1,64}$/.test(texto);
}

function clavesDe(texto) {
  return String(texto)
    .split(",")
    .map((clave) => clave.trim())
    .filter(Boolean);
}

function comoEnv(secretos) {
  return Object.keys(secretos)
    .sort()
    .map((clave) => `${clave}=${secretos[clave]}`)
    .join("\n");
}

function urlDeClaves(project, env) {
  return `/v1/secrets?project=${encodeURIComponent(project)}&env=${encodeURIComponent(env)}`;
}

function alcanceDeToken(token) {
  const partes = [token.admin ? "administra" : `${token.project}/${token.env}`];
  if (token.keys && token.keys.length) partes.push(`sólo ${token.keys.join(", ")}`);
  return partes.join(" · ");
}

if (typeof module !== "undefined") {
  module.exports = { segundos, describir, hace, falta, agrupar, esSlug, clavesDe, comoEnv, urlDeClaves, alcanceDeToken };
}
