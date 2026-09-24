/* Lo que se puede probar sin un navegador: cuentas, textos y URLs. */

function segundos(texto) {
  const unidades = { s: 1, m: 60, h: 3600, d: 86400 };
  const escrito = String(texto).trim();
  const numero = Number(escrito.slice(0, -1));
  const unidad = unidades[escrito.slice(-1)];
  if (!unidad || !Number.isFinite(numero) || numero <= 0) return null;
  return numero * unidad;
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
  module.exports = { segundos, clavesDe, comoEnv, urlDeClaves, alcanceDeToken };
}
