const test = require("node:test");
const assert = require("node:assert");
const { segundos, describir, hace, falta, agrupar, esSlug, clavesDe, comoEnv, paresDeEnv, urlDeClaves, alcanceDeToken } = require("./util.js");

test("el vencimiento se escribe con su unidad", () => {
  assert.equal(segundos("30s"), 30);
  assert.equal(segundos("15m"), 900);
  assert.equal(segundos("2h"), 7200);
  assert.equal(segundos("7d"), 604800);
});

test("un vencimiento que no se entiende no es un número", () => {
  assert.equal(segundos("2"), null);
  assert.equal(segundos("h"), null);
  assert.equal(segundos("2w"), null);
  assert.equal(segundos(""), null);
  assert.equal(segundos("0h"), null);
  assert.equal(segundos("-2h"), null);
});

test("cada acción se cuenta en castellano con su tono", () => {
  assert.deepEqual(describir("set"), { texto: "guardó", clase: "escritura" });
  assert.deepEqual(describir("get-secrets"), { texto: "leyó", clase: "lectura" });
  assert.deepEqual(describir("project-drop"), { texto: "borró el proyecto", clase: "borrado" });
  assert.deepEqual(describir("vaya-uno-a-saber"), {
    texto: "vaya-uno-a-saber",
    clase: "lectura",
  });
});

test("el paso del tiempo se cuenta corto", () => {
  const ahora = 1_800_000_000;
  assert.equal(hace(ahora - 10, ahora), "recién");
  assert.equal(hace(ahora - 300, ahora), "hace 5 min");
  assert.equal(hace(ahora - 7200, ahora), "hace 2 h");
  assert.equal(hace(ahora - 3 * 86400, ahora), "hace 3 d");
});

test("el vencimiento se cuenta para adelante", () => {
  const ahora = 1_800_000_000;
  assert.equal(falta(ahora + 900, ahora), "vence en 15 min");
  assert.equal(falta(ahora + 7200, ahora), "vence en 2 h");
  assert.equal(falta(ahora + 2 * 86400, ahora), "vence en 2 d");
  assert.equal(falta(ahora - 1, ahora), "venció");
});

test("los entornos se agrupan por proyecto y salen ordenados", () => {
  assert.deepEqual(agrupar(["bifrost/prod", "bifrost/dev", "axe/dev"]), {
    bifrost: ["dev", "prod"],
    axe: ["dev"],
  });
  assert.deepEqual(agrupar([]), {});
});

test("el nombre de un proyecto o entorno es un slug", () => {
  assert.equal(esSlug("bifrost"), true);
  assert.equal(esSlug("mi-proyecto_2"), true);
  assert.equal(esSlug("Mi Proyecto"), false);
  assert.equal(esSlug("odín"), false);
  assert.equal(esSlug(""), false);
  assert.equal(esSlug("con/barras"), false);
  assert.equal(esSlug("a".repeat(65)), false);
});

test("las claves se separan por coma y se limpian", () => {
  assert.deepEqual(clavesDe(""), []);
  assert.deepEqual(clavesDe("A"), ["A"]);
  assert.deepEqual(clavesDe("A, B ,,C "), ["A", "B", "C"]);
});

test("el .env sale ordenado y con un renglón por clave", () => {
  const texto = comoEnv({ STRIPE_KEY: "sk_test", DB_URL: "postgres://x/y" });
  assert.equal(texto, "DB_URL=postgres://x/y\nSTRIPE_KEY=sk_test");
});

test("un valor con salto de línea no rompe el orden", () => {
  assert.equal(comoEnv({ B: "uno\ndos", A: "tres" }), "A=tres\nB=uno\ndos");
});

test("las claves van escapadas en la URL", () => {
  assert.equal(urlDeClaves("bifrost", "dev"), "/v1/secrets?project=bifrost&env=dev");
  assert.equal(urlDeClaves("con espacio", "a/b"), "/v1/secrets?project=con%20espacio&env=a%2Fb");
});

test("el alcance de un token dice qué toca", () => {
  assert.equal(alcanceDeToken({ project: "bifrost", env: "dev" }), "bifrost/dev");
  assert.equal(
    alcanceDeToken({ project: "bifrost", env: "dev", keys: ["A", "B"] }),
    "bifrost/dev · sólo A, B"
  );
  assert.equal(alcanceDeToken({ admin: true, project: "", env: "" }), "administra");
  assert.equal(alcanceDeToken({ admin: true, keys: ["A"] }), "administra · sólo A");
});

test("un .env se lee línea por línea, salteando vacías y comentarios", () => {
  const { pares, rotas } = paresDeEnv("A=1\n\n# un comentario\nB=dos\n");
  assert.deepEqual(pares, { A: "1", B: "dos" });
  assert.deepEqual(rotas, []);
});

test("las comillas y los escapes se sacan solos", () => {
  assert.deepEqual(paresDeEnv('A="dos palabras"').pares, { A: "dos palabras" });
  assert.deepEqual(paresDeEnv("A='crudo $x'").pares, { A: "crudo $x" });
  assert.deepEqual(paresDeEnv('A="linea\\nueva"').pares, { A: "linea\nueva" });
  assert.deepEqual(paresDeEnv("A=sin # comentario").pares, { A: "sin" });
});

test("el primer = parte la línea y lo que no se entiende se junta aparte", () => {
  const { pares, rotas } = paresDeEnv("URL=a=b\nlo que sea\n1MALA=x\n=suelta\n");
  assert.deepEqual(pares, { URL: "a=b" });
  assert.deepEqual(rotas, ["lo que sea", "1MALA=x", "=suelta"]);
});

test("un .env vacío no inventa nada", () => {
  const { pares, rotas } = paresDeEnv("");
  assert.deepEqual(pares, {});
  assert.deepEqual(rotas, []);
});
