const test = require("node:test");
const assert = require("node:assert");
const { segundos, agrupar, esSlug, clavesDe, comoEnv, urlDeClaves, alcanceDeToken } = require("./util.js");

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
