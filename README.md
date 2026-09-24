# Heimdall

A small secrets service: projects, environments, and tokens scoped to one
environment and, if you want, to a list of key names. The point is handing an
agent test credentials with no path to production.

Nobody gets into the service. The only way to a secret is the API, with a token.

## How it works

- One SQLite file in the volume, in WAL. Each value is sealed on its own with
  XChaCha20-Poly1305, and the key is derived with blake3 from
  `HEIMDALL_MASTER_KEY` plus that environment's context, so one environment
  never opens another. Project names, key names, tokens and audit rows stay
  readable: a dump of the volume gives up no secret, but it does show which
  services exist.
- Tokens are stored hashed, with their scope. A token for `bifrost/dev` cannot
  read `bifrost/prod`: no request returns it, and asking for it is a 403.
- The audit log records who touched what, never a value.

## The service

```
HEIMDALL_MASTER_KEY=$(openssl rand -hex 32)
HEIMDALL_ADMIN_TOKEN=$(openssl rand -hex 24)
HEIMDALL_DATA=/data
PORT=8080
```

`HEIMDALL_MASTER_KEY` is 32 bytes in hex. Change it and nothing opens again.

`heimdall` with no arguments serves; `heimdall serve` does the same.

## The client

```
export HEIMDALL_URL=https://heimdall.example.com
export HEIMDALL_TOKEN=<the admin token, or an agent one>

heimdall set STRIPE_KEY=sk_test_1 --project bifrost --env dev
heimdall ls --project bifrost --env dev
heimdall environments
heimdall token create --name agente --project bifrost --env dev --keys STRIPE_KEY
heimdall token list
heimdall token revoke --id 3f9c1a
heimdall audit
heimdall run --project bifrost --env dev -- npm test
```

`run` puts whatever the token sees into the command's environment and takes
`HEIMDALL_TOKEN` out of it, so the child cannot read the store on its own.

## The API

| Route | Who | What |
|---|---|---|
| `GET /v1/health` | anyone | is it up |
| `GET /v1/secrets?project=&env=` | admin, or a token of that environment | the values it sees |
| `GET /v1/keys?project=&env=` | same | their names |
| `PUT /v1/secrets` | admin | `{project,env,key,value}` |
| `DELETE /v1/secrets` | admin | `{project,env,key}` |
| `GET /v1/environments` | admin | every `project/env` that exists |
| `GET /v1/tokens` | admin | the tokens, without their secrets |
| `POST /v1/tokens` | admin | `{name,project,env,keys?}`, returns the token once |
| `DELETE /v1/tokens?id=` | admin | revoke |
| `GET /v1/audit` | admin | the log |

Tokens go in `Authorization: Bearer <token>`.

## Development

```
make test   # unit, plus end-to-end against the built binary
make lint
make fmt
```
