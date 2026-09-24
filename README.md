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
- Every value carries its own name inside its sealed box, so swapping two rows
  in the database is a decryption error and not a swapped secret.
- The audit log records who read what, who wrote it and who asked for a token.
  Never a value.

## The service

```
HEIMDALL_MASTER_KEY=$(openssl rand -hex 32)
HEIMDALL_ADMIN_TOKEN=$(openssl rand -hex 24)
HEIMDALL_DATA=/data
PORT=8080
```

`HEIMDALL_MASTER_KEY` is 32 bytes in hex. Change it and nothing opens again.

`HEIMDALL_ADMIN_TOKEN` is the way in before any token exists. Create a real
admin token with `--admin --ttl` and keep the environment one as the
break-glass key.

`heimdall` with no arguments serves; `heimdall serve` does the same.

## The web

`/` is the same store with a face: pick an environment, see the keys, reveal a
value, add or delete one, create a token and read the audit. It is one static
page and a little JavaScript over the same API, so there is nothing new to
learn and nothing new to trust.

You get in with a magic link. Only the addresses in `HEIMDALL_EMAILS` get one,
one per minute at most; the link lives fifteen minutes and works once.

The token travels in the URL fragment, which never reaches the server, so it
stays out of the logs. The session is an `HttpOnly`, `SameSite=Strict`,
`Secure` cookie for thirty days.

```
HEIMDALL_EMAILS=me@example.com,otro@example.com
HEIMDALL_URL=https://heimdall.example.com   # to build the link
RESEND_API_KEY=...                          # without it, the link goes to the log
HEIMDALL_FROM="Heimdall <heimdall@example.com>"
HEIMDALL_WEB_DEV=1                          # answers the link instead of mailing it
```

The page is `/`, the login is `/login`, and the link points at `/auth`, where a
handful of lines of JavaScript turn the fragment into a session.

## The client

```
export HEIMDALL_URL=https://heimdall.example.com
export HEIMDALL_TOKEN=<the admin token, or an agent one>

heimdall set STRIPE_KEY=sk_test_1 --project bifrost --env dev
heimdall ls --project bifrost --env dev
heimdall environments
heimdall token create --name agente --project bifrost --env dev --keys STRIPE_KEY --ttl 1h
heimdall token create --name jimmy --admin --ttl 24h
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
| `POST /v1/tokens` | admin | `{name,project,env,keys?,admin?,ttl?}`, returns the token once |
| `DELETE /v1/tokens?id=` | admin | revoke |
| `GET /v1/audit` | admin | `?limit=`, newest first |

Tokens go in `Authorization: Bearer <token>`. They expire only if you gave them a `ttl`, in seconds.

## Limits

- 64 connections at a time, each one giving up after 15 seconds. Past that the
  answer is a 503, not another thread.
- 16 KB of request header, 8 KB per line, 1 MB of body, 64 KB per value. A
  request that goes over is cut off instead of growing the process.
- The audit endpoint answers the newest 500 unless you pass another `limit`.

## What it does not do

Nobody gets into the service, but the container itself is only as tight as the
platform around it:

- The master key lives in the service's environment. Anyone who can read that
  container's environment opens every value; there is no KMS behind it.
- The process runs as an unprivileged user, with no shell and nothing to
  execute, but the volume is still the volume.
- There is no rate limiting beyond the login cooldown, and no lockout: with no
  passwords there is nothing to guess, and tokens are 192 bits.

## Development

```
make test   # unit, plus end-to-end against the built binary
make lint
make fmt
```
