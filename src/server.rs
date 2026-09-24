use crate::crypto;
use crate::http::{self, Request};
use crate::mail::Mail;
use crate::store::{self, Error, NewToken, Store, Token};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const COOKIE: &str = "heimdall_session";

const MAX_LIVE: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(15);
const AUDIT_LIMIT: usize = 500;

type Reply = Result<Value, (u16, String)>;

pub struct Server {
    pub store: Mutex<Store>,
    pub admin: String,
    pub emails: Vec<String>,
    pub mail: Option<Mail>,
    pub link_base: String,
    pub dev: bool,
}

enum Actor {
    Admin(String),
    Token(Box<Token>),
}

impl Actor {
    fn label(&self) -> &str {
        match self {
            Actor::Admin(name) => name,
            Actor::Token(token) => &token.name,
        }
    }
}

pub fn listen(port: u16) -> std::result::Result<TcpListener, String> {
    TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("no pude escuchar en {port}: {e}"))
}

static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Slot;

impl Slot {
    fn take() -> Option<Slot> {
        if LIVE.fetch_add(1, Ordering::SeqCst) >= MAX_LIVE {
            LIVE.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn serve(server: Arc<Server>, listener: TcpListener) {
    for mut stream in listener.incoming().flatten() {
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        let Some(slot) = Slot::take() else {
            let _ = http::send_error(&mut stream, 503, "estoy lleno, probá en un rato");
            continue;
        };
        let server = server.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            if let Err(e) = handle(&server, &mut stream) {
                eprintln!("heimdall: {e}");
            }
        });
    }
}

fn handle(server: &Arc<Server>, stream: &mut TcpStream) -> std::io::Result<()> {
    let Some(request) = http::read(stream)? else {
        return Ok(());
    };
    if request.too_large {
        return http::send_error(stream, 413, "eso es demasiado grande");
    }
    if !request.path.starts_with("/v1/") {
        return crate::web::handle(server, &request, stream);
    }
    let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
    match route(server, &store, &request) {
        Ok(value) => http::send_json(stream, 200, &value),
        Err((status, message)) => http::send_error(stream, status, &message),
    }
}

fn route(server: &Arc<Server>, store: &Store, request: &Request) -> Reply {
    if request.path == "/v1/health" {
        return Ok(json!({ "ok": true }));
    }
    let actor = authenticate(server, store, request)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/secrets") => read_secrets(store, &actor, request),
        ("GET", "/v1/keys") => read_keys(store, &actor, request),
        ("PUT", "/v1/secrets") => write_secret(store, &actor, request),
        ("DELETE", "/v1/secrets") => delete_secret(store, &actor, request),
        ("POST", "/v1/environments") => create_environment(store, &actor, request),
        ("DELETE", "/v1/environments") => drop_environment(store, &actor, request),
        ("DELETE", "/v1/projects") => drop_project(store, &actor, request),
        ("POST", "/v1/rename-environment") => rename_environment(store, &actor, request),
        ("POST", "/v1/rename-project") => rename_project(store, &actor, request),
        ("GET", "/v1/environments") => {
            admin(&actor)?;
            let names = reply(store.names())?;
            reply(store.audit(actor.label(), "get-environments", "", "", None))?;
            Ok(json!(names))
        }
        ("GET", "/v1/tokens") => {
            admin(&actor)?;
            let tokens = reply(store.tokens())?;
            reply(store.audit(actor.label(), "get-tokens", "", "", None))?;
            Ok(json!(tokens))
        }
        ("POST", "/v1/tokens") => create_token(store, &actor, request),
        ("DELETE", "/v1/tokens") => revoke_token(store, &actor, request),
        ("GET", "/v1/audit") => {
            admin(&actor)?;
            let limit = request
                .param("limit")
                .and_then(|limit| limit.parse().ok())
                .unwrap_or(AUDIT_LIMIT);
            Ok(json!(reply(store.audit_log(limit))?))
        }
        _ => Err((404, "no está".to_string())),
    }
}

fn authenticate(
    server: &Arc<Server>,
    store: &Store,
    request: &Request,
) -> std::result::Result<Actor, (u16, String)> {
    if let Some(cookie) = request.cookie(COOKIE) {
        match store.session(&cookie) {
            Ok(Some(email)) => return Ok(Actor::Admin(email)),
            Ok(None) => {}
            Err(error) => return Err(internal(error)),
        }
    }
    let Some(presented) = request.bearer() else {
        return Err((401, "falta el token".to_string()));
    };
    if crypto::equal(presented, &server.admin) {
        return Ok(Actor::Admin("admin".to_string()));
    }
    let token = match store.find(presented) {
        Ok(Some(token)) => token,
        Ok(None) => return Err((401, "ese token no sirve".to_string())),
        Err(Error::Bad(message)) => return Err((401, message)),
        Err(error) => return Err(internal(error)),
    };
    let _ = store.touch(&token.id);
    if token.admin {
        return Ok(Actor::Admin(token.name.clone()));
    }
    Ok(Actor::Token(Box::new(token)))
}

fn reply<T>(result: store::Result<T>) -> std::result::Result<T, (u16, String)> {
    result.map_err(|error| match error {
        Error::Bad(message) => (400, message),
        Error::Internal(message) => internal(Error::Internal(message)),
    })
}

fn internal(error: Error) -> (u16, String) {
    let Error::Internal(message) = error else {
        return (500, "algo se rompió acá adentro".to_string());
    };
    eprintln!("heimdall: {message}");
    (500, "algo se rompió acá adentro".to_string())
}

fn admin(actor: &Actor) -> std::result::Result<(), (u16, String)> {
    match actor {
        Actor::Admin(_) => Ok(()),
        Actor::Token(_) => Err((403, "este token no administra".to_string())),
    }
}

fn scoped(actor: &Actor, project: &str, env: &str) -> std::result::Result<(), (u16, String)> {
    match actor {
        Actor::Admin(_) => Ok(()),
        Actor::Token(token) if token.project == project && token.env == env => Ok(()),
        Actor::Token(_) => Err((403, "este token no llega a ese entorno".to_string())),
    }
}

fn visible(actor: &Actor, map: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let Actor::Token(token) = actor else {
        return map;
    };
    let Some(keys) = &token.keys else {
        return map;
    };
    map.into_iter()
        .filter(|(name, _)| keys.contains(name))
        .collect()
}

fn scoped_request(
    request: &Request,
    actor: &Actor,
) -> std::result::Result<(String, String), (u16, String)> {
    let project = request.param("project").unwrap_or_default().to_string();
    let env = request.param("env").unwrap_or_default().to_string();
    if project.is_empty() || env.is_empty() {
        return Err((400, "faltan project y env".to_string()));
    }
    scoped(actor, &project, &env)?;
    Ok((project, env))
}

fn read_secrets(store: &Store, actor: &Actor, request: &Request) -> Reply {
    let (project, env) = scoped_request(request, actor)?;
    if let Actor::Token(token) = actor {
        if let (Some(keys), Some(wanted)) = (&token.keys, request.param("key")) {
            if !keys.contains(&wanted.to_string()) {
                return Err((403, format!("este token no ve {wanted}")));
            }
        }
    }
    let map = reply(store.secrets(&project, &env))?;
    let filtered = visible(actor, map);
    reply(store.audit(actor.label(), "get-secrets", &project, &env, None))?;
    Ok(json!(filtered))
}

fn read_keys(store: &Store, actor: &Actor, request: &Request) -> Reply {
    let (project, env) = scoped_request(request, actor)?;
    let map = reply(store.secrets(&project, &env))?;
    let names: Vec<String> = visible(actor, map).into_keys().collect();
    reply(store.audit(actor.label(), "get-keys", &project, &env, None))?;
    Ok(json!(names))
}

fn write_secret(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let name = request.field("key").unwrap_or_default();
    let value = request.field("value").unwrap_or_default();
    reply(store.set(&project, &env, &name, &value, actor.label()))?;
    Ok(json!({ "ok": true }))
}

fn delete_secret(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let name = request.field("key").unwrap_or_default();
    reply(store.unset(&project, &env, &name, actor.label()))?;
    Ok(json!({ "ok": true }))
}

fn create_environment(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    reply(store.create_environment(&project, &env, actor.label()))?;
    Ok(json!({ "ok": true }))
}

fn drop_environment(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    reply(store.drop_environment(&project, &env, actor.label()))?;
    Ok(json!({ "ok": true }))
}

fn drop_project(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    reply(store.drop_project(&project, actor.label()))?;
    Ok(json!({ "ok": true }))
}

fn rename_environment(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let to = request.field("to").unwrap_or_default();
    reply(store.rename_environment(&project, &env, &to, actor.label()))?;
    Ok(json!({ "ok": true, "env": to }))
}

fn rename_project(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let to = request.field("to").unwrap_or_default();
    reply(store.rename_project(&project, &to, actor.label()))?;
    Ok(json!({ "ok": true, "project": to }))
}

fn create_token(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let new = NewToken {
        name: request.field("name").unwrap_or_default(),
        project: request.field("project").unwrap_or_default(),
        env: request.field("env").unwrap_or_default(),
        keys: request.list("keys"),
        admin: request.flag("admin"),
        ttl: request.number("ttl"),
    };
    let (token, plain) = reply(store.create_token(new, actor.label()))?;
    Ok(json!({
        "id": token.id,
        "name": token.name,
        "project": token.project,
        "env": token.env,
        "keys": token.keys,
        "admin": token.admin,
        "expires_at": token.expires_at,
        "token": plain,
    }))
}

fn revoke_token(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let id = request
        .field("id")
        .or_else(|| request.param("id").map(str::to_string))
        .unwrap_or_default();
    let token = reply(store.revoke(&id, actor.label()))?;
    Ok(json!({ "id": token.id, "name": token.name }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;
    use crate::store::temp_root;
    use std::collections::HashMap;

    fn server() -> Arc<Server> {
        let store = Store::open(temp_root(), Key::from_hex(&"ab".repeat(32)).unwrap()).unwrap();
        Arc::new(Server {
            store: Mutex::new(store),
            admin: "hd_admin".to_string(),
            emails: vec!["berti@ejemplo.com".to_string()],
            mail: None,
            link_base: "http://localhost:8080".to_string(),
            dev: true,
        })
    }

    fn request(method: &str, path: &str, token: &str, body: Value) -> Request {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: http::parse_pairs(query),
            headers: HashMap::from([("authorization".to_string(), format!("Bearer {token}"))]),
            body: serde_json::to_vec(&body).unwrap_or_default(),
            too_large: false,
        }
    }

    fn agent(store: &Store, keys: Option<Vec<String>>, ttl: Option<i64>) -> String {
        let new = NewToken {
            name: "agente".to_string(),
            project: "bifrost".to_string(),
            env: "dev".to_string(),
            keys,
            admin: false,
            ttl,
        };
        store.create_token(new, "berti").unwrap().1
    }

    #[test]
    fn a_request_without_a_token_is_rejected() {
        let server = server();
        let store = server.store.lock().unwrap();
        let mut bare = request("GET", "/v1/secrets", "", json!({}));
        bare.headers.clear();
        assert_eq!(route(&server, &store, &bare).unwrap_err().0, 401);
    }

    #[test]
    fn the_admin_writes_and_a_token_reads() {
        let server = server();
        let store = server.store.lock().unwrap();
        let write = json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" });
        route(
            &server,
            &store,
            &request("PUT", "/v1/secrets", "hd_admin", write),
        )
        .unwrap();
        let plain = agent(&store, None, None);
        let read = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=dev",
                &plain,
                json!({}),
            ),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
    }

    #[test]
    fn a_token_does_not_reach_another_environment() {
        let server = server();
        let store = server.store.lock().unwrap();
        store.set("bifrost", "prod", "A", "1", "berti").unwrap();
        let plain = agent(&store, None, None);
        let error = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=prod",
                &plain,
                json!({}),
            ),
        )
        .unwrap_err();
        assert_eq!(error.0, 403);
    }

    #[test]
    fn a_token_with_keys_only_sees_those() {
        let server = server();
        let store = server.store.lock().unwrap();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "dev", "B", "2", "berti").unwrap();
        let plain = agent(&store, Some(vec!["A".to_string()]), None);
        let read = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=dev",
                &plain,
                json!({}),
            ),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
        assert!(read["B"].is_null());
        let keys = route(
            &server,
            &store,
            &request("GET", "/v1/keys?project=bifrost&env=dev", &plain, json!({})),
        )
        .unwrap();
        assert_eq!(keys.as_array().unwrap().len(), 1);
        let denied = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=dev&key=B",
                &plain,
                json!({}),
            ),
        )
        .unwrap_err();
        assert_eq!(denied.0, 403);
    }

    #[test]
    fn a_token_cannot_write_or_administrate() {
        let server = server();
        let store = server.store.lock().unwrap();
        let plain = agent(&store, None, None);
        let write = json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" });
        assert_eq!(
            route(
                &server,
                &store,
                &request("PUT", "/v1/secrets", &plain, write)
            )
            .unwrap_err()
            .0,
            403
        );
        assert_eq!(
            route(
                &server,
                &store,
                &request("GET", "/v1/tokens", &plain, json!({}))
            )
            .unwrap_err()
            .0,
            403
        );
    }

    #[test]
    fn an_admin_token_administrates() {
        let server = server();
        let store = server.store.lock().unwrap();
        let new = NewToken {
            name: "jimmy".to_string(),
            project: String::new(),
            env: String::new(),
            keys: None,
            admin: true,
            ttl: None,
        };
        let (_, plain) = store.create_token(new, "berti").unwrap();
        let write = json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" });
        assert_eq!(
            route(
                &server,
                &store,
                &request("PUT", "/v1/secrets", &plain, write)
            )
            .unwrap()["ok"],
            true
        );
        let read = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=dev",
                &plain,
                json!({}),
            ),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
    }

    #[test]
    fn an_expired_token_is_a_401() {
        let server = server();
        let store = server.store.lock().unwrap();
        let plain = agent(&store, None, Some(-1));
        assert_eq!(
            route(
                &server,
                &store,
                &request(
                    "GET",
                    "/v1/secrets?project=bifrost&env=dev",
                    &plain,
                    json!({})
                )
            )
            .unwrap_err()
            .0,
            401
        );
    }

    #[test]
    fn the_structure_is_created_and_dropped_from_the_api() {
        let server = server();
        let store = server.store.lock().unwrap();
        let body = json!({ "project": "bifrost", "env": "dev" });
        route(
            &server,
            &store,
            &request("POST", "/v1/environments", "hd_admin", body.clone()),
        )
        .unwrap();
        assert_eq!(
            route(
                &server,
                &store,
                &request("GET", "/v1/environments", "hd_admin", json!({}))
            )
            .unwrap(),
            json!(["bifrost/dev"])
        );

        route(
            &server,
            &store,
            &request(
                "PUT",
                "/v1/secrets",
                "hd_admin",
                json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" }),
            ),
        )
        .unwrap();
        route(
            &server,
            &store,
            &request("DELETE", "/v1/environments", "hd_admin", body),
        )
        .unwrap();
        assert_eq!(
            route(
                &server,
                &store,
                &request("GET", "/v1/environments", "hd_admin", json!({}))
            )
            .unwrap(),
            json!([])
        );
        assert_eq!(
            route(
                &server,
                &store,
                &request(
                    "GET",
                    "/v1/secrets?project=bifrost&env=dev",
                    "hd_admin",
                    json!({})
                )
            )
            .unwrap(),
            json!({})
        );
    }

    #[test]
    fn renaming_from_the_api_keeps_the_values() {
        let server = server();
        let store = server.store.lock().unwrap();
        route(
            &server,
            &store,
            &request(
                "PUT",
                "/v1/secrets",
                "hd_admin",
                json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" }),
            ),
        )
        .unwrap();
        let renamed = json!({ "project": "bifrost", "env": "dev", "to": "testing" });
        assert_eq!(
            route(
                &server,
                &store,
                &request("POST", "/v1/rename-environment", "hd_admin", renamed)
            )
            .unwrap()["env"],
            "testing"
        );
        let read = route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=testing",
                "hd_admin",
                json!({}),
            ),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
    }

    #[test]
    fn only_an_admin_touches_the_structure() {
        let server = server();
        let store = server.store.lock().unwrap();
        let plain = agent(&store, None, None);
        let body = json!({ "project": "bifrost", "env": "dev" });
        assert_eq!(
            route(
                &server,
                &store,
                &request("POST", "/v1/environments", &plain, body)
            )
            .unwrap_err()
            .0,
            403
        );
        assert_eq!(
            route(
                &server,
                &store,
                &request(
                    "DELETE",
                    "/v1/projects",
                    &plain,
                    json!({ "project": "bifrost" })
                )
            )
            .unwrap_err()
            .0,
            403
        );
    }

    #[test]
    fn every_read_leaves_a_trail() {
        let server = server();
        let store = server.store.lock().unwrap();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        let plain = agent(&store, None, None);
        route(
            &server,
            &store,
            &request(
                "GET",
                "/v1/secrets?project=bifrost&env=dev",
                &plain,
                json!({}),
            ),
        )
        .unwrap();
        route(
            &server,
            &store,
            &request("GET", "/v1/keys?project=bifrost&env=dev", &plain, json!({})),
        )
        .unwrap();
        let log = store.audit_log(10).unwrap();
        let reads: Vec<&str> = log
            .iter()
            .map(|entry| entry["action"].as_str().unwrap())
            .filter(|action| action.starts_with("get-"))
            .collect();
        assert_eq!(reads, vec!["get-keys", "get-secrets"]);
        assert!(log
            .iter()
            .all(|entry| entry["actor"] == "agente" || entry["actor"] == "berti"));
    }
}
