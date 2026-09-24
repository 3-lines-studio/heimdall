use crate::crypto;
use crate::http::{self, Request};
use crate::store::{Store, Token};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

type Reply = Result<Value, (u16, String)>;

pub struct Server {
    pub store: Mutex<Store>,
    pub admin: String,
}

enum Actor {
    Admin,
    Token(Box<Token>),
}

impl Actor {
    fn label(&self) -> &str {
        match self {
            Actor::Admin => "admin",
            Actor::Token(token) => &token.name,
        }
    }
}

pub fn listen(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("no pude escuchar en {port}: {e}"))
}

pub fn serve(server: Arc<Server>, listener: TcpListener) {
    for stream in listener.incoming().flatten() {
        let server = server.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
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
        ("GET", "/v1/environments") => {
            admin(&actor)?;
            Ok(json!(store.names().map_err(bad_request)?))
        }
        ("GET", "/v1/tokens") => {
            admin(&actor)?;
            let tokens = store.tokens().map_err(bad_request)?;
            Ok(json!(tokens))
        }
        ("POST", "/v1/tokens") => create_token(store, &actor, request),
        ("DELETE", "/v1/tokens") => revoke_token(store, &actor, request),
        ("GET", "/v1/audit") => {
            admin(&actor)?;
            Ok(json!(store.audit_log().map_err(bad_request)?))
        }
        _ => Err((404, "no está".to_string())),
    }
}

fn authenticate(
    server: &Arc<Server>,
    store: &Store,
    request: &Request,
) -> Result<Actor, (u16, String)> {
    let Some(presented) = request.bearer() else {
        return Err((401, "falta el token".to_string()));
    };
    if crypto::equal(presented, &server.admin) {
        return Ok(Actor::Admin);
    }
    let found = store.find(presented).map_err(bad_request)?;
    let Some(token) = found else {
        return Err((401, "ese token no sirve".to_string()));
    };
    let _ = store.touch(&token.id);
    Ok(Actor::Token(Box::new(token)))
}

fn admin(actor: &Actor) -> Result<(), (u16, String)> {
    match actor {
        Actor::Admin => Ok(()),
        Actor::Token(_) => Err((403, "este token no administra".to_string())),
    }
}

fn scoped(actor: &Actor, project: &str, env: &str) -> Result<(), (u16, String)> {
    match actor {
        Actor::Admin => Ok(()),
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

fn scoped_request(request: &Request, actor: &Actor) -> Result<(String, String), (u16, String)> {
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
    let map = store.secrets(&project, &env).map_err(bad_request)?;
    let filtered = visible(actor, map);
    if let Actor::Token(token) = actor {
        if let Some(keys) = &token.keys {
            if let Some(wanted) = request.param("key") {
                if !keys.contains(&wanted.to_string()) {
                    return Err((403, format!("este token no ve {wanted}")));
                }
            }
        }
    }
    Ok(json!(filtered))
}

fn read_keys(store: &Store, actor: &Actor, request: &Request) -> Reply {
    let (project, env) = scoped_request(request, actor)?;
    let map = store.secrets(&project, &env).map_err(bad_request)?;
    let names: Vec<String> = visible(actor, map).into_keys().collect();
    Ok(json!(names))
}

fn write_secret(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let name = request.field("key").unwrap_or_default();
    let value = request.field("value").unwrap_or_default();
    store
        .set(&project, &env, &name, &value, actor.label())
        .map_err(bad_request)?;
    Ok(json!({ "ok": true }))
}

fn delete_secret(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let name = request.field("key").unwrap_or_default();
    store
        .unset(&project, &env, &name, actor.label())
        .map_err(bad_request)?;
    Ok(json!({ "ok": true }))
}

fn create_token(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let name = request.field("name").unwrap_or_default();
    let project = request.field("project").unwrap_or_default();
    let env = request.field("env").unwrap_or_default();
    let keys = request.list("keys");
    let (token, plain) = store
        .create_token(&name, &project, &env, keys, actor.label())
        .map_err(bad_request)?;
    Ok(json!({
        "id": token.id,
        "name": token.name,
        "project": token.project,
        "env": token.env,
        "keys": token.keys,
        "token": plain,
    }))
}

fn revoke_token(store: &Store, actor: &Actor, request: &Request) -> Reply {
    admin(actor)?;
    let id = request
        .field("id")
        .or_else(|| request.param("id").map(str::to_string))
        .unwrap_or_default();
    let token = store.revoke(&id, actor.label()).map_err(bad_request)?;
    Ok(json!({ "id": token.id, "name": token.name }))
}

fn bad_request(message: String) -> (u16, String) {
    (400, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Key;
    use crate::store::temp_root;

    fn server() -> Arc<Server> {
        let store = Store::open(temp_root(), Key::from_hex(&"ab".repeat(32)).unwrap()).unwrap();
        Arc::new(Server {
            store: Mutex::new(store),
            admin: "hd_admin".to_string(),
        })
    }

    fn get(path: &str, token: &str) -> Request {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        Request {
            method: "GET".into(),
            path: path.to_string(),
            query: http::parse_pairs(query),
            headers: std::collections::HashMap::from([(
                "authorization".to_string(),
                format!("Bearer {token}"),
            )]),
            body: Vec::new(),
            too_large: false,
        }
    }

    fn put(body: Value, token: &str) -> Request {
        Request {
            method: "PUT".into(),
            path: "/v1/secrets".into(),
            query: Default::default(),
            headers: std::collections::HashMap::from([(
                "authorization".to_string(),
                format!("Bearer {token}"),
            )]),
            body: serde_json::to_vec(&body).unwrap(),
            too_large: false,
        }
    }

    #[test]
    fn a_request_without_a_token_is_rejected() {
        let server = server();
        let request = Request {
            method: "GET".into(),
            path: "/v1/secrets".into(),
            query: Default::default(),
            headers: Default::default(),
            body: Vec::new(),
            too_large: false,
        };
        let store = server.store.lock().unwrap();
        assert_eq!(route(&server, &store, &request).unwrap_err().0, 401);
    }

    #[test]
    fn the_admin_writes_and_a_token_reads() {
        let server = server();
        let store = server.store.lock().unwrap();
        let write = route(
            &server,
            &store,
            &put(
                json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" }),
                "hd_admin",
            ),
        )
        .unwrap();
        assert_eq!(write["ok"], true);
        let (token, plain) = store
            .create_token("agente", "bifrost", "dev", None, "admin")
            .unwrap();
        assert_eq!(token.project, "bifrost");
        let read = route(
            &server,
            &store,
            &get("/v1/secrets?project=bifrost&env=dev", &plain),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
    }

    #[test]
    fn a_token_does_not_reach_another_environment() {
        let server = server();
        let store = server.store.lock().unwrap();
        store.set("bifrost", "prod", "A", "1", "admin").unwrap();
        let (_, plain) = store
            .create_token("agente", "bifrost", "dev", None, "admin")
            .unwrap();
        let error = route(
            &server,
            &store,
            &get("/v1/secrets?project=bifrost&env=prod", &plain),
        )
        .unwrap_err();
        assert_eq!(error.0, 403);
    }

    #[test]
    fn a_token_with_keys_only_sees_those() {
        let server = server();
        let store = server.store.lock().unwrap();
        store.set("bifrost", "dev", "A", "1", "admin").unwrap();
        store.set("bifrost", "dev", "B", "2", "admin").unwrap();
        let keys = Some(vec!["A".to_string()]);
        let (_, plain) = store
            .create_token("agente", "bifrost", "dev", keys, "admin")
            .unwrap();
        let read = route(
            &server,
            &store,
            &get("/v1/secrets?project=bifrost&env=dev", &plain),
        )
        .unwrap();
        assert_eq!(read["A"], "1");
        assert!(read["B"].is_null());
        let keys = route(
            &server,
            &store,
            &get("/v1/keys?project=bifrost&env=dev", &plain),
        )
        .unwrap();
        assert_eq!(keys.as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_token_cannot_write_or_administrate() {
        let server = server();
        let store = server.store.lock().unwrap();
        let (_, plain) = store
            .create_token("agente", "bifrost", "dev", None, "admin")
            .unwrap();
        let write = route(
            &server,
            &store,
            &put(
                json!({ "project": "bifrost", "env": "dev", "key": "A", "value": "1" }),
                &plain,
            ),
        )
        .unwrap_err();
        assert_eq!(write.0, 403);
        let tokens = route(&server, &store, &get("/v1/tokens", &plain)).unwrap_err();
        assert_eq!(tokens.0, 403);
    }
}
