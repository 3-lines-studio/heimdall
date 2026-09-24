use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Running {
    child: Child,
    url: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start() -> Running {
    let root = std::env::temp_dir().join(format!(
        "heimdall-e2e-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_heimdall"))
        .env("HEIMDALL_DATA", &root)
        .env("HEIMDALL_MASTER_KEY", "ab".repeat(32))
        .env("HEIMDALL_ADMIN_TOKEN", "hd_admin")
        .env("HEIMDALL_EMAILS", "berti@ejemplo.com")
        .env("HEIMDALL_WEB_DEV", "1")
        .env("PORT", "0")
        .stdout(Stdio::piped())
        .spawn()
        .expect("no arrancó el server");
    let stdout = child.stdout.take().expect("sin stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("sin salida");
    let port = line.trim().rsplit(':').next().expect("sin puerto");
    Running {
        child,
        url: format!("http://127.0.0.1:{port}"),
    }
}

fn call(
    running: &Running,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let url = format!("{}{}", running.url, path);
    let request = match method {
        "GET" => ureq::get(&url),
        "PUT" => ureq::put(&url),
        "POST" => ureq::post(&url),
        "DELETE" => ureq::delete(&url),
        other => panic!("método {other}"),
    }
    .set("Authorization", &format!("Bearer {token}"));
    let response = match body {
        Some(value) => request.send_json(value),
        None => request.call(),
    };
    match response {
        Ok(response) => (200, response.into_json().unwrap()),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_json().unwrap_or_else(|_| json!({})))
        }
        Err(e) => panic!("{e}"),
    }
}

fn wait_for(running: &Running) {
    for _ in 0..50 {
        if ureq::get(&format!("{}/v1/health", running.url))
            .call()
            .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("el server no contestó");
}

#[test]
fn an_agent_token_only_reaches_its_environment() {
    let running = start();
    wait_for(&running);

    let (status, _) = call(
        &running,
        "PUT",
        "/v1/secrets",
        "hd_admin",
        Some(
            json!({ "project": "bifrost", "env": "dev", "key": "STRIPE_KEY", "value": "sk_test_1" }),
        ),
    );
    assert_eq!(status, 200);
    let (status, _) = call(
        &running,
        "PUT",
        "/v1/secrets",
        "hd_admin",
        Some(
            json!({ "project": "bifrost", "env": "prod", "key": "STRIPE_KEY", "value": "sk_live_1" }),
        ),
    );
    assert_eq!(status, 200);

    let (status, created) = call(
        &running,
        "POST",
        "/v1/tokens",
        "hd_admin",
        Some(
            json!({ "name": "agente", "project": "bifrost", "env": "dev", "keys": ["STRIPE_KEY"] }),
        ),
    );
    assert_eq!(status, 200);
    let agent = created["token"].as_str().unwrap().to_string();
    assert!(agent.starts_with("hd_"));

    let (status, secrets) = call(
        &running,
        "GET",
        "/v1/secrets?project=bifrost&env=dev",
        &agent,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(secrets["STRIPE_KEY"], "sk_test_1");

    let (status, error) = call(
        &running,
        "GET",
        "/v1/secrets?project=bifrost&env=prod",
        &agent,
        None,
    );
    assert_eq!(status, 403);
    assert!(error["error"].as_str().unwrap().contains("no llega"));

    let (status, _) = call(
        &running,
        "PUT",
        "/v1/secrets",
        &agent,
        Some(json!({ "project": "bifrost", "env": "dev", "key": "OTRO", "value": "x" })),
    );
    assert_eq!(status, 403);

    let (status, _) = call(&running, "GET", "/v1/tokens", &agent, None);
    assert_eq!(status, 403);
}

#[test]
fn a_revoked_token_stops_working() {
    let running = start();
    wait_for(&running);

    call(
        &running,
        "PUT",
        "/v1/secrets",
        "hd_admin",
        Some(json!({ "project": "axe", "env": "dev", "key": "A", "value": "1" })),
    );
    let (_, created) = call(
        &running,
        "POST",
        "/v1/tokens",
        "hd_admin",
        Some(json!({ "name": "agente", "project": "axe", "env": "dev" })),
    );
    let agent = created["token"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();

    let (status, _) = call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        &agent,
        None,
    );
    assert_eq!(status, 200);

    let (status, _) = call(
        &running,
        "DELETE",
        &format!("/v1/tokens?id={id}"),
        "hd_admin",
        None,
    );
    assert_eq!(status, 200);

    let (status, _) = call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        &agent,
        None,
    );
    assert_eq!(status, 401);
}

#[test]
fn a_bad_token_is_rejected() {
    let running = start();
    wait_for(&running);
    let (status, _) = call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        "hd_inventado",
        None,
    );
    assert_eq!(status, 401);
}

#[test]
fn an_admin_token_can_be_created_and_used() {
    let running = start();
    wait_for(&running);

    let (status, created) = call(
        &running,
        "POST",
        "/v1/tokens",
        "hd_admin",
        Some(json!({ "name": "jimmy", "admin": true })),
    );
    assert_eq!(status, 200);
    let admin = created["token"].as_str().unwrap().to_string();

    let (status, _) = call(
        &running,
        "PUT",
        "/v1/secrets",
        &admin,
        Some(json!({ "project": "axe", "env": "dev", "key": "A", "value": "1" })),
    );
    assert_eq!(status, 200);
    let (status, secrets) = call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        &admin,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(secrets["A"], "1");
}

#[test]
fn an_expired_token_stops_working() {
    let running = start();
    wait_for(&running);

    let (status, created) = call(
        &running,
        "POST",
        "/v1/tokens",
        "hd_admin",
        Some(json!({ "name": "agente", "project": "axe", "env": "dev", "ttl": -1 })),
    );
    assert_eq!(status, 200);
    let agent = created["token"].as_str().unwrap().to_string();

    let (status, error) = call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        &agent,
        None,
    );
    assert_eq!(status, 401);
    assert!(error["error"].as_str().unwrap().contains("venció"));
}

#[test]
fn reading_shows_up_in_the_audit() {
    let running = start();
    wait_for(&running);

    call(
        &running,
        "PUT",
        "/v1/secrets",
        "hd_admin",
        Some(json!({ "project": "axe", "env": "dev", "key": "A", "value": "1" })),
    );
    let (_, created) = call(
        &running,
        "POST",
        "/v1/tokens",
        "hd_admin",
        Some(json!({ "name": "agente", "project": "axe", "env": "dev" })),
    );
    let agent = created["token"].as_str().unwrap().to_string();
    call(
        &running,
        "GET",
        "/v1/secrets?project=axe&env=dev",
        &agent,
        None,
    );

    let (status, log) = call(&running, "GET", "/v1/audit?limit=10", "hd_admin", None);
    assert_eq!(status, 200);
    let reads: Vec<&str> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["action"].as_str().unwrap())
        .filter(|action| action.starts_with("get-"))
        .collect();
    assert_eq!(reads, vec!["get-secrets"]);
    let reader = log
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "get-secrets")
        .unwrap();
    assert_eq!(reader["actor"], "agente");
    assert_eq!(reader["env"], "dev");
}

fn raw(running: &Running, path: &str, cookie: Option<&str>) -> String {
    let host = running.url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(host).unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(cookie) = cookie {
        request.push_str(&format!("Cookie: {cookie}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn status_of(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn cookie_of(response: &str) -> Option<String> {
    response
        .lines()
        .find(|line| line.to_lowercase().starts_with("set-cookie:"))
        .map(|line| {
            line["set-cookie:".len()..]
                .trim()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        })
}

fn enter(running: &Running, token: &str) -> (u16, Option<String>) {
    let host = running.url.trim_start_matches("http://");
    let body = format!(r#"{{"token":"{token}"}}"#);
    let mut stream = std::net::TcpStream::connect(host).unwrap();
    let request = format!(
        "POST /api/enter HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    (status_of(&response), cookie_of(&response))
}

fn with_cookie(running: &Running, path: &str, cookie: &str) -> (u16, Value) {
    let url = format!("{}{}", running.url, path);
    match ureq::get(&url).set("Cookie", cookie).call() {
        Ok(response) => (200, response.into_json().unwrap_or_else(|_| json!({}))),
        Err(ureq::Error::Status(status, response)) => {
            (status, response.into_json().unwrap_or_else(|_| json!({})))
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn the_magic_link_opens_a_session() {
    let running = start();
    wait_for(&running);

    assert_eq!(status_of(&raw(&running, "/", None)), 303);

    let (_, stranger) = call(
        &running,
        "POST",
        "/api/login",
        "nada",
        Some(json!({ "email": "otro@ejemplo.com" })),
    );
    assert!(stranger["link"].is_null());

    let (_, asked) = call(
        &running,
        "POST",
        "/api/login",
        "nada",
        Some(json!({ "email": "berti@ejemplo.com" })),
    );
    let link = asked["link"].as_str().expect("sin link").to_string();
    assert!(link.contains("/auth#token="), "{link}");
    let token = link.split("token=").nth(1).expect("sin token");

    let (status, cookie) = enter(&running, token);
    assert_eq!(status, 200);
    let session = cookie
        .expect("sin cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let (status, me) = with_cookie(&running, "/api/me", &session);
    assert_eq!(status, 200);
    assert_eq!(me["email"], "berti@ejemplo.com");

    let (status, _) = with_cookie(&running, "/v1/environments", &session);
    assert_eq!(status, 200);

    assert_eq!(enter(&running, token).0, 401);
    let (status, _) = with_cookie(&running, "/api/me", "heimdall_session=nada");
    assert_eq!(status, 401);
}

#[test]
fn a_second_link_to_the_same_address_waits() {
    let running = start();
    wait_for(&running);

    let (_, first) = call(
        &running,
        "POST",
        "/api/login",
        "nada",
        Some(json!({ "email": "berti@ejemplo.com" })),
    );
    assert!(first["link"].as_str().is_some());

    let (status, second) = call(
        &running,
        "POST",
        "/api/login",
        "nada",
        Some(json!({ "email": "berti@ejemplo.com" })),
    );
    assert_eq!(status, 200);
    assert!(second["link"].is_null());
}

#[test]
fn a_giant_header_does_not_take_the_server_down() {
    let running = start();
    wait_for(&running);

    let host = running.url.trim_start_matches("http://").to_string();
    let mut stream = std::net::TcpStream::connect(&host).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = b"GET / HTTP/1.1\r\nHost: x\r\nX-Relleno: ".to_vec();
    request.extend(std::iter::repeat_n(b'A', 256 * 1024));
    let _ = stream.write_all(&request);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut respuesta = Vec::new();
    let _ = stream.read_to_end(&mut respuesta);
    assert!(respuesta.is_empty(), "contestó algo: {}", respuesta.len());

    let (status, _) = call(&running, "GET", "/v1/health", "nada", None);
    assert_eq!(status, 200);
}

#[test]
fn the_structure_lives_on_its_own() {
    let running = start();
    wait_for(&running);

    let body = json!({ "project": "bifrost", "env": "dev" });
    let (status, _) = call(&running, "POST", "/v1/environments", "hd_admin", Some(body));
    assert_eq!(status, 200);

    let (_, names) = call(&running, "GET", "/v1/environments", "hd_admin", None);
    assert_eq!(names, json!(["bifrost/dev"]));

    let renamed = json!({ "project": "bifrost", "env": "dev", "to": "testing" });
    let (_, moved) = call(
        &running,
        "POST",
        "/v1/rename-environment",
        "hd_admin",
        Some(renamed),
    );
    assert_eq!(moved["env"], "testing");

    let (status, _) = call(
        &running,
        "DELETE",
        "/v1/environments",
        "hd_admin",
        Some(json!({ "project": "bifrost", "env": "testing" })),
    );
    assert_eq!(status, 200);
    let (_, names) = call(&running, "GET", "/v1/environments", "hd_admin", None);
    assert_eq!(names, json!([]));
}

#[test]
fn renaming_a_project_keeps_the_secrets_readable() {
    let running = start();
    wait_for(&running);

    call(
        &running,
        "PUT",
        "/v1/secrets",
        "hd_admin",
        Some(
            json!({ "project": "bifrost", "env": "dev", "key": "STRIPE_KEY", "value": "sk_test_123" }),
        ),
    );
    let (status, _) = call(
        &running,
        "POST",
        "/v1/rename-project",
        "hd_admin",
        Some(json!({ "project": "bifrost", "to": "puente" })),
    );
    assert_eq!(status, 200);

    let (status, secrets) = call(
        &running,
        "GET",
        "/v1/secrets?project=puente&env=dev",
        "hd_admin",
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(secrets["STRIPE_KEY"], "sk_test_123");

    let (_, names) = call(&running, "GET", "/v1/environments", "hd_admin", None);
    assert_eq!(names, json!(["puente/dev"]));

    let (status, _) = call(
        &running,
        "DELETE",
        "/v1/projects",
        "hd_admin",
        Some(json!({ "project": "puente" })),
    );
    assert_eq!(status, 200);
    let (_, names) = call(&running, "GET", "/v1/environments", "hd_admin", None);
    assert_eq!(names, json!([]));
}
