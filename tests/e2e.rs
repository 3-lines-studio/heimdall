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
    let token = link.split("token=").nth(1).expect("sin token");

    let entered = raw(&running, &format!("/auth?token={token}"), None);
    assert_eq!(status_of(&entered), 303);
    let session = cookie_of(&entered).expect("sin cookie");

    let (status, me) = with_cookie(&running, "/api/me", &session);
    assert_eq!(status, 200);
    assert_eq!(me["email"], "berti@ejemplo.com");

    let (status, _) = with_cookie(&running, "/v1/environments", &session);
    assert_eq!(status, 200);

    assert_eq!(
        status_of(&raw(&running, &format!("/auth?token={token}"), None)),
        303
    );
    let (status, _) = with_cookie(&running, "/api/me", "heimdall_session=nada");
    assert_eq!(status, 401);
}
