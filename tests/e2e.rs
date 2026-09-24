use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
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
