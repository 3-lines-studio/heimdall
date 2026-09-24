use crate::http::{self, Request};
use crate::server::{Server, COOKIE};
use serde_json::json;
use std::net::TcpStream;
use std::sync::Arc;

const INDEX: &str = include_str!("../web/index.html");
const LOGIN: &str = include_str!("../web/login.html");
const APP: &str = include_str!("../web/app.js");
const UTIL: &str = include_str!("../web/util.js");
const STYLE: &str = include_str!("../web/style.css");
const ICON: &str = include_str!("../web/icon.svg");

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
const LOGIN_TTL: i64 = 900;
const SESSION_TTL: i64 = 30 * 24 * 60 * 60;

pub fn handle(
    server: &Arc<Server>,
    request: &Request,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => app(server, request, stream),
        ("GET", "/login") => http::send_text(stream, 200, HTML, &versioned(LOGIN)),
        ("GET", "/app.js") => asset(stream, JS, APP.as_bytes()),
        ("GET", "/util.js") => asset(stream, JS, UTIL.as_bytes()),
        ("GET", "/style.css") => asset(stream, CSS, STYLE.as_bytes()),
        ("GET", "/icon.svg") => asset(stream, "image/svg+xml", ICON.as_bytes()),
        ("POST", "/api/login") => ask_for_link(server, request, stream),
        ("GET", "/auth") => enter(server, request, stream),
        ("POST", "/api/logout") => leave(server, request, stream),
        ("GET", "/api/me") => me(server, request, stream),
        _ => http::send_text(stream, 404, "text/plain", "no está"),
    }
}

fn app(server: &Arc<Server>, request: &Request, stream: &mut TcpStream) -> std::io::Result<()> {
    if who(server, request).is_none() {
        return http::respond(stream, 303, "text/plain", &[("Location", "/login")], b"");
    }
    http::send_text(stream, 200, HTML, &versioned(INDEX))
}

fn me(server: &Arc<Server>, request: &Request, stream: &mut TcpStream) -> std::io::Result<()> {
    match who(server, request) {
        Some(email) => http::send_json(stream, 200, &json!({ "email": email })),
        None => http::send_error(stream, 401, "sin sesión"),
    }
}

fn ask_for_link(
    server: &Arc<Server>,
    request: &Request,
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    let email = request
        .field("email")
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let mut answer = json!({ "sent": true });
    if !server.emails.contains(&email) {
        return http::send_json(stream, 200, &answer);
    }
    let link = {
        let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.sweep();
        match store.create_login(&email, LOGIN_TTL) {
            Ok(link) => link,
            Err(_) => return http::send_error(stream, 500, "no pude armar el link"),
        }
    };
    let url = format!("{}/auth?token={link}", server.link_base);
    match &server.mail {
        Some(mail) => {
            if let Err(e) = mail.send_link(&email, &url) {
                eprintln!("heimdall: {e}");
            }
        }
        None => eprintln!("heimdall: link para {email}: {url}"),
    }
    if server.dev {
        answer["link"] = json!(url);
    }
    http::send_json(stream, 200, &answer)
}

fn enter(server: &Arc<Server>, request: &Request, stream: &mut TcpStream) -> std::io::Result<()> {
    let email = request.param("token").and_then(|token| {
        let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
        store.consume_login(token).ok()
    });
    let Some(email) = email else {
        return http::respond(
            stream,
            303,
            "text/plain",
            &[("Location", "/login?error=1")],
            b"",
        );
    };
    let session = {
        let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
        store
            .create_session(&email, SESSION_TTL)
            .unwrap_or_default()
    };
    let cookie = format!(
        "{COOKIE}={session}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age={SESSION_TTL}"
    );
    http::respond(
        stream,
        303,
        "text/plain",
        &[("Location", "/"), ("Set-Cookie", &cookie)],
        b"",
    )
}

fn leave(server: &Arc<Server>, request: &Request, stream: &mut TcpStream) -> std::io::Result<()> {
    if let Some(cookie) = request.cookie(COOKIE) {
        let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = store.drop_session(&cookie);
    }
    let expired = format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0");
    http::send_json_with(
        stream,
        200,
        &json!({ "ok": true }),
        &[("Set-Cookie", &expired)],
    )
}

fn who(server: &Arc<Server>, request: &Request) -> Option<String> {
    let cookie = request.cookie(COOKIE)?;
    let store = server.store.lock().unwrap_or_else(|e| e.into_inner());
    store.session(&cookie).ok().flatten()
}

fn asset(stream: &mut TcpStream, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    http::respond(
        stream,
        200,
        content_type,
        &[("Cache-Control", IMMUTABLE)],
        body,
    )
}

fn versioned(page: &str) -> String {
    let version = std::env::var("RAILWAY_GIT_COMMIT_SHA").unwrap_or_default();
    page.replace("/app.js", &format!("/app.js?v={version}"))
        .replace("/util.js", &format!("/util.js?v={version}"))
        .replace("/style.css", &format!("/style.css?v={version}"))
        .replace("/icon.svg", &format!("/icon.svg?v={version}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_assets_point_at_the_commit() {
        std::env::set_var("RAILWAY_GIT_COMMIT_SHA", "abc123");
        let page = versioned(
            r#"<script src="/app.js"></script><script src="/util.js"></script><link href="/style.css">"#,
        );
        assert!(page.contains("/app.js?v=abc123"));
        assert!(page.contains("/util.js?v=abc123"));
        assert!(page.contains("/style.css?v=abc123"));
    }
}
