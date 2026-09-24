mod cli;
mod crypto;
mod http;
mod mail;
mod server;
mod store;
mod web;

use crypto::Key;
use server::Server;
use std::sync::{Arc, Mutex};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        _ => cli::run(&args),
    };
    if let Err(message) = result {
        eprintln!("heimdall: {message}");
        std::process::exit(1);
    }
}

fn serve() -> Result<(), String> {
    let root = std::env::var("HEIMDALL_DATA").unwrap_or_else(|_| "/data/heimdall".to_string());
    let key = Key::from_hex(&required_env("HEIMDALL_MASTER_KEY")?)?;
    let admin = required_env("HEIMDALL_ADMIN_TOKEN")?;
    let port = std::env::var("PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(8080);
    let store = store::Store::open(std::path::PathBuf::from(root).join("heimdall.db"), key)?;
    let emails: Vec<String> = std::env::var("HEIMDALL_EMAILS")
        .unwrap_or_default()
        .split(',')
        .map(|email| email.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .collect();
    if emails.is_empty() {
        eprintln!("heimdall: HEIMDALL_EMAILS está vacío, no va a poder entrar nadie");
    }
    let server = Arc::new(Server {
        store: Mutex::new(store),
        admin,
        emails,
        mail: mail::Mail::from_env(),
        link_base: std::env::var("HEIMDALL_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string())
            .trim_end_matches('/')
            .to_string(),
        dev: std::env::var("HEIMDALL_WEB_DEV").is_ok(),
    });
    let listener = server::listen(port)?;
    let address = listener
        .local_addr()
        .map_err(|e| format!("sin dirección: {e}"))?;
    println!("heimdall en {address}");
    server::serve(server, listener);
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("falta {name}"))
}
