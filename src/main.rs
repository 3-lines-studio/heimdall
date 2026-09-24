mod cli;
mod crypto;
mod http;
mod server;
mod store;

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
    let store = store::Store::open(root.into(), key)?;
    let server = Arc::new(Server {
        store: Mutex::new(store),
        admin,
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
