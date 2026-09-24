use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SETUP_FILE: &str = "heimdall.yaml";

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("") {
        "run" => forward(args),
        "setup" => setup(args),
        "login" => login(args),
        "logout" => logout(),
        "set" => set(args),
        "unset" => unset(args),
        "ls" | "keys" => keys(args),
        "environments" | "envs" => environments(),
        "token" => token(args),
        "audit" => audit(),
        "help" => {
            usage();
            Ok(())
        }
        other => Err(format!("no conozco «{other}», mirá `heimdall help`")),
    }
}

fn usage() {
    println!(
        "\
heimdall — secretos por proyecto y entorno

  heimdall setup --project X --config Y [--dir D]
  heimdall run [--project X] [--config Y] -- comando
  heimdall login --token T
  heimdall logout
  heimdall set CLAVE=valor [--project X] [--env Y]
  heimdall unset CLAVE [--project X] [--env Y]
  heimdall ls [--project X] [--env Y]
  heimdall environments
  heimdall token create --name N [--project X] [--env Y] [--keys A,B] [--ttl 2h]
                        (el proyecto y el entorno aceptan «*»)
  heimdall token create --name N --admin [--ttl 24h]
  heimdall token list
  heimdall token revoke --id ID
  heimdall audit
  heimdall help

El proyecto y el entorno salen de los flags o, si no los pasás, de un
heimdall.yaml que se busca en el directorio actual y hacia arriba. Lo escribe
«heimdall setup». Los flags son los de doppler: -p/--project, -c/--config.

El cliente lee HEIMDALL_URL (por defecto http://127.0.0.1:8080) y HEIMDALL_TOKEN.
El token también puede estar guardado con «heimdall login»."
    );
}

fn forward(args: &[String]) -> Result<(), String> {
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return Err("falta el -- antes del comando".to_string());
    };
    let (project, env) = scope(&args[..separator])?;
    let command = &args[separator + 1..];
    let Some((program, rest)) = command.split_first() else {
        return Err("falta el comando después del --".to_string());
    };
    let secrets = call(
        "GET",
        &format!("/v1/secrets?project={project}&env={env}"),
        None,
    )?;
    let mut child = Command::new(program);
    child.args(rest);
    child.env_remove("HEIMDALL_TOKEN");
    if let Some(map) = secrets.as_object() {
        for (name, value) in map {
            if std::env::var_os(name).is_some() {
                continue;
            }
            if let Some(text) = value.as_str() {
                child.env(name, text);
            }
        }
    }
    Err(format!("no pude correr {program}: {}", child.exec()))
}

struct Setup {
    project: String,
    env: String,
}

fn setup(args: &[String]) -> Result<(), String> {
    let dir = match flag(args, "--dir") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::current_dir().map_err(|e| format!("no sé dónde estoy: {e}"))?,
    };
    let project = pick(args, &["--project", "-p"], None).ok_or("falta --project")?;
    let env = pick(args, &["--config", "-c", "--env"], None).ok_or("falta --config")?;
    let file = dir.join(SETUP_FILE);
    let body = format!("setup:\n  - project: {project}\n    config: {env}\n");
    std::fs::write(&file, body).map_err(|e| format!("no pude escribir {}: {e}", file.display()))?;
    println!("{} → {project}/{env}", file.display());
    Ok(())
}

fn login(args: &[String]) -> Result<(), String> {
    let token = match flag(args, "--token") {
        Some(token) => token,
        None => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("no pude leer el token: {e}"))?;
            line.trim().to_string()
        }
    };
    if token.is_empty() {
        return Err(
            "esperaba el token: `heimdall login --token T`, o pegámelo por stdin".to_string(),
        );
    }
    let file = token_file();
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("no pude crear {}: {e}", dir.display()))?;
    }
    std::fs::write(&file, token)
        .map_err(|e| format!("no pude escribir {}: {e}", file.display()))?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("no pude cerrar los permisos de {}: {e}", file.display()))?;
    println!("guardado en {}", file.display());
    Ok(())
}

fn logout() -> Result<(), String> {
    let file = token_file();
    if file.exists() {
        std::fs::remove_file(&file)
            .map_err(|e| format!("no pude borrar {}: {e}", file.display()))?;
    }
    println!("listo, no queda ningún token guardado");
    Ok(())
}

fn scope(args: &[String]) -> Result<(String, String), String> {
    let file = find_setup();
    let project = pick(
        args,
        &["--project", "-p"],
        file.as_ref().map(|s| s.project.clone()),
    )
    .ok_or("falta el proyecto: pasá --project, o corré «heimdall setup»")?;
    let env = pick(
        args,
        &["--config", "-c", "--env"],
        file.as_ref().map(|s| s.env.clone()),
    )
    .ok_or("falta el entorno: pasá --config, o corré «heimdall setup»")?;
    Ok((project, env))
}

fn pick(args: &[String], names: &[&str], fallback: Option<String>) -> Option<String> {
    names.iter().find_map(|name| flag(args, name)).or(fallback)
}

fn find_setup() -> Option<Setup> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let file = dir.join(SETUP_FILE);
        if file.is_file() {
            return read_setup(&file);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

fn read_setup(file: &Path) -> Option<Setup> {
    let text = std::fs::read_to_string(file).ok()?;
    Some(Setup {
        project: yaml_value(&text, "project")?,
        env: yaml_value(&text, "config")?,
    })
}

fn yaml_value(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    text.lines().find_map(|line| {
        line.trim()
            .trim_start_matches('-')
            .trim()
            .strip_prefix(&prefix)
            .map(|value| value.trim().to_string())
    })
}

fn set(args: &[String]) -> Result<(), String> {
    let (project, env) = scope(args)?;
    let pair = args
        .get(1)
        .filter(|arg| arg.contains('='))
        .ok_or("esperaba CLAVE=valor")?;
    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
    call(
        "PUT",
        "/v1/secrets",
        Some(json!({ "project": project, "env": env, "key": name, "value": value })),
    )?;
    println!("{name} guardada en {project}/{env}");
    Ok(())
}

fn unset(args: &[String]) -> Result<(), String> {
    let (project, env) = scope(args)?;
    let name = args.get(1).ok_or("esperaba la clave a sacar")?;
    call(
        "DELETE",
        "/v1/secrets",
        Some(json!({ "project": project, "env": env, "key": name })),
    )?;
    println!("{name} ya no está en {project}/{env}");
    Ok(())
}

fn keys(args: &[String]) -> Result<(), String> {
    let (project, env) = scope(args)?;
    let value = call(
        "GET",
        &format!("/v1/keys?project={project}&env={env}"),
        None,
    )?;
    for name in value.as_array().into_iter().flatten() {
        if let Some(text) = name.as_str() {
            println!("{text}");
        }
    }
    Ok(())
}

fn environments() -> Result<(), String> {
    let value = call("GET", "/v1/environments", None)?;
    for name in value.as_array().into_iter().flatten() {
        if let Some(text) = name.as_str() {
            println!("{text}");
        }
    }
    Ok(())
}

fn token(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str).unwrap_or("list") {
        "create" => token_create(args),
        "revoke" => token_revoke(args),
        "list" => token_list(),
        other => Err(format!("no conozco `token {other}`")),
    }
}

fn token_create(args: &[String]) -> Result<(), String> {
    let name = required(args, "--name")?;
    let admin = args.iter().any(|arg| arg == "--admin");
    let mut body = json!({ "name": name, "admin": admin });
    if !admin {
        let (project, env) = scope(args)?;
        body["project"] = json!(project);
        body["env"] = json!(env);
        if let Some(keys) = flag(args, "--keys") {
            let list: Vec<&str> = keys
                .split(',')
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .collect();
            body["keys"] = json!(list);
        }
    }
    if let Some(ttl) = flag(args, "--ttl") {
        body["ttl"] = json!(parse_ttl(&ttl)?);
    }
    let value = call("POST", "/v1/tokens", Some(body))?;
    println!("{}", value["token"].as_str().unwrap_or(""));
    eprintln!(
        "guardalo: no se vuelve a mostrar. id {}.",
        value["id"].as_str().unwrap_or("")
    );
    Ok(())
}

fn parse_ttl(text: &str) -> Result<i64, String> {
    if text.len() < 2 {
        return Err(format!("«{text}»: usá un número y s, m, h o d"));
    }
    let (number, unit) = text.split_at(text.len() - 1);
    let value: i64 = number
        .parse()
        .map_err(|_| format!("«{text}» no tiene un número adelante"))?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("«{text}»: usá s, m, h o d")),
    };
    Ok(value * seconds)
}

fn token_revoke(args: &[String]) -> Result<(), String> {
    let id = required(args, "--id")?;
    let value = call("DELETE", &format!("/v1/tokens?id={id}"), None)?;
    println!("revocado {}", value["name"].as_str().unwrap_or(&id));
    Ok(())
}

fn token_list() -> Result<(), String> {
    let value = call("GET", "/v1/tokens", None)?;
    for entry in value.as_array().into_iter().flatten() {
        println!(
            "{}  {}",
            entry["id"].as_str().unwrap_or(""),
            describe(entry)
        );
    }
    Ok(())
}

fn describe(entry: &Value) -> String {
    let name = entry["name"].as_str().unwrap_or("");
    let scope = if entry["admin"].as_bool().unwrap_or(false) {
        "admin".to_string()
    } else {
        format!(
            "{}/{}",
            entry["project"].as_str().unwrap_or(""),
            entry["env"].as_str().unwrap_or("")
        )
    };
    let keys = entry["keys"].as_array().map(|keys| {
        keys.iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",")
    });
    let mut out = format!(
        "{name}  {scope}  {}",
        match keys {
            Some(keys) if !keys.is_empty() => format!("claves: {keys}"),
            Some(_) => "sin claves: ve todo el entorno".to_string(),
            None => "ve todo el entorno".to_string(),
        }
    );
    if let Some(expires) = entry["expires_at"].as_i64() {
        out.push_str(&format!("  vence {expires}"));
    }
    out.push_str(&match entry["last_used"].as_i64() {
        Some(used) => format!("  último uso {used}"),
        None => "  sin uso".to_string(),
    });
    out
}

fn audit() -> Result<(), String> {
    let value = call("GET", "/v1/audit", None)?;
    for entry in value.as_array().into_iter().flatten() {
        println!(
            "{}  {}  {}  {}/{}  {}",
            entry["at"].as_u64().unwrap_or_default(),
            entry["actor"].as_str().unwrap_or(""),
            entry["action"].as_str().unwrap_or(""),
            entry["project"].as_str().unwrap_or(""),
            entry["env"].as_str().unwrap_or(""),
            entry["key"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn call(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let url = format!("{}{}", base_url(), path);
    let token = auth_token()?;
    let request = match method {
        "GET" => ureq::get(&url),
        "PUT" => ureq::put(&url),
        "POST" => ureq::post(&url),
        "DELETE" => ureq::delete(&url),
        other => return Err(format!("no sé hacer {other}")),
    }
    .set("Authorization", &format!("Bearer {token}"));
    let response = match body {
        Some(value) => request.send_json(value),
        None => request.call(),
    };
    match response {
        Ok(response) => response
            .into_json::<Value>()
            .map_err(|e| format!("respuesta rota: {e}")),
        Err(ureq::Error::Status(_, response)) => {
            let value = response.into_json::<Value>().unwrap_or_else(|_| json!({}));
            Err(value["error"]
                .as_str()
                .unwrap_or("la API contestó mal")
                .to_string())
        }
        Err(e) => Err(format!("no pude hablar con {url}: {e}")),
    }
}

fn base_url() -> String {
    std::env::var("HEIMDALL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

fn auth_token() -> Result<String, String> {
    if let Ok(token) = std::env::var("HEIMDALL_TOKEN") {
        return Ok(token);
    }
    let file = token_file();
    std::fs::read_to_string(&file)
        .map(|text| text.trim().to_string())
        .map_err(|_| {
            format!(
                "falta HEIMDALL_TOKEN, o guardalo con «heimdall login» en {}",
                file.display()
            )
        })
}

fn token_file() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".heimdall").join("token")
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for (index, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("falta {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn flags_read_the_value_after_the_name() {
        let args = args("run --project bifrost --env dev -- echo hola");
        assert_eq!(flag(&args, "--project").unwrap(), "bifrost");
        assert_eq!(flag(&args, "--env").unwrap(), "dev");
        assert!(flag(&args, "--nada").is_none());
    }

    #[test]
    fn flags_also_read_the_value_after_an_equals_sign() {
        let args = args("run --config=dev -- echo hola");
        assert_eq!(flag(&args, "--config").unwrap(), "dev");
    }

    #[test]
    fn the_doppler_short_flags_work() {
        let args = args("run -p picsel -c dev -- echo hola");
        assert_eq!(pick(&args, &["--project", "-p"], None).unwrap(), "picsel");
        assert_eq!(pick(&args, &["--config", "-c"], None).unwrap(), "dev");
    }

    #[test]
    fn a_flag_beats_the_setup_file() {
        let args = args("run -c prd -- echo hola");
        let env = pick(&args, &["--config", "-c"], Some("dev".to_string()));
        assert_eq!(env.unwrap(), "prd");
    }

    #[test]
    fn the_setup_file_fills_what_the_flags_leave_out() {
        let args = args("run -- echo hola");
        let env = pick(&args, &["--config", "-c"], Some("dev".to_string()));
        assert_eq!(env.unwrap(), "dev");
    }

    #[test]
    fn the_setup_file_gives_the_project_and_the_environment() {
        let text = "setup:\n  - project: picsel\n    config: dev\n";
        assert_eq!(yaml_value(text, "project").unwrap(), "picsel");
        assert_eq!(yaml_value(text, "config").unwrap(), "dev");
        assert!(yaml_value(text, "token").is_none());
    }

    #[test]
    fn the_command_goes_after_the_separator() {
        let args = args("run --project bifrost --env dev -- echo hola mundo");
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[separator + 1..].join(" "), "echo hola mundo");
    }

    #[test]
    fn a_repeated_flag_does_not_move_the_separator() {
        let args = args("run --preserve-env --preserve-env -- echo hola");
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[separator + 1..].join(" "), "echo hola");
    }

    #[test]
    fn a_missing_flag_is_an_error() {
        assert!(flag(&args("ls"), "--project").is_none());
    }

    #[test]
    fn ttl_units_become_seconds() {
        assert_eq!(parse_ttl("30s").unwrap(), 30);
        assert_eq!(parse_ttl("15m").unwrap(), 900);
        assert_eq!(parse_ttl("2h").unwrap(), 7200);
        assert_eq!(parse_ttl("7d").unwrap(), 604800);
    }

    #[test]
    fn a_bad_ttl_is_an_error() {
        assert!(parse_ttl("2").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("2w").is_err());
        assert!(parse_ttl("dos-h").is_err());
    }
}
