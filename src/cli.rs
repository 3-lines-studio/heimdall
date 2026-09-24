use serde_json::{json, Value};
use std::process::Command;

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("") {
        "run" => forward(args),
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

  heimdall run --project X --env Y -- comando
  heimdall set CLAVE=valor --project X --env Y
  heimdall unset CLAVE --project X --env Y
  heimdall ls --project X --env Y
  heimdall environments
  heimdall token create --name N --project X --env Y [--keys A,B]
  heimdall token list
  heimdall token revoke --id ID
  heimdall audit
  heimdall help

El cliente lee HEIMDALL_URL (por defecto http://127.0.0.1:8080) y HEIMDALL_TOKEN."
    );
}

fn forward(args: &[String]) -> Result<(), String> {
    let project = required(args, "--project")?;
    let env = required(args, "--env")?;
    let Some(separator) = args.iter().position(|arg| arg == "--") else {
        return Err("falta el -- antes del comando".to_string());
    };
    let command: Vec<&String> = args[separator + 1..].iter().collect();
    let Some((program, rest)) = command.split_first() else {
        return Err("falta el comando después del --".to_string());
    };
    let secrets = call(
        "GET",
        &format!("/v1/secrets?project={project}&env={env}"),
        None,
    )?;
    let mut child = Command::new(program);
    child.args(rest.iter().map(|arg| arg.as_str()));
    child.env_remove("HEIMDALL_TOKEN");
    if let Some(map) = secrets.as_object() {
        for (name, value) in map {
            if let Some(text) = value.as_str() {
                child.env(name, text);
            }
        }
    }
    let status = child
        .status()
        .map_err(|e| format!("no pude correr {program}: {e}"))?;
    std::process::exit(status.code().unwrap_or(1))
}

fn set(args: &[String]) -> Result<(), String> {
    let project = required(args, "--project")?;
    let env = required(args, "--env")?;
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
    let project = required(args, "--project")?;
    let env = required(args, "--env")?;
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
    let project = required(args, "--project")?;
    let env = required(args, "--env")?;
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
    let project = required(args, "--project")?;
    let env = required(args, "--env")?;
    let mut body = json!({ "name": name, "project": project, "env": env });
    if let Some(keys) = flag(args, "--keys") {
        let list: Vec<&str> = keys
            .split(',')
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .collect();
        body["keys"] = json!(list);
    }
    let value = call("POST", "/v1/tokens", Some(body))?;
    println!("{}", value["token"].as_str().unwrap_or(""));
    eprintln!(
        "guardalo: no se vuelve a mostrar. id {}.",
        value["id"].as_str().unwrap_or("")
    );
    Ok(())
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
        let keys = entry["keys"].as_array().map(|keys| {
            keys.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        });
        println!(
            "{}  {}  {}/{}  {}{}",
            entry["id"].as_str().unwrap_or(""),
            entry["name"].as_str().unwrap_or(""),
            entry["project"].as_str().unwrap_or(""),
            entry["env"].as_str().unwrap_or(""),
            match keys {
                Some(keys) if !keys.is_empty() => format!("claves: {keys}"),
                Some(_) => "sin claves: ve todo el entorno".to_string(),
                None => "ve todo el entorno".to_string(),
            },
            match entry["last_used"].as_u64() {
                Some(used) => format!("  último uso {used}"),
                None => "  sin uso".to_string(),
            }
        );
    }
    Ok(())
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
    let token = std::env::var("HEIMDALL_TOKEN").map_err(|_| "falta HEIMDALL_TOKEN".to_string())?;
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

fn flag(args: &[String], name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    args.get(index + 1).cloned()
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
    fn the_command_goes_after_the_separator() {
        let args = args("run --project bifrost --env dev -- echo hola mundo");
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[separator + 1..].join(" "), "echo hola mundo");
    }

    #[test]
    fn a_missing_flag_is_an_error() {
        assert!(required(&args("ls"), "--project").is_err());
    }
}
