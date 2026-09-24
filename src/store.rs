use crate::crypto::{self, Key};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_VALUE: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Clone)]
pub struct Token {
    pub id: String,
    pub name: String,
    pub project: String,
    pub env: String,
    pub keys: Option<Vec<String>>,
    pub hash: String,
    pub created_at: u64,
    pub last_used: Option<u64>,
}

pub struct Store {
    root: PathBuf,
    key: Key,
}

impl Store {
    pub fn open(root: PathBuf, key: Key) -> Result<Store, String> {
        fs::create_dir_all(root.join("secrets"))
            .map_err(|e| format!("no pude crear {root:?}: {e}"))?;
        Ok(Store { root, key })
    }

    pub fn names(&self) -> Result<Vec<String>, String> {
        let dir = self.root.join("secrets");
        let mut out = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|e| format!("no pude leer {dir:?}: {e}"))?;
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let project = entry.file_name().to_string_lossy().to_string();
            let evs =
                fs::read_dir(entry.path()).map_err(|e| format!("no pude leer {entry:?}: {e}"))?;
            for ev in evs.flatten() {
                let file = ev.file_name().to_string_lossy().to_string();
                if let Some(env) = file.strip_suffix(".enc") {
                    out.push(format!("{project}/{env}"));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn secrets(&self, project: &str, env: &str) -> Result<BTreeMap<String, String>, String> {
        let path = self.secrets_path(project, env)?;
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let blob = fs::read(&path).map_err(|e| format!("no pude leer {path:?}: {e}"))?;
        let plain = self.key.derive(&context(project, env)).open(&blob)?;
        serde_json::from_slice(&plain)
            .map_err(|e| format!("{path:?} no es un mapa de secretos: {e}"))
    }

    pub fn set(
        &self,
        project: &str,
        env: &str,
        name: &str,
        value: &str,
        actor: &str,
    ) -> Result<(), String> {
        slug(project)?;
        slug(env)?;
        key_name(name)?;
        if value.len() > MAX_VALUE {
            return Err(format!("el valor pasa los {MAX_VALUE} bytes"));
        }
        let mut map = self.secrets(project, env)?;
        map.insert(name.to_string(), value.to_string());
        self.write_secrets(project, env, &map)?;
        self.audit(actor, "set", project, env, Some(name))
    }

    pub fn unset(&self, project: &str, env: &str, name: &str, actor: &str) -> Result<(), String> {
        let mut map = self.secrets(project, env)?;
        if map.remove(name).is_none() {
            return Err(format!("{name} no está en {project}/{env}"));
        }
        self.write_secrets(project, env, &map)?;
        self.audit(actor, "unset", project, env, Some(name))
    }

    fn write_secrets(
        &self,
        project: &str,
        env: &str,
        map: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        let path = self.secrets_path(project, env)?;
        let plain = serde_json::to_vec(map).map_err(|e| format!("no pude serializar: {e}"))?;
        let blob = self.key.derive(&context(project, env)).seal(&plain)?;
        write_atomic(&path, &blob)
    }

    fn secrets_path(&self, project: &str, env: &str) -> Result<PathBuf, String> {
        slug(project)?;
        slug(env)?;
        let dir = self.root.join("secrets").join(project);
        fs::create_dir_all(&dir).map_err(|e| format!("no pude crear {dir:?}: {e}"))?;
        Ok(dir.join(format!("{env}.enc")))
    }

    pub fn tokens(&self) -> Result<Vec<Token>, String> {
        let path = self.root.join("tokens.enc");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let blob = fs::read(&path).map_err(|e| format!("no pude leer {path:?}: {e}"))?;
        let plain = self.key.derive("tokens").open(&blob)?;
        serde_json::from_slice(&plain).map_err(|e| format!("{path:?} no son tokens: {e}"))
    }

    pub fn create_token(
        &self,
        name: &str,
        project: &str,
        env: &str,
        keys: Option<Vec<String>>,
        actor: &str,
    ) -> Result<(Token, String), String> {
        slug(project)?;
        slug(env)?;
        if name.trim().is_empty() {
            return Err("el token necesita un nombre".to_string());
        }
        let plain = format!("hd_{}", crypto::random_hex(24)?);
        let token = Token {
            id: crypto::random_hex(6)?,
            name: name.to_string(),
            project: project.to_string(),
            env: env.to_string(),
            keys,
            hash: crypto::hash(&plain),
            created_at: now(),
            last_used: None,
        };
        let mut tokens = self.tokens()?;
        tokens.push(token.clone());
        self.write_tokens(&tokens)?;
        self.audit(actor, "token-create", project, env, Some(&token.name))?;
        Ok((token, plain))
    }

    pub fn revoke(&self, id: &str, actor: &str) -> Result<Token, String> {
        let mut tokens = self.tokens()?;
        let Some(index) = tokens.iter().position(|token| token.id == id) else {
            return Err(format!("no hay token {id}"));
        };
        let token = tokens.remove(index);
        self.write_tokens(&tokens)?;
        self.audit(
            actor,
            "token-revoke",
            &token.project,
            &token.env,
            Some(&token.name),
        )?;
        Ok(token)
    }

    pub fn find(&self, plain: &str) -> Result<Option<Token>, String> {
        let presented = crypto::hash(plain);
        let tokens = self.tokens()?;
        Ok(tokens
            .into_iter()
            .find(|token| crypto::equal(&token.hash, &presented)))
    }

    pub fn touch(&self, id: &str) -> Result<(), String> {
        let mut tokens = self.tokens()?;
        let Some(token) = tokens.iter_mut().find(|token| token.id == id) else {
            return Ok(());
        };
        token.last_used = Some(now());
        self.write_tokens(&tokens)
    }

    fn write_tokens(&self, tokens: &[Token]) -> Result<(), String> {
        let plain = serde_json::to_vec(tokens).map_err(|e| format!("no pude serializar: {e}"))?;
        let blob = self.key.derive("tokens").seal(&plain)?;
        write_atomic(&self.root.join("tokens.enc"), &blob)
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        project: &str,
        env: &str,
        name: Option<&str>,
    ) -> Result<(), String> {
        let entry = serde_json::json!({
            "at": now(),
            "actor": actor,
            "action": action,
            "project": project,
            "env": env,
            "key": name,
        });
        let line = format!("{entry}\n");
        let path = self.root.join("audit.jsonl");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("no pude abrir {path:?}: {e}"))?;
        use std::io::Write;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("no pude escribir {path:?}: {e}"))
    }

    pub fn audit_log(&self) -> Result<Vec<serde_json::Value>, String> {
        let path = self.root.join("audit.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("no pude leer {path:?}: {e}"))?;
        Ok(text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }
}

fn context(project: &str, env: &str) -> String {
    format!("secrets/{project}/{env}")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("no pude escribir {tmp:?}: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("no pude mover {tmp:?}: {e}"))
}

pub fn slug(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!("«{name}» tiene que medir entre 1 y 64"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!(
            "«{name}» sólo acepta minúsculas, números, guiones y guiones bajos"
        ));
    }
    Ok(())
}

fn key_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("la clave no puede estar vacía".to_string());
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(format!("«{name}» no es un nombre de variable válido"));
    }
    Ok(())
}

#[cfg(test)]
pub fn temp_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("heimdall-{}", crypto::random_hex(6).unwrap()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open(temp_root(), Key::from_hex(&"ab".repeat(32)).unwrap()).unwrap()
    }

    #[test]
    fn a_secret_survives_a_reopen() {
        let root = temp_root();
        let key = Key::from_hex(&"ab".repeat(32)).unwrap();
        Store::open(root.clone(), key.clone())
            .unwrap()
            .set("bifrost", "dev", "STRIPE_KEY", "sk_test_123", "berti")
            .unwrap();
        let reopened = Store::open(root, key).unwrap();
        let map = reopened.secrets("bifrost", "dev").unwrap();
        assert_eq!(map.get("STRIPE_KEY").unwrap(), "sk_test_123");
    }

    #[test]
    fn the_value_never_lands_in_clear() {
        let store = store();
        store
            .set("bifrost", "dev", "DB_PASSWORD", "hunter2", "berti")
            .unwrap();
        let raw = fs::read(store.root.join("secrets/bifrost/dev.enc")).unwrap();
        assert!(!raw.windows(7).any(|w| w == b"hunter2"));
    }

    #[test]
    fn environments_and_projects_do_not_mix() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "A", "2", "berti").unwrap();
        store.set("axe", "dev", "A", "3", "berti").unwrap();
        assert_eq!(store.secrets("bifrost", "dev").unwrap()["A"], "1");
        assert_eq!(store.secrets("bifrost", "prod").unwrap()["A"], "2");
        assert_eq!(store.secrets("axe", "dev").unwrap()["A"], "3");
    }

    #[test]
    fn names_cannot_escape_the_root() {
        let store = store();
        assert!(store.set("../etc", "dev", "A", "1", "berti").is_err());
        assert!(store.set("bifrost", "..", "A", "1", "berti").is_err());
        assert!(store.set("bifrost", "dev", "A B", "1", "berti").is_err());
        assert!(store.set("bifrost", "dev", "1ABC", "1", "berti").is_err());
    }

    #[test]
    fn missing_secrets_are_an_empty_map() {
        assert!(store().secrets("bifrost", "prod").unwrap().is_empty());
    }

    #[test]
    fn a_removed_key_is_no_longer_there() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.unset("bifrost", "dev", "A", "berti").unwrap();
        assert!(store.secrets("bifrost", "dev").unwrap().is_empty());
        assert!(store.unset("bifrost", "dev", "A", "berti").is_err());
    }

    #[test]
    fn only_the_matching_token_is_found() {
        let store = store();
        let (token, plain) = store
            .create_token("agente", "bifrost", "dev", None, "berti")
            .unwrap();
        assert!(store.find("hd_nada").unwrap().is_none());
        assert_eq!(store.find(&plain).unwrap().unwrap().id, token.id);
    }

    #[test]
    fn a_revoked_token_is_gone() {
        let store = store();
        let (token, plain) = store
            .create_token("agente", "bifrost", "dev", None, "berti")
            .unwrap();
        store.revoke(&token.id, "berti").unwrap();
        assert!(store.find(&plain).unwrap().is_none());
    }

    #[test]
    fn the_token_hash_never_lands_in_clear() {
        let store = store();
        let (_, plain) = store
            .create_token("agente", "bifrost", "dev", None, "berti")
            .unwrap();
        let raw = fs::read(store.root.join("tokens.enc")).unwrap();
        assert!(!raw.windows(plain.len()).any(|w| w == plain.as_bytes()));
    }

    #[test]
    fn the_audit_records_no_values() {
        let store = store();
        store
            .set("bifrost", "dev", "DB_PASSWORD", "hunter2", "berti")
            .unwrap();
        let log = store.audit_log().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["key"], "DB_PASSWORD");
        let raw = fs::read_to_string(store.root.join("audit.jsonl")).unwrap();
        assert!(!raw.contains("hunter2"));
    }

    #[test]
    fn names_lists_what_exists() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "A", "1", "berti").unwrap();
        store.set("axe", "dev", "A", "1", "berti").unwrap();
        assert_eq!(
            store.names().unwrap(),
            vec!["axe/dev", "bifrost/dev", "bifrost/prod"]
        );
    }
}
