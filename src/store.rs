use crate::crypto::{self, Key};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const MAX_VALUE: usize = 64 * 1024;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS secrets (
    project TEXT NOT NULL,
    env TEXT NOT NULL,
    name TEXT NOT NULL,
    value BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project, env, name)
);
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    project TEXT NOT NULL,
    env TEXT NOT NULL,
    keys TEXT,
    hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used INTEGER
);
CREATE INDEX IF NOT EXISTS tokens_hash ON tokens (hash);
CREATE TABLE IF NOT EXISTS audit (
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    project TEXT NOT NULL,
    env TEXT NOT NULL,
    name TEXT
);
";

#[derive(Serialize, Deserialize, Clone)]
pub struct Token {
    pub id: String,
    pub name: String,
    pub project: String,
    pub env: String,
    pub keys: Option<Vec<String>>,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

pub struct Store {
    db: Connection,
    key: Key,
}

impl Store {
    pub fn open(path: PathBuf, key: Key) -> Result<Store, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("no pude crear {parent:?}: {e}"))?;
        }
        let db = Connection::open(&path).map_err(|e| format!("no pude abrir {path:?}: {e}"))?;
        db.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))
            .map_err(|e| format!("no pude poner {path:?} en WAL: {e}"))?;
        db.execute_batch(SCHEMA)
            .map_err(|e| format!("no pude armar el esquema: {e}"))?;
        Ok(Store { db, key })
    }

    fn fail(&self, error: rusqlite::Error) -> String {
        error.to_string()
    }

    pub fn names(&self) -> Result<Vec<String>, String> {
        let mut statement = self
            .db
            .prepare("SELECT DISTINCT project || '/' || env FROM secrets ORDER BY 1")
            .map_err(|e| self.fail(e))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| self.fail(e))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()
            .map_err(|e| self.fail(e))
    }

    pub fn secrets(&self, project: &str, env: &str) -> Result<BTreeMap<String, String>, String> {
        let subkey = self.key.derive(&context(project, env));
        let mut statement = self
            .db
            .prepare("SELECT name, value FROM secrets WHERE project = ?1 AND env = ?2")
            .map_err(|e| self.fail(e))?;
        let rows = statement
            .query_map(params![project, env], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| self.fail(e))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (name, value) = row.map_err(|e| self.fail(e))?;
            let plain = subkey.open(&value)?;
            let text = String::from_utf8(plain).map_err(|_| format!("{name} no es texto"))?;
            out.insert(name, text);
        }
        Ok(out)
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
        let sealed = self
            .key
            .derive(&context(project, env))
            .seal(value.as_bytes())?;
        self.db
            .execute(
                "INSERT INTO secrets (project, env, name, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (project, env, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![project, env, name, sealed, now()],
            )
            .map_err(|e| self.fail(e))?;
        self.audit(actor, "set", project, env, Some(name))
    }

    pub fn unset(&self, project: &str, env: &str, name: &str, actor: &str) -> Result<(), String> {
        let removed = self
            .db
            .execute(
                "DELETE FROM secrets WHERE project = ?1 AND env = ?2 AND name = ?3",
                params![project, env, name],
            )
            .map_err(|e| self.fail(e))?;
        if removed == 0 {
            return Err(format!("{name} no está en {project}/{env}"));
        }
        self.audit(actor, "unset", project, env, Some(name))
    }

    pub fn tokens(&self) -> Result<Vec<Token>, String> {
        let mut statement = self
            .db
            .prepare("SELECT id, name, project, env, keys, created_at, last_used FROM tokens ORDER BY created_at")
            .map_err(|e| self.fail(e))?;
        let rows = statement
            .query_map([], |row| {
                let keys: Option<String> = row.get(4)?;
                Ok(Token {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    project: row.get(2)?,
                    env: row.get(3)?,
                    keys: keys.and_then(|text| serde_json::from_str(&text).ok()),
                    created_at: row.get(5)?,
                    last_used: row.get(6)?,
                })
            })
            .map_err(|e| self.fail(e))?;
        rows.collect::<rusqlite::Result<Vec<Token>>>()
            .map_err(|e| self.fail(e))
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
            created_at: now(),
            last_used: None,
        };
        let keys = token
            .keys
            .as_ref()
            .map(|keys| serde_json::to_string(keys).unwrap_or_default());
        self.db
            .execute(
                "INSERT INTO tokens (id, name, project, env, keys, hash, created_at, last_used)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
                params![
                    token.id,
                    token.name,
                    token.project,
                    token.env,
                    keys,
                    crypto::hash(&plain),
                    token.created_at
                ],
            )
            .map_err(|e| self.fail(e))?;
        self.audit(actor, "token-create", project, env, Some(&token.name))?;
        Ok((token, plain))
    }

    pub fn revoke(&self, id: &str, actor: &str) -> Result<Token, String> {
        let token = self
            .tokens()?
            .into_iter()
            .find(|token| token.id == id)
            .ok_or_else(|| format!("no hay token {id}"))?;
        self.db
            .execute("DELETE FROM tokens WHERE id = ?1", params![id])
            .map_err(|e| self.fail(e))?;
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
        let mut statement = self
            .db
            .prepare("SELECT id, name, project, env, keys, created_at, last_used, hash FROM tokens")
            .map_err(|e| self.fail(e))?;
        let rows = statement
            .query_map([], |row| {
                let keys: Option<String> = row.get(4)?;
                Ok((
                    Token {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        project: row.get(2)?,
                        env: row.get(3)?,
                        keys: keys.and_then(|text| serde_json::from_str(&text).ok()),
                        created_at: row.get(5)?,
                        last_used: row.get(6)?,
                    },
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| self.fail(e))?;
        for row in rows {
            let (token, hash) = row.map_err(|e| self.fail(e))?;
            if crypto::equal(&hash, &presented) {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }

    pub fn touch(&self, id: &str) -> Result<(), String> {
        self.db
            .execute(
                "UPDATE tokens SET last_used = ?2 WHERE id = ?1",
                params![id, now()],
            )
            .map_err(|e| self.fail(e))?;
        Ok(())
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        project: &str,
        env: &str,
        name: Option<&str>,
    ) -> Result<(), String> {
        self.db
            .execute(
                "INSERT INTO audit (at, actor, action, project, env, name) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![now(), actor, action, project, env, name],
            )
            .map_err(|e| self.fail(e))?;
        Ok(())
    }

    pub fn audit_log(&self) -> Result<Vec<serde_json::Value>, String> {
        let mut statement = self
            .db
            .prepare("SELECT at, actor, action, project, env, name FROM audit ORDER BY at, rowid")
            .map_err(|e| self.fail(e))?;
        let rows = statement
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "at": row.get::<_, i64>(0)?,
                    "actor": row.get::<_, String>(1)?,
                    "action": row.get::<_, String>(2)?,
                    "project": row.get::<_, String>(3)?,
                    "env": row.get::<_, String>(4)?,
                    "key": row.get::<_, Option<String>>(5)?,
                }))
            })
            .map_err(|e| self.fail(e))?;
        rows.collect::<rusqlite::Result<Vec<serde_json::Value>>>()
            .map_err(|e| self.fail(e))
    }
}

fn context(project: &str, env: &str) -> String {
    format!("secrets/{project}/{env}")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
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
    std::env::temp_dir().join(format!("heimdall-{}.db", crypto::random_hex(6).unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open(temp_root(), Key::from_hex(&"ab".repeat(32)).unwrap()).unwrap()
    }

    fn dump(store: &Store) -> Vec<u8> {
        let path: String = store
            .db
            .query_row("PRAGMA database_list", [], |row| row.get(2))
            .unwrap();
        let mut out = std::fs::read(&path).unwrap();
        if let Ok(wal) = std::fs::read(format!("{path}-wal")) {
            out.extend_from_slice(&wal);
        }
        out
    }

    #[test]
    fn a_secret_survives_a_reopen() {
        let path = temp_root();
        let key = Key::from_hex(&"ab".repeat(32)).unwrap();
        Store::open(path.clone(), key.clone())
            .unwrap()
            .set("bifrost", "dev", "STRIPE_KEY", "sk_test_123", "berti")
            .unwrap();
        let reopened = Store::open(path, key).unwrap();
        assert_eq!(
            reopened.secrets("bifrost", "dev").unwrap()["STRIPE_KEY"],
            "sk_test_123"
        );
    }

    #[test]
    fn the_value_never_lands_in_clear() {
        let store = store();
        store
            .set("bifrost", "dev", "DB_PASSWORD", "hunter2", "berti")
            .unwrap();
        let raw = dump(&store);
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
    fn bad_names_are_rejected() {
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
        let raw = dump(&store);
        assert!(!raw.windows(plain.len()).any(|w| w == plain.as_bytes()));
    }

    #[test]
    fn a_used_token_says_so() {
        let store = store();
        let (token, _) = store
            .create_token("agente", "bifrost", "dev", None, "berti")
            .unwrap();
        assert!(store.tokens().unwrap()[0].last_used.is_none());
        store.touch(&token.id).unwrap();
        assert!(store.tokens().unwrap()[0].last_used.is_some());
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
        assert!(!String::from_utf8_lossy(&dump(&store)).contains("hunter2"));
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
