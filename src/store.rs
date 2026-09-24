use crate::crypto::{self, Key};
use rusqlite::{params, Connection, OptionalExtension};
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
    admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
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
CREATE TABLE IF NOT EXISTS environments (
    project TEXT NOT NULL,
    env TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project, env)
);
CREATE TABLE IF NOT EXISTS logins (
    hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
";

const COLUMNS: &str = "id, name, project, env, keys, admin, created_at, expires_at, last_used";

#[derive(Debug)]
pub enum Error {
    Bad(String),
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Error {
        Error::Internal(error.to_string())
    }
}

fn bad<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Bad(message.into()))
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Token {
    pub id: String,
    pub name: String,
    pub project: String,
    pub env: String,
    pub keys: Option<Vec<String>>,
    pub admin: bool,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used: Option<i64>,
}

pub struct NewToken {
    pub name: String,
    pub project: String,
    pub env: String,
    pub keys: Option<Vec<String>>,
    pub admin: bool,
    pub ttl: Option<i64>,
}

pub struct Store {
    db: Connection,
    key: Key,
}

impl Store {
    pub fn open(path: PathBuf, key: Key) -> std::result::Result<Store, String> {
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

    /// Lo que se declaró más lo que ya tiene secretos: los entornos que existían
    /// antes de que hubiera una tabla siguen apareciendo sin migrar nada.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut statement = self.db.prepare(
            "SELECT project || '/' || env FROM environments
             UNION
             SELECT DISTINCT project || '/' || env FROM secrets
             ORDER BY 1",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    }

    pub fn create_environment(&self, project: &str, env: &str, actor: &str) -> Result<()> {
        slug(project)?;
        slug(env)?;
        self.db.execute(
            "INSERT OR IGNORE INTO environments (project, env, created_at) VALUES (?1, ?2, ?3)",
            params![project, env, now()],
        )?;
        self.audit(actor, "env-create", project, env, None)
    }

    /// Los tokens que apuntaban al entorno se van con él: no tienen sentido
    /// sobre algo que dejó de existir.
    pub fn drop_environment(&self, project: &str, env: &str, actor: &str) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        let secrets = self.db.execute(
            "DELETE FROM secrets WHERE project = ?1 AND env = ?2",
            params![project, env],
        )?;
        let declared = self.db.execute(
            "DELETE FROM environments WHERE project = ?1 AND env = ?2",
            params![project, env],
        )?;
        let tokens = self.db.execute(
            "DELETE FROM tokens WHERE project = ?1 AND env = ?2",
            params![project, env],
        )?;
        if secrets == 0 && declared == 0 && tokens == 0 {
            return bad(format!("{project}/{env} no existe"));
        }
        self.audit(actor, "env-drop", project, env, None)?;
        tx.commit()?;
        Ok(())
    }

    pub fn drop_project(&self, project: &str, actor: &str) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        let secrets = self
            .db
            .execute("DELETE FROM secrets WHERE project = ?1", params![project])?;
        let declared = self.db.execute(
            "DELETE FROM environments WHERE project = ?1",
            params![project],
        )?;
        let tokens = self
            .db
            .execute("DELETE FROM tokens WHERE project = ?1", params![project])?;
        if secrets == 0 && declared == 0 && tokens == 0 {
            return bad(format!("{project} no existe"));
        }
        self.audit(actor, "project-drop", project, "", None)?;
        tx.commit()?;
        Ok(())
    }

    /// Renombrar mueve la clave derivada y el dato asociado, así que hay que
    /// volver a sellar cada valor: el sobre viejo no abre en el nombre nuevo.
    pub fn rename_environment(
        &self,
        project: &str,
        env: &str,
        to: &str,
        actor: &str,
    ) -> Result<()> {
        slug(to)?;
        if env == to {
            return Ok(());
        }
        let moved = self.secrets(project, env)?;
        if !self.secrets(project, to)?.is_empty() {
            return bad(format!("{project}/{to} ya tiene secretos"));
        }
        let tx = self.db.unchecked_transaction()?;
        for (name, value) in &moved {
            let sealed = self
                .key
                .derive(&context(project, to))
                .seal(value.as_bytes(), aad(project, to, name).as_bytes())
                .map_err(Error::Internal)?;
            self.db.execute(
                "INSERT INTO secrets (project, env, name, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![project, to, name, sealed, now()],
            )?;
        }
        self.db.execute(
            "DELETE FROM secrets WHERE project = ?1 AND env = ?2",
            params![project, env],
        )?;
        self.db.execute(
            "DELETE FROM environments WHERE project = ?1 AND env = ?2",
            params![project, to],
        )?;
        self.db.execute(
            "UPDATE environments SET env = ?1 WHERE project = ?2 AND env = ?3",
            params![to, project, env],
        )?;
        self.audit(actor, "env-rename", project, to, Some(env))?;
        tx.commit()?;
        Ok(())
    }

    pub fn rename_project(&self, project: &str, to: &str, actor: &str) -> Result<()> {
        slug(to)?;
        if project == to {
            return Ok(());
        }
        if self
            .names()?
            .iter()
            .any(|name| name.starts_with(&format!("{to}/")))
        {
            return bad(format!("{to} ya existe"));
        }
        let mut statement = self.db.prepare(
            "SELECT env FROM environments WHERE project = ?1
             UNION
             SELECT DISTINCT env FROM secrets WHERE project = ?1",
        )?;
        let envs: Vec<String> = statement
            .query_map(params![project], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        drop(statement);
        if envs.is_empty() {
            return bad(format!("{project} no existe"));
        }
        let tx = self.db.unchecked_transaction()?;
        for env in &envs {
            for (name, value) in &self.secrets(project, env)? {
                let sealed = self
                    .key
                    .derive(&context(to, env))
                    .seal(value.as_bytes(), aad(to, env, name).as_bytes())
                    .map_err(Error::Internal)?;
                self.db.execute(
                    "INSERT INTO secrets (project, env, name, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![to, env, name, sealed, now()],
                )?;
            }
        }
        self.db
            .execute("DELETE FROM secrets WHERE project = ?1", params![project])?;
        self.db.execute(
            "UPDATE environments SET project = ?1 WHERE project = ?2",
            params![to, project],
        )?;
        self.audit(actor, "project-rename", to, "", Some(project))?;
        tx.commit()?;
        Ok(())
    }

    pub fn secrets(&self, project: &str, env: &str) -> Result<BTreeMap<String, String>> {
        let subkey = self.key.derive(&context(project, env));
        let mut statement = self
            .db
            .prepare("SELECT name, value FROM secrets WHERE project = ?1 AND env = ?2")?;
        let rows = statement.query_map(params![project, env], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (name, value) = row?;
            let plain = subkey
                .open(&value, aad(project, env, &name).as_bytes())
                .map_err(Error::Internal)?;
            let text = String::from_utf8(plain)
                .map_err(|_| Error::Internal(format!("{name} no es texto")))?;
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
    ) -> Result<()> {
        slug(project)?;
        slug(env)?;
        key_name(name)?;
        if value.len() > MAX_VALUE {
            return bad(format!("el valor pasa los {MAX_VALUE} bytes"));
        }
        let sealed = self
            .key
            .derive(&context(project, env))
            .seal(value.as_bytes(), aad(project, env, name).as_bytes())
            .map_err(Error::Internal)?;
        let tx = self.db.unchecked_transaction()?;
        self.db.execute(
            "INSERT INTO secrets (project, env, name, value, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (project, env, name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![project, env, name, sealed, now()],
        )?;
        self.audit(actor, "set", project, env, Some(name))?;
        tx.commit()?;
        Ok(())
    }

    pub fn unset(&self, project: &str, env: &str, name: &str, actor: &str) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        let removed = self.db.execute(
            "DELETE FROM secrets WHERE project = ?1 AND env = ?2 AND name = ?3",
            params![project, env, name],
        )?;
        if removed == 0 {
            return bad(format!("{name} no está en {project}/{env}"));
        }
        self.audit(actor, "unset", project, env, Some(name))?;
        tx.commit()?;
        Ok(())
    }

    pub fn tokens(&self) -> Result<Vec<Token>> {
        let mut statement = self
            .db
            .prepare(&format!("SELECT {COLUMNS} FROM tokens ORDER BY created_at"))?;
        let rows = statement.query_map([], row_token)?;
        Ok(rows.collect::<rusqlite::Result<Vec<Token>>>()?)
    }

    pub fn create_token(&self, new: NewToken, actor: &str) -> Result<(Token, String)> {
        if new.admin {
            if new.keys.is_some() {
                return bad("un token de administración ve todo");
            }
        } else {
            slug_or_all(&new.project)?;
            slug_or_all(&new.env)?;
        }
        if new.name.trim().is_empty() {
            return bad("el token necesita un nombre");
        }
        let plain = format!("hd_{}", crypto::random_hex(24).map_err(Error::Internal)?);
        let token = Token {
            id: crypto::random_hex(6).map_err(Error::Internal)?,
            name: new.name,
            project: new.project,
            env: new.env,
            keys: new.keys,
            admin: new.admin,
            created_at: now(),
            expires_at: new.ttl.map(|ttl| now() + ttl),
            last_used: None,
        };
        let keys = token
            .keys
            .as_ref()
            .map(|keys| serde_json::to_string(keys).unwrap_or_default());
        let tx = self.db.unchecked_transaction()?;
        self.db.execute(
            "INSERT INTO tokens (id, name, project, env, keys, hash, admin, created_at, expires_at, last_used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                token.id,
                token.name,
                token.project,
                token.env,
                keys,
                crypto::hash(&plain),
                token.admin as i64,
                token.created_at,
                token.expires_at
            ],
        )?;
        self.audit(
            actor,
            "token-create",
            &token.project,
            &token.env,
            Some(&token.name),
        )?;
        tx.commit()?;
        Ok((token, plain))
    }

    pub fn revoke(&self, id: &str, actor: &str) -> Result<Token> {
        let token = self
            .tokens()?
            .into_iter()
            .find(|token| token.id == id)
            .ok_or_else(|| Error::Bad(format!("no hay token {id}")))?;
        let tx = self.db.unchecked_transaction()?;
        self.db
            .execute("DELETE FROM tokens WHERE id = ?1", params![id])?;
        self.audit(
            actor,
            "token-revoke",
            &token.project,
            &token.env,
            Some(&token.name),
        )?;
        tx.commit()?;
        Ok(token)
    }

    pub fn find(&self, plain: &str) -> Result<Option<Token>> {
        let presented = crypto::hash(plain);
        let mut statement = self
            .db
            .prepare(&format!("SELECT {COLUMNS}, hash FROM tokens"))?;
        let rows =
            statement.query_map([], |row| Ok((row_token(row)?, row.get::<_, String>(9)?)))?;
        for row in rows {
            let (token, hash) = row?;
            if crypto::equal(&hash, &presented) {
                if token.expires_at.is_some_and(|expires| expires <= now()) {
                    return bad("ese token venció");
                }
                return Ok(Some(token));
            }
        }
        Ok(None)
    }

    pub fn touch(&self, id: &str) -> Result<()> {
        self.db.execute(
            "UPDATE tokens SET last_used = ?2 WHERE id = ?1",
            params![id, now()],
        )?;
        Ok(())
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        project: &str,
        env: &str,
        name: Option<&str>,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO audit (at, actor, action, project, env, name) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![now(), actor, action, project, env, name],
        )?;
        Ok(())
    }

    pub fn audit_log(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut statement = self.db.prepare(
            "SELECT at, actor, action, project, env, name FROM audit ORDER BY at DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "at": row.get::<_, i64>(0)?,
                "actor": row.get::<_, String>(1)?,
                "action": row.get::<_, String>(2)?,
                "project": row.get::<_, String>(3)?,
                "env": row.get::<_, String>(4)?,
                "key": row.get::<_, Option<String>>(5)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<serde_json::Value>>>()?)
    }

    pub fn create_login(&self, email: &str, ttl: i64) -> Result<String> {
        let plain = crypto::random_hex(24).map_err(Error::Internal)?;
        self.db.execute(
            "INSERT INTO logins (hash, email, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![crypto::hash(&plain), email, now(), now() + ttl],
        )?;
        Ok(plain)
    }

    pub fn consume_login(&self, plain: &str) -> Result<String> {
        let hash = crypto::hash(plain);
        let email: Option<String> = self
            .db
            .query_row(
                "SELECT email FROM logins WHERE hash = ?1 AND expires_at > ?2",
                params![hash, now()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(email) = email else {
            return bad("ese link ya no sirve");
        };
        self.db
            .execute("DELETE FROM logins WHERE hash = ?1", params![hash])?;
        Ok(email)
    }

    pub fn asked_recently(&self, email: &str, within: i64) -> Result<bool> {
        let last: Option<i64> = self.db.query_row(
            "SELECT MAX(created_at) FROM logins WHERE email = ?1",
            params![email],
            |row| row.get(0),
        )?;
        Ok(last.is_some_and(|last| now() - last < within))
    }

    pub fn create_session(&self, email: &str, ttl: i64) -> Result<String> {
        let plain = crypto::random_hex(24).map_err(Error::Internal)?;
        self.db.execute(
            "INSERT INTO sessions (hash, email, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![crypto::hash(&plain), email, now(), now() + ttl],
        )?;
        Ok(plain)
    }

    pub fn session(&self, plain: &str) -> Result<Option<String>> {
        let email = self
            .db
            .query_row(
                "SELECT email FROM sessions WHERE hash = ?1 AND expires_at > ?2",
                params![crypto::hash(plain), now()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(email)
    }

    pub fn drop_session(&self, plain: &str) -> Result<()> {
        self.db.execute(
            "DELETE FROM sessions WHERE hash = ?1",
            params![crypto::hash(plain)],
        )?;
        Ok(())
    }

    pub fn sweep(&self) -> Result<()> {
        let now = now();
        self.db
            .execute("DELETE FROM logins WHERE expires_at <= ?1", params![now])?;
        self.db
            .execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
        Ok(())
    }
}

fn row_token(row: &rusqlite::Row) -> rusqlite::Result<Token> {
    let keys: Option<String> = row.get("keys")?;
    Ok(Token {
        id: row.get("id")?,
        name: row.get("name")?,
        project: row.get("project")?,
        env: row.get("env")?,
        keys: keys.and_then(|text| serde_json::from_str(&text).ok()),
        admin: row.get::<_, i64>("admin")? != 0,
        created_at: row.get("created_at")?,
        expires_at: row.get("expires_at")?,
        last_used: row.get("last_used")?,
    })
}

fn context(project: &str, env: &str) -> String {
    format!("secrets/{project}/{env}")
}

/// El sobre cifrado lleva su nombre adentro, así que moverlo de fila no lo
/// convierte en otro secreto.
fn aad(project: &str, env: &str, name: &str) -> String {
    format!("secrets/{project}/{env}/{name}")
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn slug_or_all(name: &str) -> Result<()> {
    if name == "*" {
        return Ok(());
    }
    slug(name)
}

pub fn slug(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return bad(format!("«{name}» tiene que medir entre 1 y 64"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return bad(format!(
            "«{name}» sólo acepta minúsculas, números, guiones y guiones bajos"
        ));
    }
    Ok(())
}

fn key_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return bad("la clave no puede estar vacía");
    };
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return bad(format!("«{name}» no es un nombre de variable válido"));
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

    fn new_token(name: &str, project: &str, env: &str) -> NewToken {
        NewToken {
            name: name.to_string(),
            project: project.to_string(),
            env: env.to_string(),
            keys: None,
            admin: false,
            ttl: None,
        }
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
        assert!(!dump(&store).windows(7).any(|w| w == b"hunter2"));
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
    fn a_failed_unset_leaves_no_audit_row() {
        let store = store();
        assert!(store.unset("bifrost", "dev", "A", "berti").is_err());
        assert!(store.audit_log(10).unwrap().is_empty());
    }

    #[test]
    fn only_the_matching_token_is_found() {
        let store = store();
        let (token, plain) = store
            .create_token(new_token("agente", "bifrost", "dev"), "berti")
            .unwrap();
        assert!(store.find("hd_nada").unwrap().is_none());
        assert_eq!(store.find(&plain).unwrap().unwrap().id, token.id);
    }

    #[test]
    fn a_revoked_token_is_gone() {
        let store = store();
        let (token, plain) = store
            .create_token(new_token("agente", "bifrost", "dev"), "berti")
            .unwrap();
        store.revoke(&token.id, "berti").unwrap();
        assert!(store.find(&plain).unwrap().is_none());
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let store = store();
        let mut new = new_token("agente", "bifrost", "dev");
        new.ttl = Some(-1);
        let (_, plain) = store.create_token(new, "berti").unwrap();
        assert!(store.find(&plain).is_err());
    }

    #[test]
    fn a_token_without_ttl_does_not_expire() {
        let store = store();
        let (_, plain) = store
            .create_token(new_token("agente", "bifrost", "dev"), "berti")
            .unwrap();
        let token = store.find(&plain).unwrap().unwrap();
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn an_admin_token_is_marked_as_one() {
        let store = store();
        let mut new = new_token("jimmy", "", "");
        new.admin = true;
        let (token, plain) = store.create_token(new, "berti").unwrap();
        assert!(token.admin);
        assert!(store.find(&plain).unwrap().unwrap().admin);
    }

    #[test]
    fn the_token_hash_never_lands_in_clear() {
        let store = store();
        let (_, plain) = store
            .create_token(new_token("agente", "bifrost", "dev"), "berti")
            .unwrap();
        let raw = dump(&store);
        assert!(!raw.windows(plain.len()).any(|w| w == plain.as_bytes()));
    }

    #[test]
    fn a_used_token_says_so() {
        let store = store();
        let (token, _) = store
            .create_token(new_token("agente", "bifrost", "dev"), "berti")
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
        let log = store.audit_log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0]["key"], "DB_PASSWORD");
        assert!(!String::from_utf8_lossy(&dump(&store)).contains("hunter2"));
    }

    #[test]
    fn the_audit_is_newest_first_and_capped() {
        let store = store();
        for name in ["A", "B", "C"] {
            store.set("bifrost", "dev", name, "1", "berti").unwrap();
        }
        let log = store.audit_log(2).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0]["key"], "C");
        assert_eq!(log[1]["key"], "B");
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

    #[test]
    fn an_environment_can_exist_before_its_first_secret() {
        let store = store();
        store.create_environment("bifrost", "dev", "berti").unwrap();
        assert_eq!(store.names().unwrap(), vec!["bifrost/dev"]);
        assert!(store.secrets("bifrost", "dev").unwrap().is_empty());
    }

    #[test]
    fn the_listing_also_shows_what_was_there_before_the_table() {
        let store = store();
        store.set("axe", "dev", "A", "1", "berti").unwrap();
        store.create_environment("bifrost", "dev", "berti").unwrap();
        assert_eq!(store.names().unwrap(), vec!["axe/dev", "bifrost/dev"]);
    }

    #[test]
    fn dropping_an_environment_takes_its_secrets() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "A", "2", "berti").unwrap();
        store.drop_environment("bifrost", "dev", "berti").unwrap();
        assert_eq!(store.names().unwrap(), vec!["bifrost/prod"]);
        assert!(store.secrets("bifrost", "dev").unwrap().is_empty());
        assert_eq!(store.secrets("bifrost", "prod").unwrap()["A"], "2");
    }

    #[test]
    fn dropping_an_empty_environment_works_too() {
        let store = store();
        store.create_environment("bifrost", "dev", "berti").unwrap();
        store.drop_environment("bifrost", "dev", "berti").unwrap();
        assert!(store.names().unwrap().is_empty());
        assert!(store.drop_environment("bifrost", "dev", "berti").is_err());
    }

    #[test]
    fn dropping_a_project_takes_everything() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "A", "2", "berti").unwrap();
        store.set("axe", "dev", "A", "3", "berti").unwrap();
        store.drop_project("bifrost", "berti").unwrap();
        assert_eq!(store.names().unwrap(), vec!["axe/dev"]);
        assert!(store.drop_project("bifrost", "berti").is_err());
    }

    #[test]
    fn dropping_an_environment_takes_its_tokens() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        let nuevos = NewToken {
            name: "agente".to_string(),
            project: "bifrost".to_string(),
            env: "dev".to_string(),
            keys: None,
            admin: false,
            ttl: None,
        };
        let (_, plain) = store.create_token(nuevos, "berti").unwrap();
        store.drop_environment("bifrost", "dev", "berti").unwrap();
        assert!(store.find(&plain).unwrap().is_none());
        assert!(store.tokens().unwrap().is_empty());
    }

    #[test]
    fn dropping_a_project_leaves_the_admin_tokens_alone() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        let nuevos = NewToken {
            name: "agente".to_string(),
            project: "bifrost".to_string(),
            env: "dev".to_string(),
            keys: None,
            admin: false,
            ttl: None,
        };
        let (_, agente) = store.create_token(nuevos, "berti").unwrap();
        let admin = NewToken {
            name: "jimmy".to_string(),
            project: String::new(),
            env: String::new(),
            keys: None,
            admin: true,
            ttl: None,
        };
        let (_, plain) = store.create_token(admin, "berti").unwrap();
        store.drop_project("bifrost", "berti").unwrap();
        assert!(store.find(&plain).unwrap().is_some());
        assert!(store.find(&agente).unwrap().is_none());
    }

    #[test]
    fn renaming_an_environment_keeps_its_values_working() {
        let store = store();
        store
            .set("bifrost", "dev", "STRIPE_KEY", "sk_test_123", "berti")
            .unwrap();
        store
            .rename_environment("bifrost", "dev", "testing", "berti")
            .unwrap();
        assert_eq!(store.names().unwrap(), vec!["bifrost/testing"]);
        assert_eq!(
            store.secrets("bifrost", "testing").unwrap()["STRIPE_KEY"],
            "sk_test_123"
        );
        assert!(store.secrets("bifrost", "dev").unwrap().is_empty());
    }

    #[test]
    fn renaming_an_environment_into_a_taken_one_is_refused() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "A", "2", "berti").unwrap();
        assert!(store
            .rename_environment("bifrost", "dev", "prod", "berti")
            .is_err());
        assert_eq!(store.secrets("bifrost", "prod").unwrap()["A"], "2");
    }

    #[test]
    fn renaming_a_project_keeps_every_value_working() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("bifrost", "prod", "B", "2", "berti").unwrap();
        store.rename_project("bifrost", "puente", "berti").unwrap();
        assert_eq!(store.names().unwrap(), vec!["puente/dev", "puente/prod"]);
        assert_eq!(store.secrets("puente", "dev").unwrap()["A"], "1");
        assert_eq!(store.secrets("puente", "prod").unwrap()["B"], "2");
        assert!(store
            .names()
            .unwrap()
            .iter()
            .all(|name| !name.starts_with("bifrost")));
    }

    #[test]
    fn renaming_a_project_onto_another_is_refused() {
        let store = store();
        store.set("bifrost", "dev", "A", "1", "berti").unwrap();
        store.set("axe", "dev", "A", "2", "berti").unwrap();
        assert!(store.rename_project("bifrost", "axe", "berti").is_err());
        assert_eq!(store.secrets("axe", "dev").unwrap()["A"], "2");
    }

    #[test]
    fn renaming_an_empty_project_is_refused() {
        let store = store();
        assert!(store.rename_project("nada", "otro", "berti").is_err());
    }

    #[test]
    fn a_login_link_works_once() {
        let store = store();
        let link = store.create_login("berti@ejemplo.com", 900).unwrap();
        assert_eq!(store.consume_login(&link).unwrap(), "berti@ejemplo.com");
        assert!(store.consume_login(&link).is_err());
    }

    #[test]
    fn an_expired_login_link_is_refused() {
        let store = store();
        let link = store.create_login("berti@ejemplo.com", -1).unwrap();
        assert!(store.consume_login(&link).is_err());
    }

    #[test]
    fn a_second_link_is_a_cooldown_too_soon() {
        let store = store();
        assert!(!store.asked_recently("berti@ejemplo.com", 60).unwrap());
        store.create_login("berti@ejemplo.com", 900).unwrap();
        assert!(store.asked_recently("berti@ejemplo.com", 60).unwrap());
        assert!(!store.asked_recently("otro@ejemplo.com", 60).unwrap());
    }

    #[test]
    fn a_session_lives_and_dies() {
        let store = store();
        let cookie = store.create_session("berti@ejemplo.com", 60).unwrap();
        assert_eq!(
            store.session(&cookie).unwrap().unwrap(),
            "berti@ejemplo.com"
        );
        store.drop_session(&cookie).unwrap();
        assert!(store.session(&cookie).unwrap().is_none());
    }

    #[test]
    fn an_expired_session_is_no_session() {
        let store = store();
        let cookie = store.create_session("berti@ejemplo.com", -1).unwrap();
        assert!(store.session(&cookie).unwrap().is_none());
    }

    #[test]
    fn sweeping_clears_what_expired() {
        let store = store();
        let login = store.create_login("berti@ejemplo.com", -1).unwrap();
        let session = store.create_session("berti@ejemplo.com", -1).unwrap();
        let live = store.create_session("berti@ejemplo.com", 60).unwrap();
        store.sweep().unwrap();
        assert!(store.consume_login(&login).is_err());
        assert!(store.session(&session).unwrap().is_none());
        assert!(store.session(&live).unwrap().is_some());
    }

    #[test]
    fn neither_the_login_nor_the_session_lands_in_clear() {
        let store = store();
        let login = store.create_login("berti@ejemplo.com", 900).unwrap();
        let session = store.create_session("berti@ejemplo.com", 900).unwrap();
        let raw = dump(&store);
        assert!(!raw.windows(login.len()).any(|w| w == login.as_bytes()));
        assert!(!raw.windows(session.len()).any(|w| w == session.as_bytes()));
    }
}
