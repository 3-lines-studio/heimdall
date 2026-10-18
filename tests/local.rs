use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn temp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "heimdall-local-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

fn heimdall(dir: &Path, args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heimdall"))
        .args(args)
        .current_dir(cwd)
        .env("HEIMDALL_DIR", dir)
        .env_remove("HEIMDALL_URL")
        .env_remove("HEIMDALL_TOKEN")
        .env_remove("HEIMDALL_MASTER_KEY")
        .output()
        .expect("no corrió heimdall")
}

fn ok(dir: &Path, args: &[&str], cwd: &Path) -> String {
    let output = heimdall(dir, args, cwd);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn repo(root: &Path, project: &str) -> PathBuf {
    let dir = root.join("repo");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("heimdall.yaml"),
        format!("setup:\n  - project: {project}\n    config: dev\n"),
    )
    .unwrap();
    dir
}

#[test]
fn a_command_gets_its_secrets_without_a_server() {
    let root = temp();
    let vault = root.join("vault");
    let repo = repo(&root, "bifrost");

    ok(&vault, &["set", "STRIPE_KEY=sk_test_1"], &repo);
    let value = ok(
        &vault,
        &["run", "--", "sh", "-c", "printf %s \"$STRIPE_KEY\""],
        &repo,
    );

    assert_eq!(value, "sk_test_1");
    assert!(vault.join("heimdall.db").is_file());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_child_never_sees_the_master_key() {
    let root = temp();
    let vault = root.join("vault");
    let repo = repo(&root, "bifrost");

    ok(&vault, &["set", "A=1"], &repo);
    let env = ok(&vault, &["run", "--", "sh", "-c", "printenv"], &repo);

    assert!(env.contains("A=1"), "{env}");
    assert!(!env.contains("HEIMDALL_MASTER_KEY"), "{env}");
    assert!(!env.contains("HEIMDALL_TOKEN"), "{env}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn another_project_does_not_get_these_secrets() {
    let root = temp();
    let vault = root.join("vault");
    let repo = repo(&root, "bifrost");

    ok(&vault, &["set", "STRIPE_KEY=sk_test_1"], &repo);
    let value = ok(
        &vault,
        &[
            "run",
            "--project",
            "axe",
            "--",
            "sh",
            "-c",
            "printf %s \"$STRIPE_KEY\"",
        ],
        &repo,
    );

    assert_eq!(value, "");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_variable_is_stored_as_one() {
    let root = temp();
    let vault = root.join("vault");
    let repo = repo(&root, "bifrost");

    ok(&vault, &["set", "AUTHOR=Jimmy", "--var"], &repo);
    ok(&vault, &["set", "TOKEN=s3cr3t"], &repo);
    let store = heimdall::store::Store::open_dir(&vault).unwrap();

    assert!(store.plain("bifrost", "dev").unwrap().contains("AUTHOR"));
    assert!(!store.plain("bifrost", "dev").unwrap().contains("TOKEN"));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_missing_vault_says_where_it_looked() {
    let root = temp();
    let repo = repo(&root, "bifrost");
    let output = heimdall(&root.join("nada"), &["ls"], &repo);

    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(error.contains("nada"), "{error}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_master_key_that_is_not_the_one_on_disk_says_so() {
    let root = temp();
    let vault = root.join("vault");
    let repo = repo(&root, "bifrost");

    ok(&vault, &["set", "A=1"], &repo);
    let output = Command::new(env!("CARGO_BIN_EXE_heimdall"))
        .args(["ls"])
        .current_dir(&repo)
        .env("HEIMDALL_DIR", &vault)
        .env("HEIMDALL_MASTER_KEY", "cd".repeat(32))
        .env_remove("HEIMDALL_URL")
        .output()
        .unwrap();

    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(error.contains("no es la de"), "{error}");
    std::fs::remove_dir_all(&root).unwrap();
}
