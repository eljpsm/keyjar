//! End-to-end tests of the keyjar binary in a sandboxed environment. Every
//! run gets a fresh HOME and XDG tree and loses the developer's real
//! KEYJAR_* variables. PTY tests cover terminal-only safety checks.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A throwaway HOME. Tests run in parallel in one process, so each gets its
/// own tree and reaches the store only through the binary.
struct Sandbox {
    // Held only to keep the directory alive; dropping it deletes the tree.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        Sandbox { dir, home }
    }

    /// env_clear is the point: a developer's real KEYJAR_STORE or
    /// KEYJAR_IDENTITY would otherwise aim the tests at their own secrets.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyjar"));
        cmd.args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CONFIG_HOME", self.home.join("config"));
        // cargo llvm-cov needs subprocess profiles in its own directory.
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn run_with_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Arrange a stored value. Panics on failure so a broken setup does not
    /// masquerade as the assertion under test.
    fn set(&self, name: &str, value: &[u8]) {
        let out = self.run_with_stdin(&["set", name], value);
        assert!(out.status.success(), "set {name}: {}", stderr(&out));
    }

    fn store_dir(&self) -> PathBuf {
        self.home.join("data/keyjar")
    }
}

/// keyjar behind a real terminal. Nothing else exercises the tty branches:
/// hidden input, the get refusal, the rm prompt.
struct PtyChild {
    child: Child,
    writer: File,
    /// A slave handle kept past spawn so termios can be read after exit, and
    /// so the pty does not hang up while the child is still writing.
    slave: File,
    chunks: Receiver<Vec<u8>>,
    reader: JoinHandle<()>,
    transcript: Vec<u8>,
}

struct PtyOutput {
    status: ExitStatus,
    /// Everything the terminal saw, which is stdout, stderr, and any echo,
    /// interleaved. A pty gives no way to separate them, so tests search it
    /// for a secret rather than matching a stream exactly.
    transcript: Vec<u8>,
    echo_enabled: bool,
}

impl PtyChild {
    /// Drain the master on a thread. A child that fills the pty buffer blocks
    /// on write, so reading only after exit would deadlock.
    fn spawn(mut command: Command) -> Self {
        let pty = nix::pty::openpty(None, None).unwrap();
        let master = File::from(pty.master);
        let slave = File::from(pty.slave);
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        let child = command.spawn().unwrap();
        let writer = master.try_clone().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut master = master;
            let mut buf = [0; 1024];
            while let Ok(count) = master.read(&mut buf) {
                if count == 0 || sender.send(buf[..count].to_vec()).is_err() {
                    break;
                }
            }
        });
        PtyChild {
            child,
            writer,
            slave,
            chunks,
            reader,
            transcript: Vec::new(),
        }
    }

    /// Wait for a prompt before answering it. Writing early would race the
    /// child's termios setup and the keystrokes could land while echo is on.
    /// The deadline turns a hang into a named failure.
    fn read_until(&mut self, expected: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self
            .transcript
            .windows(expected.len())
            .any(|window| window == expected)
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let chunk = match self.chunks.recv_timeout(remaining) {
                Ok(chunk) => chunk,
                Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!("PTY output did not contain {:?}", expected);
                }
            };
            self.transcript.extend(chunk);
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
    }

    /// Reap the child, then read the terminal it leaves behind. The echo flag
    /// has to be sampled here, after exit and before the pty is dropped: it is
    /// the evidence that the NoEcho guard restored the caller's terminal.
    fn finish(mut self) -> PtyOutput {
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                let _ = self.child.wait();
                panic!("PTY child did not exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut termios) },
            0
        );
        let echo_enabled = termios.c_lflag & libc::ECHO != 0;
        drop(self.slave);
        drop(self.writer);
        self.reader.join().unwrap();
        while let Ok(chunk) = self.chunks.try_recv() {
            self.transcript.extend(chunk);
        }
        PtyOutput {
            status,
            transcript: self.transcript,
            echo_enabled,
        }
    }
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap()
}

fn stdout(out: &Output) -> &str {
    std::str::from_utf8(&out.stdout).unwrap()
}

fn stderr(out: &Output) -> &str {
    std::str::from_utf8(&out.stderr).unwrap()
}

#[test]
fn terminal_set_hides_input_and_restores_echo() {
    let jar = Sandbox::new();
    let mut child = PtyChild::spawn(jar.command(&["set", "terminal"]));
    child.read_until(b"value for terminal: ");
    child.write(b"hidden-value\n");
    let out = child.finish();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.transcript)
    );
    // The secret must not reach the screen, and the terminal must be handed
    // back with echo on. A shell left echo-less outlives the process.
    assert!(!out.transcript.windows(12).any(|w| w == b"hidden-value"));
    assert!(out.echo_enabled);
    assert_eq!(jar.run(&["get", "terminal"]).stdout, b"hidden-value");
}

#[test]
fn terminal_get_requires_force() {
    let jar = Sandbox::new();
    jar.set("terminal", b"secret\n");

    let out = PtyChild::spawn(jar.command(&["get", "terminal"])).finish();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.transcript).contains("stdout is a terminal"));
    assert!(!out.transcript.windows(6).any(|w| w == b"secret"));

    let out = PtyChild::spawn(jar.command(&["get", "terminal", "--force"])).finish();
    assert!(out.status.success());
    assert!(out.transcript.windows(6).any(|w| w == b"secret"));
}

#[test]
fn terminal_rm_honors_decline_and_confirmation() {
    let jar = Sandbox::new();
    jar.set("terminal", b"secret\n");

    let mut child = PtyChild::spawn(jar.command(&["rm", "terminal"]));
    child.read_until(b"remove terminal? [y/N] ");
    child.write(b"n\n");
    assert!(child.finish().status.success());
    assert!(jar.store_dir().join("terminal.age").exists());

    let mut child = PtyChild::spawn(jar.command(&["rm", "terminal"]));
    child.read_until(b"remove terminal? [y/N] ");
    child.write(b"YES\n");
    assert!(child.finish().status.success());
    assert!(!jar.store_dir().join("terminal.age").exists());
}

#[test]
fn set_then_get_round_trips_the_exact_bytes() {
    let jar = Sandbox::new();
    jar.set("openai", b"sk-123\n");

    let out = jar.run(&["get", "openai"]);
    assert_eq!(code(&out), 0);
    // The newline that ended the input line is not part of the value.
    assert_eq!(out.stdout, b"sk-123");

    let out = jar.run(&["get", "openai", "-n"]);
    assert_eq!(out.stdout, b"sk-123\n");
}

#[test]
fn the_identity_appears_private_and_age_compatible() {
    let jar = Sandbox::new();
    let value = b"plaintext-marker-value";
    jar.set("openai", value);

    let identity = jar.home.join("config/keyjar/identity");
    let contents = std::fs::read_to_string(&identity).unwrap();
    assert!(contents.contains("AGE-SECRET-KEY-1"), "{contents}");
    assert_eq!(identity.metadata().unwrap().mode() & 0o777, 0o600);
    let public = contents
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap();
    let marker = std::fs::read_to_string(jar.store_dir().join(".keyjar-recipient")).unwrap();
    assert_eq!(marker, format!("{public}\n"));

    // The ciphertext must not leak the plaintext.
    let ciphertext = std::fs::read(jar.store_dir().join("openai.age")).unwrap();
    assert!(!ciphertext.windows(value.len()).any(|w| w == value));
    assert!(ciphertext.starts_with(b"age-encryption.org/v1"));
}

#[test]
fn a_missing_entry_fails_with_a_message_and_empty_stdout() {
    let jar = Sandbox::new();
    jar.set("other", b"x\n");
    let out = jar.run(&["get", "missing"]);
    assert_eq!(code(&out), 1);
    assert!(out.stdout.is_empty());
    assert!(
        stderr(&out).contains("no entry named missing"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn multiline_set_keeps_every_byte_and_show_adds_one_newline() {
    let jar = Sandbox::new();
    let value = b"line one\nline two\n";
    let out = jar.run_with_stdin(&["set", "-m", "note"], value);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = jar.run(&["get", "note"]);
    assert_eq!(out.stdout, value);

    // The value already ends with a newline; show must not add a blank line.
    let out = jar.run(&["show", "note"]);
    assert_eq!(out.stdout, value);

    jar.set("bare", b"no newline");
    let out = jar.run(&["show", "bare"]);
    assert_eq!(out.stdout, b"no newline\n");
}

#[test]
fn ls_sorts_and_filters_by_path_component() {
    let jar = Sandbox::new();
    for name in ["work/db", "openai", "work/aws", "workshop/key"] {
        jar.set(name, b"x\n");
    }
    let out = jar.run(&["ls"]);
    assert_eq!(stdout(&out), "openai\nwork/aws\nwork/db\nworkshop/key\n");

    let out = jar.run(&["ls", "work"]);
    assert_eq!(stdout(&out), "work/aws\nwork/db\n");
}

#[test]
fn an_empty_store_lists_nothing_and_succeeds() {
    let jar = Sandbox::new();
    let out = jar.run(&["ls"]);
    assert_eq!(code(&out), 0);
    assert!(out.stdout.is_empty());
}

#[test]
fn a_traversal_name_is_rejected_before_touching_the_disk() {
    let jar = Sandbox::new();
    let out = jar.run_with_stdin(&["set", "../escape"], b"x\n");
    assert_eq!(code(&out), 2);
    assert!(!jar.home.join("escape.age").exists());
}

#[test]
fn rm_refuses_a_pipe_without_force_and_prunes_with_it() {
    let jar = Sandbox::new();
    jar.set("work/only", b"x\n");

    // Automation deleting the wrong secret silently is the failure mode;
    // a pipe cannot confirm, so it must refuse.
    let out = jar.run_with_stdin(&["rm", "work/only"], b"y\n");
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert!(jar.store_dir().join("work/only.age").exists());

    let out = jar.run(&["rm", "-f", "work/only"]);
    assert_eq!(code(&out), 0);
    assert!(!jar.store_dir().join("work").exists());
    assert!(jar.store_dir().exists());

    let out = jar.run(&["rm", "-f", "work/only"]);
    assert_eq!(code(&out), 1);
}

#[test]
fn mv_renames_and_the_value_survives() {
    let jar = Sandbox::new();
    jar.set("work/deep/key", b"v\n");

    let out = jar.run(&["mv", "work/deep/key", "personal/key"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(jar.run(&["get", "personal/key"]).stdout, b"v");
    assert_eq!(code(&jar.run(&["get", "work/deep/key"])), 1);
    assert!(!jar.store_dir().join("work").exists());
}

#[test]
fn mv_onto_an_existing_entry_refuses_a_pipe_and_overwrites_with_force() {
    let jar = Sandbox::new();
    jar.set("a", b"one\n");
    jar.set("b", b"two\n");

    // A pipe cannot confirm the overwrite, so it must refuse.
    let out = jar.run_with_stdin(&["mv", "a", "b"], b"y\n");
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(jar.run(&["get", "b"]).stdout, b"two");

    let out = jar.run(&["mv", "-f", "a", "b"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(jar.run(&["get", "b"]).stdout, b"one");
    assert_eq!(code(&jar.run(&["get", "a"])), 1);
}

#[test]
fn terminal_mv_confirms_before_overwriting() {
    let jar = Sandbox::new();
    jar.set("a", b"one\n");
    jar.set("b", b"two\n");

    let mut child = PtyChild::spawn(jar.command(&["mv", "a", "b"]));
    child.read_until(b"overwrite b? [y/N] ");
    child.write(b"n\n");
    assert!(child.finish().status.success());
    assert_eq!(jar.run(&["get", "a"]).stdout, b"one");
    assert_eq!(jar.run(&["get", "b"]).stdout, b"two");

    let mut child = PtyChild::spawn(jar.command(&["mv", "a", "b"]));
    child.read_until(b"overwrite b? [y/N] ");
    child.write(b"y\n");
    assert!(child.finish().status.success());
    assert_eq!(jar.run(&["get", "b"]).stdout, b"one");
    assert_eq!(code(&jar.run(&["get", "a"])), 1);
}

#[test]
fn mv_to_the_same_name_is_an_error() {
    let jar = Sandbox::new();
    jar.set("a", b"one\n");
    let out = jar.run(&["mv", "a", "a"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("same"), "{}", stderr(&out));
    assert_eq!(jar.run(&["get", "a"]).stdout, b"one");
}

#[test]
fn env_emits_eval_safe_export_lines() {
    let jar = Sandbox::new();
    jar.set("work/aws-access-key", b"AKIA123\n");
    jar.set("openai", b"sk-1\n");

    let out = jar.run(&["env", "work"]);
    assert_eq!(stdout(&out), "export AWS_ACCESS_KEY='AKIA123'\n");

    let out = jar.run(&["env"]);
    assert_eq!(
        stdout(&out),
        "export OPENAI='sk-1'\nexport WORK_AWS_ACCESS_KEY='AKIA123'\n"
    );
}

#[test]
fn env_prefixes_select_strict_descendants() {
    let jar = Sandbox::new();
    jar.set("work", b"top\n");
    jar.set("work/token", b"nested\n");

    let out = jar.run(&["env", "work"]);
    assert_eq!(stdout(&out), "export TOKEN='nested'\n");
}

#[test]
fn env_rejects_non_utf8_values() {
    let jar = Sandbox::new();
    let out = jar.run_with_stdin(&["set", "-m", "binary"], b"\xff");
    assert!(out.status.success(), "{}", stderr(&out));

    let out = jar.run(&["env"]);
    assert_eq!(code(&out), 1);
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("not valid UTF-8"), "{}", stderr(&out));
}

#[test]
fn environment_values_reject_nul_bytes() {
    let jar = Sandbox::new();
    let out = jar.run_with_stdin(&["set", "-m", "binary"], b"before\0after");
    assert!(out.status.success(), "{}", stderr(&out));

    for args in [&["env"][..], &["run", "--", "sh", "-c", "exit 0"][..]] {
        let out = jar.run(args);
        assert_eq!(code(&out), 1);
        assert!(stderr(&out).contains("NUL byte"), "{}", stderr(&out));
    }
}

// A script that calls `keyjar run` on a machine with no secrets must not be
// the thing that mints an identity.
#[test]
fn empty_environment_selections_need_no_identity() {
    let jar = Sandbox::new();

    let out = jar.run(&["env"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(out.stdout.is_empty());

    let out = jar.run(&["run", "--", "sh", "-c", "exit 0"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(!jar.home.join("config/keyjar/identity").exists());
}

// The output of `env` is fed to a shell, so quoting is a correctness problem
// before it is a safety one. Assert against a real eval, not the quoted form.
#[test]
fn hostile_values_survive_a_real_eval() {
    let jar = Sandbox::new();
    let value = b"it's $HOME `pwd` \"quoted\"\nsecond line";
    let out = jar.run_with_stdin(&["set", "-m", "tricky"], value);
    assert!(out.status.success(), "{}", stderr(&out));

    let script = format!(
        "eval \"$({} env)\"; printf %s \"$TRICKY\"",
        env!("CARGO_BIN_EXE_keyjar")
    );
    let out = jar
        .command(&[])
        .args(["run", "--", "sh", "-c", &script])
        .output()
        .unwrap();
    // keyjar run only lends its sandboxed environment to sh here.
    assert_eq!(out.stdout, value, "{}", stderr(&out));
}

#[test]
fn colliding_variable_names_are_an_error_not_a_skip() {
    let jar = Sandbox::new();
    jar.set("aws-key", b"a\n");
    jar.set("aws_key", b"b\n");
    let out = jar.run(&["env"]);
    assert_eq!(code(&out), 1);
    assert!(out.stdout.is_empty());
    assert!(
        stderr(&out).contains("both map to AWS_KEY"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn run_injects_variables_and_propagates_the_exit_code() {
    let jar = Sandbox::new();
    jar.set("work/token", b"t0ps3cret\n");

    let out = jar.run(&["run", "work", "--", "sh", "-c", "printf %s \"$TOKEN\""]);
    assert_eq!(code(&out), 0);
    assert_eq!(out.stdout, b"t0ps3cret");

    let out = jar.run(&["run", "--", "sh", "-c", "exit 7"]);
    assert_eq!(code(&out), 7);

    let out = jar.run(&["run", "--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.signal(), Some(libc::SIGTERM));

    let out = jar.run(&["run", "--", "keyjar-no-such-program"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("keyjar-no-such-program"),
        "{}",
        stderr(&out)
    );
}

// First use is the only moment two processes can each decide to create an
// identity. If one overwrote the other, the earlier writes would be dead
// ciphertext, so every entry here must read back.
#[test]
fn concurrent_first_sets_share_one_identity() {
    let jar = Sandbox::new();
    let mut children = Vec::new();
    for index in 0..16 {
        let name = format!("key-{index}");
        let mut child = jar
            .command(&["set", &name])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"value\n").unwrap();
        children.push((name, child));
    }
    for (name, child) in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "set {name}: {}", stderr(&out));
        let out = jar.run(&["get", &name]);
        assert_eq!(out.stdout, b"value", "get {name}: {}", stderr(&out));
    }
}

// A second identity pointed at an existing store must fail before writing.
// Half the entries readable by one key and half by another is unrecoverable
// without noticing which is which.
#[test]
fn a_store_rejects_a_different_identity() {
    use age::secrecy::ExposeSecret;

    let jar = Sandbox::new();
    jar.set("first", b"one\n");
    let other = age::x25519::Identity::generate();
    let other_path = jar.home.join("other-identity");
    std::fs::write(
        &other_path,
        format!("{}\n", other.to_string().expose_secret()),
    )
    .unwrap();

    let out = jar
        .command(&["set", "second"])
        .env("KEYJAR_IDENTITY", &other_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(b"two\n")?;
            child.wait_with_output()
        })
        .unwrap();

    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("does not match"), "{}", stderr(&out));
    assert!(!jar.store_dir().join("second.age").exists());
}

fn identity_path(jar: &Sandbox) -> PathBuf {
    jar.home.join("config/keyjar/identity")
}

fn public_key_of(identity_contents: &str) -> String {
    identity_contents
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap()
        .to_string()
}

#[test]
fn rekey_round_trips_and_replaces_the_identity() {
    let jar = Sandbox::new();
    jar.set("openai", b"sk-1\n");
    jar.set("work/aws", b"AKIA\n");
    let identity = identity_path(&jar);
    let before_identity = std::fs::read_to_string(&identity).unwrap();
    let marker = jar.store_dir().join(".keyjar-recipient");
    let entries = [
        jar.store_dir().join("openai.age"),
        jar.store_dir().join("work/aws.age"),
    ];
    let before_ciphertexts: Vec<_> = entries.iter().map(|p| std::fs::read(p).unwrap()).collect();

    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("rekeyed 2 entries"),
        "{}",
        stderr(&out)
    );

    // The whole key ring rotated: new key installed, old key kept, no .new.
    let after_identity = std::fs::read_to_string(&identity).unwrap();
    assert_ne!(after_identity, before_identity);
    let old = jar.home.join("config/keyjar/identity.old");
    assert_eq!(std::fs::read_to_string(&old).unwrap(), before_identity);
    assert!(!jar.home.join("config/keyjar/identity.new").exists());

    // The store followed: marker and every ciphertext rewritten.
    let public = public_key_of(&after_identity);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        format!("{public}\n")
    );
    for (path, before) in entries.iter().zip(&before_ciphertexts) {
        assert_ne!(&std::fs::read(path).unwrap(), before, "{}", path.display());
    }
    assert_eq!(jar.run(&["get", "openai"]).stdout, b"sk-1");
    assert_eq!(jar.run(&["get", "work/aws"]).stdout, b"AKIA");

    // The old key can no longer open the store.
    let out = jar
        .command(&["get", "openai"])
        .env("KEYJAR_IDENTITY", &old)
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("does not match"), "{}", stderr(&out));
}

#[test]
fn rekey_refuses_a_pipe_without_force() {
    let jar = Sandbox::new();
    jar.set("k", b"v\n");
    let before = std::fs::read_to_string(identity_path(&jar)).unwrap();

    let out = jar.run_with_stdin(&["rekey"], b"y\n");
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(identity_path(&jar)).unwrap(),
        before
    );
    assert_eq!(jar.run(&["get", "k"]).stdout, b"v");
}

#[test]
fn terminal_rekey_confirms() {
    let jar = Sandbox::new();
    jar.set("k", b"v\n");
    let before = std::fs::read_to_string(identity_path(&jar)).unwrap();

    let mut child = PtyChild::spawn(jar.command(&["rekey"]));
    child.read_until(b"replace the identity? [y/N] ");
    child.write(b"n\n");
    assert!(child.finish().status.success());
    assert_eq!(
        std::fs::read_to_string(identity_path(&jar)).unwrap(),
        before
    );

    let mut child = PtyChild::spawn(jar.command(&["rekey"]));
    child.read_until(b"replace the identity? [y/N] ");
    child.write(b"y\n");
    assert!(child.finish().status.success());
    assert_ne!(
        std::fs::read_to_string(identity_path(&jar)).unwrap(),
        before
    );
    assert_eq!(jar.run(&["get", "k"]).stdout, b"v");
}

#[test]
fn rekey_with_no_store_is_an_error() {
    let jar = Sandbox::new();
    // Mint the identity through another store so the emptiness path is
    // reached, not the missing-identity one.
    let other = jar.home.join("other-store");
    let out = jar.run_with_stdin(&["set", "k", "--store", other.to_str().unwrap()], b"v\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let before = std::fs::read_to_string(identity_path(&jar)).unwrap();

    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("empty"), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(identity_path(&jar)).unwrap(),
        before
    );
}

// A store whose last entry was removed is still bound to its key; the marker
// must follow the identity or the next set would bind to a dead key.
#[test]
fn rekey_after_removing_every_entry_still_rotates() {
    let jar = Sandbox::new();
    jar.set("k", b"v\n");
    assert!(jar.run(&["rm", "-f", "k"]).status.success());
    let before = std::fs::read_to_string(identity_path(&jar)).unwrap();

    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("rekeyed 0 entries"),
        "{}",
        stderr(&out)
    );
    let after = std::fs::read_to_string(identity_path(&jar)).unwrap();
    assert_ne!(after, before);
    let marker = jar.store_dir().join(".keyjar-recipient");
    let public = public_key_of(&after);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        format!("{public}\n")
    );
    jar.set("k2", b"v2\n");
    assert_eq!(jar.run(&["get", "k2"]).stdout, b"v2");
}

#[test]
fn a_leftover_new_identity_blocks_rekey() {
    use age::secrecy::ExposeSecret;

    let jar = Sandbox::new();
    jar.set("k", b"v\n");
    let identity = identity_path(&jar);
    let before = std::fs::read_to_string(&identity).unwrap();
    let new_path = jar.home.join("config/keyjar/identity.new");

    // An unreadable .new means entries may be split between the keys.
    std::fs::write(&new_path, "garbage").unwrap();
    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("identity.new"), "{}", stderr(&out));
    assert!(stderr(&out).contains("split"), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&identity).unwrap(), before);
    assert_eq!(jar.run(&["get", "k"]).stdout, b"v");

    // A .new matching the marker means the rotation finished and only the
    // file swap remains; the advice must say exactly that.
    let done = age::x25519::Identity::generate();
    std::fs::write(&new_path, format!("{}\n", done.to_string().expose_secret())).unwrap();
    std::fs::write(
        jar.store_dir().join(".keyjar-recipient"),
        format!("{}\n", done.to_public()),
    )
    .unwrap();
    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("finish it"), "{}", stderr(&out));
}

#[test]
fn a_leftover_old_identity_blocks_rekey() {
    let jar = Sandbox::new();
    jar.set("k", b"v\n");
    let identity = identity_path(&jar);
    let before = std::fs::read_to_string(&identity).unwrap();
    std::fs::write(jar.home.join("config/keyjar/identity.old"), "x").unwrap();

    let out = jar.run(&["rekey", "-f"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("identity.old"), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&identity).unwrap(), before);
    assert_eq!(jar.run(&["get", "k"]).stdout, b"v");
}

// Run as `sh SCRIPT` so exec never targets the freshly written file; a
// concurrent test's fork holding the write fd open would make a direct
// exec fail with ETXTBSY.
fn fake_editor(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("{body}\n")).unwrap();
    format!("sh {}", path.display())
}

#[test]
fn edit_creates_updates_and_aborts_cleanly() {
    let jar = Sandbox::new();
    let editor = fake_editor(jar.home.as_path(), "editor", "echo created > \"$1\"");

    let out = jar
        .command(&["edit", "fresh"])
        .env("EDITOR", &editor)
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = jar.run(&["get", "fresh"]);
    assert_eq!(out.stdout, b"created\n");

    // A failing editor must leave the entry untouched.
    let failing = fake_editor(
        jar.home.as_path(),
        "failing",
        "echo clobbered > \"$1\"; exit 1",
    );
    let out = jar
        .command(&["edit", "fresh"])
        .env("EDITOR", &failing)
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    let out = jar.run(&["get", "fresh"]);
    assert_eq!(out.stdout, b"created\n");

    // No decrypted droppings may remain next to the ciphertext.
    let leftovers: Vec<_> = std::fs::read_dir(jar.store_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(".keyjar-edit-"))
        .collect();
    assert_eq!(leftovers, Vec::<String>::new());
}

#[test]
fn an_unchanged_edit_does_not_replace_the_ciphertext() {
    let jar = Sandbox::new();
    jar.set("same", b"value\n");
    let path = jar.store_dir().join("same.age");
    let before = std::fs::read(&path).unwrap();

    let out = jar
        .command(&["edit", "same"])
        .env("EDITOR", "true")
        .output()
        .unwrap();

    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("same unchanged"), "{}", stderr(&out));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn edit_without_an_editor_is_an_error() {
    let jar = Sandbox::new();
    let out = jar.run(&["edit", "x"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("EDITOR"), "{}", stderr(&out));
}

#[test]
fn the_store_flag_beats_the_env_var() {
    let jar = Sandbox::new();
    let env_store = jar.home.join("env-store");
    let flag_store = jar.home.join("flag-store");
    let flag = flag_store.to_str().unwrap().to_string();

    let out = jar
        .command(&["set", "key", "--store", &flag])
        .env("KEYJAR_STORE", &env_store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(b"v\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(flag_store.join("key.age").exists());
    assert!(!env_store.exists());

    // Without the flag the env var takes over.
    let out = jar
        .command(&["ls"])
        .env("KEYJAR_STORE", &flag_store)
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "key\n");
}

#[test]
fn quiet_silences_notices_but_not_errors() {
    let jar = Sandbox::new();
    let out = jar.run_with_stdin(&["-q", "set", "openai"], b"x\n");
    assert!(out.status.success());
    assert!(out.stderr.is_empty(), "{}", stderr(&out));

    let out = jar.run(&["-q", "get", "missing"]);
    assert_eq!(code(&out), 1);
    assert!(!out.stderr.is_empty());
}
