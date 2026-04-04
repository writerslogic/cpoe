

//! Shared test infrastructure for cpop_cli e2e tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/
pub struct CpopOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/
pub struct TempEnv {
    pub dir: tempfile::TempDir,
    pub bin: &'static str,
}

impl TempEnv {
    /
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("failed to create temp dir"),
            bin: env!("CARGO_BIN_EXE_cpop"),
        }
    }

    /
    pub fn with_identity() -> Self {
        let env = Self::new();
        env.run_expect_success(&["init"], None);
        env
    }

    /
    pub fn run(&self, args: &[&str], input: Option<&str>) -> CpopOutput {
        run_cpop_in(self.dir.path(), self.bin, args, input, &[])
    }

    /
    pub fn run_with_env(
        &self,
        args: &[&str],
        input: Option<&str>,
        env: &[(&str, &str)],
    ) -> CpopOutput {
        run_cpop_in(self.dir.path(), self.bin, args, input, env)
    }

    /
    pub fn run_expect_success(&self, args: &[&str], input: Option<&str>) -> String {
        let output = self.run(args, input);
        assert!(
            output.success,
            "Command failed: cpop {}\nSTDOUT: {}\nSTDERR: {}",
            args.join(" "),
            output.stdout,
            output.stderr,
        );
        output.stdout
    }

    /
    pub fn run_expect_failure(&self, args: &[&str], input: Option<&str>) -> CpopOutput {
        let output = self.run(args, input);
        assert!(
            !output.success,
            "Command unexpectedly succeeded: cpop {}\nSTDOUT: {}\nSTDERR: {}",
            args.join(" "),
            output.stdout,
            output.stderr,
        );
        output
    }

    /
    pub fn create_file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, content).expect("write fixture file");
        path
    }

    /
    pub fn with_commits(&self, filename: &str, n: u32) -> PathBuf {
        self.run_expect_success(&["init"], None);
        let path = self.create_file(filename, "initial content");
        for i in 1..=n {
            let content = format!("content version {i} with enough text to be meaningful");
            fs::write(&path, &content).expect("write file version");
            self.run_expect_success(
                &[
                    "commit",
                    path.to_str().unwrap(),
                    "-m",
                    &format!("Commit #{i}"),
                ],
                None,
            );
        }
        path
    }
}

/
fn run_cpop_in(
    dir: &Path,
    bin: &str,
    args: &[&str],
    input: Option<&str>,
    extra_env: &[(&str, &str)],
) -> CpopOutput {
    use std::io::Write;
    use std::process::Stdio;

    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("CPOP_DATA_DIR", dir)
        .env("CPOP_NO_KEYCHAIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().expect("failed to spawn cpop process");

    if let Some(stdin_content) = input {
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        stdin
            .write_all(stdin_content.as_bytes())
            .expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    CpopOutput {
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}



pub fn assert_exit_success(output: &CpopOutput, context: &str) {
    assert!(
        output.success,
        "{context}: expected success but got exit code {:?}\nSTDOUT: {}\nSTDERR: {}",
        output.exit_code, output.stdout, output.stderr,
    );
}

pub fn assert_exit_failure(output: &CpopOutput, context: &str) {
    assert!(
        !output.success,
        "{context}: expected failure but got success\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
}

pub fn assert_stdout_contains(output: &CpopOutput, needle: &str, context: &str) {
    assert!(
        output.stdout.contains(needle),
        "{context}: stdout should contain '{needle}'\nActual stdout: {}",
        output.stdout,
    );
}

pub fn assert_stderr_contains(output: &CpopOutput, needle: &str, context: &str) {
    assert!(
        output.stderr.contains(needle),
        "{context}: stderr should contain '{needle}'\nActual stderr: {}",
        output.stderr,
    );
}

pub fn assert_no_panic(output: &CpopOutput, context: &str) {
    assert!(
        !output.stderr.contains("panicked at"),
        "{context}: process panicked!\nSTDERR: {}",
        output.stderr,
    );
    assert!(
        !output.stderr.contains("RUST_BACKTRACE"),
        "{context}: backtrace in stderr indicates a panic\nSTDERR: {}",
        output.stderr,
    );
}

pub fn assert_json_valid(output: &CpopOutput, context: &str) -> serde_json::Value {
    serde_json::from_str(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{context}: stdout is not valid JSON: {e}\nActual: {}",
            output.stdout
        )
    })
}
