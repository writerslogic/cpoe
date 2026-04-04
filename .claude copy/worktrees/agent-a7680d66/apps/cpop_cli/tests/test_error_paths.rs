

//! E2E tests for error scenarios and edge-case file handling.

mod common;

use std::fs;
use std::os::unix::fs as unix_fs;



#[test]
fn test_error_commit_nonexistent_file() {
    let env = common::TempEnv::with_identity();
    let missing = env.dir.path().join("does_not_exist.txt");

    let output = env.run_expect_failure(
        &["commit", missing.to_str().unwrap(), "-m", "should fail"],
        None,
    );
    common::assert_no_panic(&output, "commit nonexistent file");
    
    assert!(
        output.stderr.contains("does_not_exist.txt"),
        "stderr should name the missing file\nActual stderr: {}",
        output.stderr,
    );
}



#[test]
fn test_error_unicode_filename_commit_succeeds() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file(
        "写作_2026.txt",
        "这是一个测试文档，用于验证 Unicode 文件名支持。",
    );

    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "Unicode filename"],
        None,
    );
    common::assert_no_panic(&output, "unicode filename commit");
    assert!(
        output.success,
        "commit with unicode filename should succeed\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
}



#[test]
fn test_error_spaces_in_filename_commit_succeeds() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file(
        "my novel chapter 01.txt",
        "It was a dark and stormy night. The rain fell in torrents.",
    );

    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "Spaces in filename"],
        None,
    );
    common::assert_no_panic(&output, "spaces in filename commit");
    assert!(
        output.success,
        "commit with spaces in filename should succeed\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
}



#[test]
fn test_error_emoji_in_filename_commit() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file(
        "📝draft.txt",
        "Draft content with enough text to be a real document.",
    );

    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "Emoji filename"],
        None,
    );
    common::assert_no_panic(&output, "emoji filename commit");
    
    if !output.success {
        assert!(
            !output.stderr.is_empty(),
            "on failure, stderr must explain the error\nActual stderr: {}",
            output.stderr,
        );
    }
    
}



#[test]
fn test_error_config_corrupted_names_file() {
    let env = common::TempEnv::with_identity();

    
    
    let config_path = env.dir.path().join("writersproof.json");
    assert!(
        config_path.exists(),
        "writersproof.json should exist after init\nDir contents: {:?}",
        fs::read_dir(env.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>(),
    );
    
    fs::write(&config_path, b"{ not valid json \x00" as &[u8]).unwrap();

    
    let output = env.run(&["status"], None);
    common::assert_no_panic(&output, "corrupted config — status");
    assert!(
        !output.success,
        "should fail when config is corrupted\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
}



#[test]
fn test_error_malformed_file_in_verify() {
    let env = common::TempEnv::with_identity();

    
    
    let garbage: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    let path = env.dir.path().join("garbage.bin");
    fs::write(&path, &garbage).unwrap();

    let output = env.run(&["verify", path.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify malformed file");
    assert!(
        !output.success,
        "verify on malformed file should fail\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
    
    assert!(
        !output.stderr.is_empty() || !output.stdout.is_empty(),
        "verify malformed: some output expected\nSTDOUT: {}\nSTDERR: {}",
        output.stdout,
        output.stderr,
    );
}



#[test]
fn test_error_verify_nonexistent_file() {
    let env = common::TempEnv::with_identity();
    let missing = env.dir.path().join("no_such_evidence.cpop");

    let output = env.run_expect_failure(&["verify", missing.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify nonexistent file");
    
    assert!(
        !output.stderr.is_empty() || !output.stdout.is_empty(),
        "verify nonexistent file: expected some output explaining the error",
    );
    
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("No such file")
            || combined.contains("not found")
            || combined.contains("no_such_evidence")
            || combined.contains("Error"),
        "error output should explain the missing file\nActual output: {}",
        combined,
    );
}



#[test]
fn test_error_commit_before_init_auto_initializes() {
    
    let env = common::TempEnv::new();
    let path = env.create_file(
        "novel.txt",
        "Chapter one began on a morning that smelled of rain and fresh ink.",
    );

    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "First commit ever"],
        None,
    );
    common::assert_no_panic(&output, "commit before explicit init");
    assert!(
        output.success,
        "CLI should auto-init and then commit\nSTDOUT: {}\nSTDERR: {}",
        output.stdout, output.stderr,
    );
    assert!(
        output.stdout.contains("Checkpoint"),
        "output should confirm a checkpoint was created\nActual stdout: {}",
        output.stdout,
    );
}



#[test]
fn test_error_export_before_init_auto_initializes() {
    
    let env = common::TempEnv::new();
    let path = env.create_file(
        "essay.txt",
        "The argument presented here rests on three pillars of evidence.",
    );

    
    let commit_out = env.run(
        &["commit", path.to_str().unwrap(), "-m", "auto-init commit"],
        None,
    );
    common::assert_no_panic(&commit_out, "auto-init commit (export test)");

    let export_path = env.dir.path().join("out.json");
    let output = env.run(
        &[
            "export",
            path.to_str().unwrap(),
            "-o",
            export_path.to_str().unwrap(),
        ],
        Some("n\nTest AI declaration\n"),
    );
    common::assert_no_panic(&output, "export before explicit init");
    
    if output.success {
        assert!(
            export_path.exists(),
            "export output file should exist on success",
        );
    }
}



#[test]
fn test_error_concurrent_commits_no_panic() {
    use std::process::{Command, Stdio};
    use std::sync::Arc;

    let env = Arc::new(common::TempEnv::with_identity());
    let bin = env.bin;
    let data_dir = env.dir.path().to_path_buf();

    
    let files: Vec<_> = (0..3)
        .map(|i| {
            let name = format!("concurrent_{i}.txt");
            let content = format!(
                "Concurrent file {i}. {}",
                "This content is long enough to be meaningful. ".repeat(4)
            );
            let path = data_dir.join(&name);
            fs::write(&path, &content).expect("write concurrent file");
            path
        })
        .collect();

    
    let mut children: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(i, path)| {
            Command::new(bin)
                .args([
                    "commit",
                    path.to_str().unwrap(),
                    "-m",
                    &format!("Concurrent commit {i}"),
                ])
                .env("CPOP_DATA_DIR", &data_dir)
                .env("CPOP_NO_KEYCHAIN", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("failed to spawn concurrent commit")
        })
        .collect();

    
    for (i, child) in children.drain(..).enumerate() {
        let output = child.wait_with_output().expect("wait on concurrent child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stderr.contains("panicked at"),
            "concurrent commit {i} panicked!\nSTDERR: {stderr}",
        );
        assert!(
            !stderr.contains("RUST_BACKTRACE"),
            "concurrent commit {i} produced a backtrace (panic indicator)\nSTDERR: {stderr}",
        );
        
        assert!(
            output.status.success(),
            "concurrent commit {i} should succeed\nSTDOUT: {stdout}\nSTDERR: {stderr}",
        );
    }
}



#[test]
fn test_error_symlink_commit() {
    let env = common::TempEnv::with_identity();

    
    let real_path = env.create_file(
        "real_document.txt",
        "The real document contains substantive content worth preserving.",
    );

    
    let link_path = env.dir.path().join("link_to_document.txt");
    unix_fs::symlink(&real_path, &link_path).expect("create symlink");

    let output = env.run(
        &[
            "commit",
            link_path.to_str().unwrap(),
            "-m",
            "Commit via symlink",
        ],
        None,
    );
    common::assert_no_panic(&output, "symlink commit");
    
    
    if !output.success {
        assert!(
            !output.stderr.is_empty(),
            "on symlink refusal, stderr must explain why\nActual stderr: {}",
            output.stderr,
        );
    }
}



#[test]
fn test_error_empty_file_commit() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("empty.txt", "");

    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "Empty file"],
        None,
    );
    common::assert_no_panic(&output, "empty file commit");
    
    if !output.success {
        assert!(
            !output.stderr.is_empty(),
            "on empty-file refusal, stderr must explain why\nActual stderr: {}",
            output.stderr,
        );
    }
}
