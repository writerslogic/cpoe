



use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

/
fn run_cpop(data_dir: &Path, args: &[&str]) -> (String, String, i32) {
    run_cpop_with_stdin(data_dir, args, None)
}

/
fn run_cpop_with_stdin(
    data_dir: &Path,
    args: &[&str],
    stdin_content: Option<&str>,
) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cpop"))
        .args(args)
        .env("CPOP_DATA_DIR", data_dir)
        .env("CPOP_NO_KEYCHAIN", "1")
        .env("CPOP_SKIP_PERMISSIONS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run cpop");

    if let Some(content) = stdin_content {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(content.as_bytes())
            .expect("failed to write stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/
fn run_cpop_ok(data_dir: &Path, args: &[&str]) -> String {
    run_cpop_ok_with_stdin(data_dir, args, None)
}

/
fn run_cpop_ok_with_stdin(data_dir: &Path, args: &[&str], stdin_content: Option<&str>) -> String {
    let (stdout, stderr, code) = run_cpop_with_stdin(data_dir, args, stdin_content);
    assert_eq!(
        code,
        0,
        "cpop {} failed (exit {})\nstdout: {}\nstderr: {}",
        args.join(" "),
        code,
        stdout,
        stderr
    );
    stdout
}

/
fn init_cpop(data_dir: &Path) {
    run_cpop_ok(data_dir, &["init"]);
}

/
fn create_min_checkpoints(data_dir: &Path, file_path: &Path) {
    fs::write(file_path, "Version 1: initial draft content.").unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 1"],
    );

    fs::write(
        file_path,
        "Version 2: revised draft content with additions.",
    )
    .unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 2"],
    );

    fs::write(
        file_path,
        "Version 3: final revised draft content with more additions and edits.",
    )
    .unwrap();
    run_cpop_ok(
        data_dir,
        &["commit", file_path.to_str().unwrap(), "-m", "Draft 3"],
    );
}





#[test]
fn scenario_complete_authoring_workflow() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let essay = data.join("essay.txt");

    
    fs::write(&essay, "The beginning of a great essay.").unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 1"]);
    assert!(
        stdout.contains("Checkpoint #1"),
        "First commit should create checkpoint #1. Got: {}",
        stdout
    );
    
    assert!(
        data.join("signing_key").exists(),
        "signing_key should exist after commit"
    );

    
    fs::write(
        &essay,
        "The beginning of a great essay. Adding more thoughts and ideas.",
    )
    .unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 2"]);
    assert!(
        stdout.contains("Checkpoint #2"),
        "Second commit should create checkpoint #2. Got: {}",
        stdout
    );

    
    fs::write(
        &essay,
        "The beginning of a great essay. Adding more thoughts and ideas. Concluding paragraph here.",
    )
    .unwrap();
    let stdout = run_cpop_ok(data, &["commit", essay.to_str().unwrap(), "-m", "Draft 3"]);
    assert!(
        stdout.contains("Checkpoint #3"),
        "Third commit should create checkpoint #3. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["log", essay.to_str().unwrap()]);
    assert!(
        stdout.contains("Draft 1"),
        "Log should show Draft 1. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Draft 2"),
        "Log should show Draft 2. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Draft 3"),
        "Log should show Draft 3. Got: {}",
        stdout
    );

    
    let evidence_json = data.join("essay.evidence.json");
    let stdout = run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            essay.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence_json.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(
        stdout.contains("exported") || stdout.contains("Evidence"),
        "Export should confirm success. Got: {}",
        stdout
    );
    assert!(evidence_json.exists(), "JSON evidence file should exist");
    
    let json_data = fs::read_to_string(&evidence_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_data).unwrap_or_else(|e| {
        panic!(
            "Evidence should be valid JSON: {}. Content: {}",
            e,
            &json_data[..200.min(json_data.len())]
        )
    });
    assert!(parsed.is_object(), "Evidence JSON should be an object");

    
    let c2pa_path = data.join("essay.c2pa.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            essay.to_str().unwrap(),
            "-f",
            "c2pa",
            "-o",
            c2pa_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(c2pa_path.exists(), "C2PA file should exist");

    
    
    
    let (stdout, _, _) = run_cpop(data, &["verify", evidence_json.to_str().unwrap()]);
    assert!(
        stdout.contains("Evidence packet Verified") || stdout.contains("Structural"),
        "Verification should confirm structural validity. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("status"),
        "Status output should contain status info. Got: {}",
        stdout
    );
}





#[test]
fn scenario_export_format_matrix() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("formats.txt");
    create_min_checkpoints(data, &doc);

    
    let formats_and_extensions: &[(&str, &str)] = &[
        ("json", "formats.txt.evidence.json"),
        ("cpop", "formats.txt.cpop"),
        ("cwar", "formats.txt.cwar"),
        ("html", "formats.txt.report.html"),
        ("c2pa", "formats.txt.c2pa.json"),
    ];

    for (format, expected_name) in formats_and_extensions {
        let out_path = data.join(expected_name);
        let (stdout, stderr, code) = run_cpop_with_stdin(
            data,
            &[
                "export",
                doc.to_str().unwrap(),
                "-f",
                format,
                "-o",
                out_path.to_str().unwrap(),
                "--no-beacons",
            ],
            Some("n\nDeclaration\n"),
        );
        assert_eq!(
            code, 0,
            "Export as {} should succeed (exit {})\nstdout: {}\nstderr: {}",
            format, code, stdout, stderr
        );
        assert!(
            out_path.exists(),
            "Output file for format '{}' should exist at {}",
            format,
            out_path.display()
        );
        let file_size = fs::metadata(&out_path).unwrap().len();
        assert!(
            file_size > 0,
            "Output for format '{}' should be non-empty",
            format
        );
    }

    
    let json_path = data.join("formats.txt.evidence.json");
    let json_data = fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&json_data).expect("JSON evidence should parse");
    assert!(parsed.is_object(), "JSON evidence should be an object");

    
    let c2pa_data = fs::read_to_string(data.join("formats.txt.c2pa.json")).unwrap();
    let c2pa_parsed: serde_json::Value =
        serde_json::from_str(&c2pa_data).expect("C2PA JSON should parse");
    assert!(c2pa_parsed.is_object(), "C2PA should be an object");
}





#[test]
fn scenario_error_commit_nonexistent() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (_, stderr, code) = run_cpop(data, &["commit", "/nonexistent/path/file.txt"]);
    assert_ne!(code, 0, "Commit of nonexistent file should fail");
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("does not exist")
            || stderr.contains("Error"),
        "Should mention file not found. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_verify_nonexistent() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (_, stderr, code) = run_cpop(data, &["verify", "/nonexistent/evidence.json"]);
    assert_ne!(code, 0, "Verify of nonexistent file should fail");
    assert!(
        stderr.contains("Error") || stderr.contains("not found") || stderr.contains("No such file"),
        "Should mention file error. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_export_no_checkpoints() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let doc = data.join("untracked.txt");
    fs::write(&doc, "Content without checkpoints").unwrap();

    let (_, stderr, code) = run_cpop_with_stdin(
        data,
        &["export", doc.to_str().unwrap(), "--no-beacons"],
        Some("n\nDecl\n"),
    );
    assert_ne!(code, 0, "Export without checkpoints should fail");
    assert!(
        stderr.contains("checkpoint")
            || stderr.contains("No events")
            || stderr.contains("track")
            || stderr.contains("Error"),
        "Should mention missing checkpoints. stderr: {}",
        stderr
    );
}

#[test]
fn scenario_error_verify_invalid_json() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let bad_file = data.join("bad.json");
    fs::write(&bad_file, "this is not valid json").unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", bad_file.to_str().unwrap()]);
    assert_ne!(code, 0, "Verify of invalid JSON should fail");
    assert!(
        stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("Error"),
        "Should mention parse error. stderr: {}",
        stderr
    );
}





#[test]
fn scenario_identity_management() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let did_output = run_cpop_ok(data, &["identity", "--did"]);
    assert!(
        did_output.contains("did:key:") || did_output.contains("DID"),
        "Identity --did should output a DID. Got: {}",
        did_output
    );

    
    let fp_output = run_cpop_ok(data, &["identity", "--fingerprint"]);
    assert!(
        !fp_output.trim().is_empty(),
        "Identity --fingerprint should produce output"
    );

    
    let did_output2 = run_cpop_ok(data, &["identity", "--did"]);
    assert_eq!(
        did_output, did_output2,
        "Identity should persist across invocations"
    );
}





#[test]
fn scenario_config_management() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start") || stdout.contains("Sentinel") || stdout.contains("VDF"),
        "Config show should display settings. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "false"]);
    assert!(
        stdout.contains("Set")
            || stdout.contains("set")
            || stdout.contains("saved")
            || stdout.contains("Updated"),
        "Config set should confirm the change. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: false") || stdout.contains("auto_start\":false"),
        "Config should show updated value. Got: {}",
        stdout
    );
}





#[test]
fn scenario_link_command() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let source = data.join("source.txt");
    create_min_checkpoints(data, &source);

    
    let derivative = data.join("derivative.pdf");
    fs::write(&derivative, "Simulated PDF derivative content").unwrap();

    
    let stdout = run_cpop_ok(
        data,
        &[
            "link",
            source.to_str().unwrap(),
            derivative.to_str().unwrap(),
            "-m",
            "PDF export",
        ],
    );
    assert!(
        stdout.contains("Link") || stdout.contains("link") || stdout.contains("Checkpoint"),
        "Link should confirm creation. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["log", source.to_str().unwrap()]);
    
    assert!(
        stdout.contains("#4") || stdout.contains("derivative") || stdout.contains("PDF export"),
        "Log should show the link checkpoint. Got: {}",
        stdout
    );
}





#[test]
fn scenario_multi_file_project() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let file_a = data.join("chapter1.txt");
    let file_b = data.join("chapter2.txt");
    let file_c = data.join("chapter3.txt");

    fs::write(&file_a, "Chapter 1: In the beginning").unwrap();
    fs::write(&file_b, "Chapter 2: The middle part").unwrap();
    fs::write(&file_c, "Chapter 3: The conclusion").unwrap();

    
    run_cpop_ok(
        data,
        &["commit", file_a.to_str().unwrap(), "-m", "Ch1 draft"],
    );
    run_cpop_ok(
        data,
        &["commit", file_b.to_str().unwrap(), "-m", "Ch2 draft"],
    );
    run_cpop_ok(
        data,
        &["commit", file_c.to_str().unwrap(), "-m", "Ch3 draft"],
    );

    
    let stdout = run_cpop_ok(data, &["log"]);
    assert!(
        stdout.contains("chapter1.txt") || stdout.contains("3 document"),
        "Log should list tracked documents. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("database"),
        "Status should show project info. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["log", file_b.to_str().unwrap()]);
    assert!(
        stdout.contains("Ch2 draft") || stdout.contains("chapter2"),
        "Log for chapter2 should show its checkpoint. Got: {}",
        stdout
    );
}





#[test]
fn scenario_json_output_modes() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let stdout = run_cpop_ok(data, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("data_dir").is_some(),
        "JSON status should have data_dir"
    );

    
    let doc = data.join("json_test.txt");
    fs::write(&doc, "Content for JSON test").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "JSON test", "--json"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(1),
        "Should have 1 checkpoint"
    );
}





#[test]
fn scenario_export_verify_roundtrip() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("roundtrip.txt");
    create_min_checkpoints(data, &doc);

    
    let evidence = data.join("roundtrip.evidence.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    assert!(evidence.exists());

    
    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    assert!(
        stdout.contains("Evidence packet Verified") || stdout.contains("Structural"),
        "Round-trip verification should confirm structural validity. Got: {}",
        stdout
    );
}





#[test]
fn test_track_creates_data_dir() {
    let dir = tempdir().unwrap();
    let data = dir.path().join("nested").join("cpop_data");
    
    assert!(!data.exists());

    
    let doc = dir.path().join("doc.txt");
    fs::write(&doc, "some content").unwrap();
    run_cpop_ok(&data, &["commit", doc.to_str().unwrap(), "-m", "first"]);

    assert!(
        data.exists(),
        "CPOP_DATA_DIR should be created on first use"
    );
}

#[test]
fn test_track_binary_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let bin_file = data.join("random.bin");
    
    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs::write(&bin_file, &bytes).unwrap();

    let stdout = run_cpop_ok(
        data,
        &["commit", bin_file.to_str().unwrap(), "-m", "binary file"],
    );
    assert!(
        stdout.contains("Checkpoint #1"),
        "Binary file commit should create checkpoint #1. Got: {}",
        stdout
    );
}

#[test]
fn test_track_symlink() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let real_file = data.join("real.txt");
    fs::write(&real_file, "symlink target content").unwrap();

    let link_path = data.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_file, &link_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&real_file, &link_path).unwrap();

    
    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", link_path.to_str().unwrap(), "-m", "via symlink"],
    );
    
    assert!(
        code == 0 || stderr.contains("symlink") || stderr.contains("resolve"),
        "Symlink commit should succeed or produce a symlink warning. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_track_large_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let large_file = data.join("large.txt");
    
    let content = "A".repeat(1_000_000);
    fs::write(&large_file, &content).unwrap();

    let start = std::time::Instant::now();
    let stdout = run_cpop_ok(
        data,
        &["commit", large_file.to_str().unwrap(), "-m", "large file"],
    );
    let elapsed = start.elapsed();

    assert!(
        stdout.contains("Checkpoint #1"),
        "Large file commit should succeed. Got: {}",
        stdout
    );
    assert!(
        elapsed.as_secs() < 30,
        "Large file commit should complete in <30s, took {:?}",
        elapsed
    );
}

#[test]
fn test_track_special_chars_in_path() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let subdir = data.join("my documents");
    fs::create_dir_all(&subdir).unwrap();
    let special_file = subdir.join("resume-draft_v2.txt");
    fs::write(&special_file, "Content with special path chars").unwrap();

    let stdout = run_cpop_ok(
        data,
        &[
            "commit",
            special_file.to_str().unwrap(),
            "-m",
            "special path",
        ],
    );
    assert!(
        stdout.contains("Checkpoint #1"),
        "File with special chars in path should commit. Got: {}",
        stdout
    );
}





#[test]
fn test_commit_empty_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let empty = data.join("empty.txt");
    fs::write(&empty, "").unwrap();

    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", empty.to_str().unwrap(), "-m", "empty file"],
    );
    
    assert!(
        code == 0 || stderr.contains("empty") || stderr.contains("Error"),
        "Empty file commit should either succeed or give a clear error. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_commit_unchanged_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("stable.txt");
    fs::write(&doc, "Unchanging content for both commits").unwrap();

    let stdout1 = run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "first commit"],
    );
    assert!(
        stdout1.contains("Checkpoint #1"),
        "First commit should succeed. Got: {}",
        stdout1
    );

    
    let stdout2 = run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "second commit"],
    );
    assert!(
        stdout2.contains("Checkpoint #2"),
        "Second commit of unchanged file should still succeed. Got: {}",
        stdout2
    );
}

#[test]
fn test_commit_with_message() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("msg_test.txt");
    fs::write(&doc, "Content for message test").unwrap();
    run_cpop_ok(
        data,
        &[
            "commit",
            doc.to_str().unwrap(),
            "-m",
            "My custom message here",
        ],
    );

    
    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("My custom message here"),
        "Log should show the commit message. Got: {}",
        stdout
    );
}

#[test]
fn test_commit_rapid_succession() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("rapid.txt");
    for i in 1..=5 {
        let content = format!("Rapid commit version {} with enough unique text", i);
        fs::write(&doc, &content).unwrap();
        let stdout = run_cpop_ok(
            data,
            &[
                "commit",
                doc.to_str().unwrap(),
                "-m",
                &format!("Rapid #{}", i),
            ],
        );
        assert!(
            stdout.contains(&format!("Checkpoint #{}", i)),
            "Rapid commit #{} should create checkpoint #{}. Got: {}",
            i,
            i,
            stdout
        );
    }

    
    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should parse: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(5),
        "Should have 5 checkpoints after rapid succession"
    );
}

#[test]
fn test_commit_after_delete_content() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("delete_test.txt");
    fs::write(&doc, "Full content that will be deleted").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "with content"],
    );

    
    fs::write(&doc, "").unwrap();
    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "after delete"],
    );
    
    assert!(
        code == 0 || stderr.contains("empty") || stderr.contains("Error"),
        "Commit after content deletion should handle gracefully. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}





#[test]
fn test_export_cpop_binary_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("binary_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("evidence.cpop");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cpop",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".cpop file should exist");
    let bytes = fs::read(&out_path).unwrap();
    assert!(
        bytes.len() > 10,
        ".cpop file should be non-trivial binary, got {} bytes",
        bytes.len()
    );
    
    
}

#[test]
fn test_export_cwar_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("cwar_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("evidence.cwar");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cwar",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".cwar file should exist");
    let size = fs::metadata(&out_path).unwrap().len();
    assert!(
        size > 0,
        ".cwar file should be non-empty, got {} bytes",
        size
    );
}

#[test]
fn test_export_html_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("html_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("report.html");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "html",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".html file should exist");
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("<html") || content.contains("<!DOCTYPE") || content.contains("<HTML"),
        "HTML export should contain HTML tags. Got first 200 chars: {}",
        &content[..200.min(content.len())]
    );
}

#[test]
fn test_export_pdf_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("pdf_export.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("report.pdf");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "pdf",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(out_path.exists(), ".pdf file should exist");
    let bytes = fs::read(&out_path).unwrap();
    assert!(
        bytes.starts_with(b"%PDF"),
        "PDF export should start with %PDF magic bytes. Got first 4 bytes: {:?}",
        &bytes[..4.min(bytes.len())]
    );
}

#[test]
fn test_export_c2pa_assertion_content() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("c2pa_content.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("assertion.c2pa.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "c2pa",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let content = fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("C2PA should be valid JSON");
    assert!(parsed.is_object(), "C2PA should be a JSON object");
    
    assert!(
        parsed.get("label").is_some()
            || parsed.get("assertion").is_some()
            || parsed.get("dc:title").is_some()
            || parsed.get("assertions").is_some(),
        "C2PA JSON should contain assertion-related fields. Keys: {:?}",
        parsed.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
}

#[test]
fn test_export_custom_output_path() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("custom_out.txt");
    create_min_checkpoints(data, &doc);

    
    let custom_dir = data.join("output").join("nested");
    fs::create_dir_all(&custom_dir).unwrap();
    let out_path = custom_dir.join("my_evidence.json");

    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(
        out_path.exists(),
        "Evidence should be written to custom output path: {}",
        out_path.display()
    );
    let content = fs::read_to_string(&out_path).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("Custom path output should be valid JSON");
}

#[test]
fn test_export_overwrites_existing() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("overwrite.txt");
    create_min_checkpoints(data, &doc);

    let out_path = data.join("overwrite.evidence.json");

    
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    let size1 = fs::metadata(&out_path).unwrap().len();
    assert!(size1 > 0, "First export should produce non-empty file");

    
    fs::write(
        &doc,
        "Version 4: even more content added for the overwrite test.",
    )
    .unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Draft 4"]);

    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    let size2 = fs::metadata(&out_path).unwrap().len();
    assert!(
        size2 > 0,
        "Second export should produce non-empty file (overwrite)"
    );
}





#[test]
fn test_verify_json_output() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_json.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("verify_json.evidence.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap(), "--json"]);
    
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "verify --json should produce valid JSON: {}\nGot: {}",
            e, stdout
        )
    });
    assert!(
        parsed.is_object(),
        "verify --json should return a JSON object"
    );
}

#[test]
fn test_verify_corrupted_evidence() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("corrupt_test.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("corrupt.evidence.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    
    let mut content = fs::read_to_string(&evidence).unwrap();
    
    content = content.replacen("\"content_hash\"", "\"content_hash_CORRUPTED\"", 1);
    fs::write(&evidence, &content).unwrap();

    let (stdout, stderr, code) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        code != 0
            || combined.to_lowercase().contains("fail")
            || combined.to_lowercase().contains("error")
            || combined.to_lowercase().contains("corrupt")
            || combined.to_lowercase().contains("invalid")
            || combined.contains("CORRUPTED"),
        "Corrupted evidence should be detected. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_verify_truncated_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let truncated = data.join("truncated.json");
    fs::write(&truncated, r#"{"version": 1, "checkpoints": ["#).unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", truncated.to_str().unwrap()]);
    assert_ne!(code, 0, "Truncated evidence file should fail verification");
    assert!(
        stderr.to_lowercase().contains("parse")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("Error")
            || stderr.to_lowercase().contains("eof"),
        "Should report parse error for truncated file. stderr: {}",
        stderr
    );
}

#[test]
fn test_verify_cwar_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_cwar.txt");
    create_min_checkpoints(data, &doc);

    let cwar_path = data.join("verify_test.cwar");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "cwar",
            "-o",
            cwar_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    assert!(cwar_path.exists(), ".cwar file should exist for verify");
    let (stdout, stderr, code) = run_cpop(data, &["verify", cwar_path.to_str().unwrap()]);
    
    assert!(
        code == 0
            || stderr.contains("Error")
            || stdout.contains("Verified")
            || stdout.contains("attestation"),
        "Verify of .cwar should produce meaningful output. \
         exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}





#[test]
fn test_log_empty_no_checkpoints() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("no_commits.txt");
    fs::write(&doc, "Never committed content").unwrap();

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("No checkpoints") || stdout.trim().is_empty(),
        "Log with no commits should show empty message. Got: {}",
        stdout
    );
}

#[test]
fn test_log_shows_messages() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("log_msg.txt");
    fs::write(&doc, "First version of the document").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "Initial rough draft"],
    );

    fs::write(&doc, "Second version with significant revisions applied").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "Major revision pass"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        stdout.contains("Initial rough draft"),
        "Log should show first message. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("Major revision pass"),
        "Log should show second message. Got: {}",
        stdout
    );
}

#[test]
fn test_log_json_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("log_json.txt");
    fs::write(&doc, "Content for JSON log test").unwrap();
    run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "JSON log entry"],
    );

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("checkpoint_count").is_some(),
        "JSON log should have checkpoint_count field. Got: {}",
        stdout
    );
    assert!(
        parsed.get("checkpoints").is_some(),
        "JSON log should have checkpoints array. Got: {}",
        stdout
    );
}

#[test]
fn test_log_per_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let file_a = data.join("alpha.txt");
    let file_b = data.join("beta.txt");

    fs::write(&file_a, "Alpha content").unwrap();
    fs::write(&file_b, "Beta content").unwrap();

    run_cpop_ok(
        data,
        &["commit", file_a.to_str().unwrap(), "-m", "Alpha commit"],
    );
    run_cpop_ok(
        data,
        &["commit", file_b.to_str().unwrap(), "-m", "Beta commit"],
    );

    
    let stdout_a = run_cpop_ok(data, &["log", file_a.to_str().unwrap()]);
    assert!(
        stdout_a.contains("Alpha commit"),
        "Log for alpha should show Alpha commit. Got: {}",
        stdout_a
    );
    assert!(
        !stdout_a.contains("Beta commit"),
        "Log for alpha should NOT show Beta commit. Got: {}",
        stdout_a
    );

    
    let stdout_b = run_cpop_ok(data, &["log", file_b.to_str().unwrap()]);
    assert!(
        stdout_b.contains("Beta commit"),
        "Log for beta should show Beta commit. Got: {}",
        stdout_b
    );
    assert!(
        !stdout_b.contains("Alpha commit"),
        "Log for beta should NOT show Alpha commit. Got: {}",
        stdout_b
    );
}





#[test]
fn test_status_no_tracking() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("Status") || stdout.contains("status") || stdout.contains("No"),
        "Status before any tracking should produce clean output. Got: {}",
        stdout
    );
}

#[test]
fn test_status_shows_tracked_files() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("tracked_status.txt");
    fs::write(&doc, "Content to track").unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Track me"]);

    let stdout = run_cpop_ok(data, &["status"]);
    assert!(
        stdout.contains("tracked_status.txt")
            || stdout.contains("1 document")
            || stdout.contains("Documents: 1")
            || stdout.contains("Tracked documents: 1"),
        "Status should mention tracked file. Got: {}",
        stdout
    );
}

#[test]
fn test_status_json_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert!(
        parsed.get("data_dir").is_some(),
        "JSON status should have data_dir. Got: {}",
        stdout
    );
}





#[test]
fn test_fingerprint_list() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (stdout, stderr, code) = run_cpop(data, &["fingerprint", "list"]);
    
    assert!(
        code == 0 || stderr.contains("Error"),
        "fingerprint list should not panic. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}

#[test]
fn test_fingerprint_show() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (stdout, stderr, code) = run_cpop(data, &["fingerprint", "show"]);
    
    assert!(
        code == 0 || stderr.contains("Error") || stderr.contains("No"),
        "fingerprint show should not panic. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}





#[test]
fn test_help_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["--help"]);
    assert!(
        stdout.contains("CPOP") || stdout.contains("cpop") || stdout.contains("Usage"),
        "--help should show usage information. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("commit") && stdout.contains("export") && stdout.contains("verify"),
        "--help should list main commands. Got: {}",
        stdout
    );
}

#[test]
fn test_version_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["--version"]);
    assert!(
        stdout.contains("cpop") || stdout.contains("CPOP"),
        "--version should contain program name. Got: {}",
        stdout
    );
    
    assert!(
        stdout.contains('.'),
        "--version should contain a version number with dots. Got: {}",
        stdout
    );
}

#[test]
fn test_subcommand_help() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    
    let stdout = run_cpop_ok(data, &["commit", "--help"]);
    assert!(
        stdout.contains("checkpoint") || stdout.contains("Checkpoint") || stdout.contains("commit"),
        "commit --help should describe the commit command. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("-m") || stdout.contains("--message"),
        "commit --help should mention the -m flag. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["export", "--help"]);
    assert!(
        stdout.contains("export") || stdout.contains("Export") || stdout.contains("evidence"),
        "export --help should describe the export command. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("json") && stdout.contains("cpop") && stdout.contains("cwar"),
        "export --help should list formats. Got: {}",
        stdout
    );

    
    let stdout = run_cpop_ok(data, &["verify", "--help"]);
    assert!(
        stdout.contains("Verify") || stdout.contains("verify") || stdout.contains("evidence"),
        "verify --help should describe the verify command. Got: {}",
        stdout
    );
}





#[test]
fn test_concurrent_commits_different_files() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let files: Vec<_> = (0..3)
        .map(|i| {
            let p = data.join(format!("concurrent_{}.txt", i));
            fs::write(&p, format!("Concurrent file {} content here", i)).unwrap();
            p
        })
        .collect();

    let handles: Vec<_> = files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let data_path = data.to_path_buf();
            let file_path = f.to_string_lossy().to_string();
            std::thread::spawn(move || {
                let (stdout, stderr, code) = run_cpop(
                    &data_path,
                    &["commit", &file_path, "-m", &format!("Thread {}", i)],
                );
                (stdout, stderr, code)
            })
        })
        .collect();

    let mut successes = 0;
    for h in handles {
        let (stdout, stderr, code) = h.join().expect("thread panicked");
        if code == 0 && stdout.contains("Checkpoint #1") {
            successes += 1;
        } else {
            
            assert!(
                stderr.contains("locked") || stderr.contains("busy") || code != 0,
                "Unexpected failure: stdout={}, stderr={}",
                stdout,
                stderr
            );
        }
    }
    assert!(
        successes >= 1,
        "At least one concurrent commit should succeed"
    );
}

#[test]
fn test_many_commits_single_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("many_commits.txt");
    let commit_count = 20;

    for i in 1..=commit_count {
        let content = format!(
            "Revision {} with unique text to differentiate each version",
            i
        );
        fs::write(&doc, &content).unwrap();
        run_cpop_ok(
            data,
            &["commit", doc.to_str().unwrap(), "-m", &format!("Rev {}", i)],
        );
    }

    let stdout = run_cpop_ok(data, &["log", doc.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should parse: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(commit_count),
        "Should have {} checkpoints",
        commit_count
    );
}

#[test]
fn test_large_commit_message() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("longmsg.txt");
    fs::write(&doc, "Content for long message test").unwrap();

    let long_msg = "A".repeat(1000);
    let stdout = run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", &long_msg]);
    assert!(
        stdout.contains("Checkpoint #1"),
        "Commit with 1000-char message should succeed. Got: {}",
        stdout
    );

    let log_out = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        log_out.contains(&long_msg[..50]),
        "Log should contain the long message. Got: {}",
        &log_out[..200.min(log_out.len())]
    );
}

#[test]
fn test_unicode_commit_message() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("unicode_msg.txt");
    fs::write(&doc, "Content for unicode message test").unwrap();

    let msg = "Draft with CJK chars and emoji: \u{1F4DD}\u{4E2D}\u{6587}\u{65E5}\u{672C}\u{8A9E}";
    let stdout = run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", msg]);
    assert!(
        stdout.contains("Checkpoint #1"),
        "Commit with unicode message should succeed. Got: {}",
        stdout
    );

    let log_out = run_cpop_ok(data, &["log", doc.to_str().unwrap()]);
    assert!(
        log_out.contains("\u{4E2D}\u{6587}"),
        "Log should preserve CJK characters. Got: {}",
        log_out
    );
}

#[test]
fn test_repeated_track_same_file() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("repeat_track.txt");
    fs::write(&doc, "Content version 1").unwrap();

    let stdout1 = run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "First"]);
    assert!(stdout1.contains("Checkpoint #1"));

    
    fs::write(&doc, "Content version 2").unwrap();
    let stdout2 = run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Second"]);
    assert!(
        stdout2.contains("Checkpoint #2"),
        "Repeated commit should increment checkpoint. Got: {}",
        stdout2
    );
}





#[test]
fn test_export_after_file_deleted() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("will_delete.txt");
    create_min_checkpoints(data, &doc);

    
    fs::remove_file(&doc).unwrap();

    
    let out_path = data.join("deleted.evidence.json");
    let (_, stderr, code) = run_cpop_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    assert_ne!(
        code, 0,
        "Export after file deletion should fail. stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("resolve") || stderr.contains("not found") || stderr.contains("No such"),
        "Should indicate file not found. stderr: {}",
        stderr
    );
}

#[test]
fn test_export_tier_basic() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("tier_basic.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("tier_basic.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-t",
            "basic",
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nBasic tier declaration\n"),
    );
    assert!(out.exists(), "Basic tier export should produce a file");
    let content = fs::read_to_string(&out).unwrap();
    let _: serde_json::Value =
        serde_json::from_str(&content).expect("Basic tier output should be valid JSON");
}

#[test]
fn test_export_tier_standard() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("tier_standard.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("tier_standard.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-t",
            "standard",
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nStandard tier declaration\n"),
    );
    assert!(out.exists(), "Standard tier export should produce a file");
}

#[test]
fn test_export_tier_enhanced() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("tier_enhanced.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("tier_enhanced.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-t",
            "enhanced",
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nEnhanced tier declaration\n"),
    );
    assert!(out.exists(), "Enhanced tier export should produce a file");
}

#[test]
fn test_export_stego_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("stego_test.txt");
    
    let long_text = |ver: u32| -> String {
        let base =
            "The quick brown fox jumps over the lazy dog and continues to run across the meadow ";
        format!("Version {} {}", ver, base.repeat(10))
    };
    fs::write(&doc, long_text(1)).unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Draft 1"]);
    fs::write(&doc, long_text(2)).unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Draft 2"]);
    fs::write(&doc, long_text(3)).unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Draft 3"]);

    let out = data.join("stego_test.json");
    let (_stdout, stderr, code) = run_cpop_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--stego",
            "--no-beacons",
        ],
        Some("n\nStego declaration\n"),
    );
    
    assert!(
        code == 0
            || stderr.contains("API")
            || stderr.contains("stego")
            || stderr.contains("watermark")
            || stderr.contains("validation"),
        "Stego flag should be accepted or give a clear warning. exit={}, stderr={}",
        code,
        stderr
    );
    if code == 0 {
        assert!(out.exists(), "Stego export should produce a file");
    }
}

#[test]
fn test_export_no_beacons_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("no_beacons.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("no_beacons.json");
    let (_stdout, stderr, _) = run_cpop_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nNo beacons declaration\n"),
    );
    
    let combined = format!("{}{}", _stdout, stderr);
    assert!(
        combined.contains("beacon") || combined.contains("Beacon") || out.exists(),
        "No-beacons flag should be acknowledged. stdout={}, stderr={}",
        _stdout,
        stderr
    );
}

#[test]
fn test_export_beacon_timeout_flag() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("beacon_timeout.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("beacon_timeout.json");
    let (_stdout, stderr, code) = run_cpop_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--beacon-timeout",
            "5",
            "--no-beacons",
        ],
        Some("n\nBeacon timeout declaration\n"),
    );
    assert_eq!(
        code, 0,
        "Export with beacon-timeout should succeed. stderr: {}",
        stderr
    );
    assert!(out.exists());
}

#[test]
fn test_export_json_structure() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("json_structure.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("structure.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nStructure test\n"),
    );

    let content = fs::read_to_string(&out).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("Export should be valid JSON");
    let obj = parsed.as_object().expect("Should be a JSON object");

    
    assert!(
        obj.contains_key("checkpoints") || obj.contains_key("events"),
        "Evidence JSON should have checkpoints or events. Keys: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
    assert!(
        obj.contains_key("declaration"),
        "Evidence JSON should have declaration. Keys: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
    assert!(
        obj.contains_key("document") || obj.contains_key("file_path") || obj.contains_key("title"),
        "Evidence JSON should have document info. Keys: {:?}",
        obj.keys().collect::<Vec<_>>()
    );
}

#[test]
fn test_export_c2pa_has_process_timestamps() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("c2pa_timestamps.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("timestamps.c2pa.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "c2pa",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nC2PA timestamps\n"),
    );

    let content = fs::read_to_string(&out).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("C2PA should be valid JSON");
    
    let json_str = serde_json::to_string(&parsed).unwrap();
    assert!(
        json_str.contains("processStart")
            || json_str.contains("process_start")
            || json_str.contains("when")
            || json_str.contains("timestamp"),
        "C2PA export should contain timestamp-related fields. Got keys: {:?}",
        parsed.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
}





#[test]
fn test_verify_shows_checkpoint_count() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_count.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("verify_count.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    assert!(
        stdout.contains("3") || stdout.contains("checkpoint"),
        "Verify output should mention checkpoint count or number 3. Got: {}",
        stdout
    );
}

#[test]
fn test_verify_shows_document_name() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("verify_docname.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("verify_docname.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    assert!(
        stdout.contains("verify_docname") || stdout.contains("Document"),
        "Verify output should mention the document name. Got: {}",
        stdout
    );
}

#[test]
fn test_verify_wrong_format() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let txt_file = data.join("plaintext.txt");
    fs::write(&txt_file, "This is a plain text file, not evidence").unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", txt_file.to_str().unwrap()]);
    assert_ne!(code, 0, "Verify of .txt file should fail");
    assert!(
        stderr.to_lowercase().contains("unknown")
            || stderr.to_lowercase().contains("format")
            || stderr.to_lowercase().contains("expected"),
        "Should mention unknown format. stderr: {}",
        stderr
    );
}

#[test]
fn test_verify_empty_json_object() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let empty_json = data.join("empty_obj.json");
    fs::write(&empty_json, "{}").unwrap();

    let (_, stderr, code) = run_cpop(data, &["verify", empty_json.to_str().unwrap()]);
    assert_ne!(code, 0, "Verify of empty JSON object should fail");
    assert!(
        stderr.contains("Error")
            || stderr.to_lowercase().contains("missing")
            || stderr.to_lowercase().contains("parse"),
        "Should indicate parse/missing field error. stderr: {}",
        stderr
    );
}

#[test]
fn test_verify_valid_packet_structure() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("roundtrip_verify.txt");
    create_min_checkpoints(data, &doc);

    let evidence = data.join("roundtrip_verify.json");
    run_cpop_ok_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            evidence.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );

    let (stdout, _, _) = run_cpop(data, &["verify", evidence.to_str().unwrap()]);
    assert!(
        stdout.contains("Verified") || stdout.contains("Structural") || stdout.contains("pass"),
        "Export-then-verify should confirm validity. Got: {}",
        stdout
    );
}





#[test]
fn test_config_set_and_get_multiple() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "true"]);
    run_cpop_ok(
        data,
        &["config", "set", "sentinel.heartbeat_interval_secs", "30"],
    );
    run_cpop_ok(data, &["config", "set", "privacy.hash_urls", "true"]);

    
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: true"),
        "auto_start should be true. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("heartbeat_interval_secs: 30"),
        "heartbeat should be 30. Got: {}",
        stdout
    );
    assert!(
        stdout.contains("hash_urls: true"),
        "hash_urls should be true. Got: {}",
        stdout
    );
}

#[test]
fn test_config_set_invalid_key() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let (_, stderr, code) = run_cpop(data, &["config", "set", "nonexistent.fake_key", "value"]);
    assert_ne!(code, 0, "Setting invalid config key should fail");
    assert!(
        stderr.to_lowercase().contains("unknown") || stderr.contains("Error"),
        "Should mention unknown key. stderr: {}",
        stderr
    );
}

#[test]
fn test_config_reset_to_default() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    run_cpop_ok(
        data,
        &["config", "set", "sentinel.heartbeat_interval_secs", "120"],
    );
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(stdout.contains("heartbeat_interval_secs: 120"));

    
    run_cpop_ok(
        data,
        &["config", "set", "sentinel.heartbeat_interval_secs", "10"],
    );
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("heartbeat_interval_secs: 10"),
        "Config should be reset to default. Got: {}",
        stdout
    );
}

#[test]
fn test_config_set_boolean_variants() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "1"]);
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: true"),
        "1 should map to true. Got: {}",
        stdout
    );

    run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "no"]);
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: false"),
        "no should map to false. Got: {}",
        stdout
    );

    run_cpop_ok(data, &["config", "set", "sentinel.auto_start", "yes"]);
    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("auto_start: true"),
        "yes should map to true. Got: {}",
        stdout
    );
}

#[test]
fn test_config_data_dir_shown() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["config", "show"]);
    assert!(
        stdout.contains("Data directory") || stdout.contains("data_dir"),
        "Config show should display data directory. Got: {}",
        stdout
    );
}





#[test]
fn test_identity_show_did() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["identity", "--did"]);
    assert!(
        stdout.contains("did:key:z"),
        "DID should start with did:key:z. Got: {}",
        stdout
    );
}

#[test]
fn test_identity_show_fingerprint() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["identity", "--fingerprint"]);
    let trimmed = stdout.trim();
    
    assert!(!trimmed.is_empty(), "Fingerprint should produce output");
    
    let has_hex = trimmed.chars().any(|c| c.is_ascii_hexdigit());
    assert!(
        has_hex,
        "Fingerprint should contain hex characters. Got: {}",
        trimmed
    );
}

#[test]
fn test_identity_mnemonic_backup() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let stdout = run_cpop_ok(data, &["identity", "--mnemonic"]);
    
    let mnemonic_words: Vec<&str> = stdout
        .split_whitespace()
        .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
        .collect();
    
    assert!(
        mnemonic_words.len() >= 12,
        "Mnemonic should have at least 12 words, got {}. Output: {}",
        mnemonic_words.len(),
        stdout
    );
}

#[test]
fn test_identity_persistence() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let did1 = run_cpop_ok(data, &["identity", "--did"]);
    let did2 = run_cpop_ok(data, &["identity", "--did"]);
    assert_eq!(
        did1.trim(),
        did2.trim(),
        "DID should be stable across invocations"
    );

    let fp1 = run_cpop_ok(data, &["identity", "--fingerprint"]);
    let fp2 = run_cpop_ok(data, &["identity", "--fingerprint"]);
    assert_eq!(
        fp1.trim(),
        fp2.trim(),
        "Fingerprint should be stable across invocations"
    );
}





#[test]
fn test_link_requires_tracked_source() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let source = data.join("untracked_source.txt");
    let derivative = data.join("derivative.pdf");
    fs::write(&source, "Source content").unwrap();
    fs::write(&derivative, "Derivative content").unwrap();

    let (_, stderr, code) = run_cpop(
        data,
        &[
            "link",
            source.to_str().unwrap(),
            derivative.to_str().unwrap(),
        ],
    );
    assert_ne!(code, 0, "Link with untracked source should fail");
    assert!(
        stderr.contains("evidence")
            || stderr.contains("Track")
            || stderr.contains("track")
            || stderr.contains("No"),
        "Should mention missing evidence chain. stderr: {}",
        stderr
    );
}

#[test]
fn test_link_derivative_must_exist() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let source = data.join("link_src.txt");
    create_min_checkpoints(data, &source);

    let (_, stderr, code) = run_cpop(
        data,
        &[
            "link",
            source.to_str().unwrap(),
            "/nonexistent/derivative.pdf",
        ],
    );
    assert_ne!(code, 0, "Link with nonexistent derivative should fail");
    assert!(
        stderr.contains("not found") || stderr.contains("Error") || stderr.contains("No such"),
        "Should mention file not found. stderr: {}",
        stderr
    );
}

#[test]
fn test_link_shows_in_log() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let source = data.join("link_log_src.txt");
    create_min_checkpoints(data, &source);

    let derivative = data.join("link_log_deriv.pdf");
    fs::write(&derivative, "PDF derivative content").unwrap();

    run_cpop_ok(
        data,
        &[
            "link",
            source.to_str().unwrap(),
            derivative.to_str().unwrap(),
            "-m",
            "Export link",
        ],
    );

    let stdout = run_cpop_ok(data, &["log", source.to_str().unwrap(), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("log --json should parse: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(4),
        "Should have 4 checkpoints (3 original + 1 link). Got: {}",
        stdout
    );
}

#[test]
fn test_link_to_self() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("self_link.txt");
    create_min_checkpoints(data, &doc);

    
    let (stdout, stderr, code) = run_cpop(
        data,
        &["link", doc.to_str().unwrap(), doc.to_str().unwrap()],
    );
    
    assert!(
        code == 0 || stderr.contains("Error"),
        "Link to self should handle gracefully. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}





#[test]
fn test_daemon_help() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["start", "--help"]);
    assert!(
        stdout.contains("daemon")
            || stdout.contains("start")
            || stdout.contains("Daemon")
            || stdout.contains("Start")
            || stdout.contains("sentinel"),
        "start --help should show daemon usage. Got: {}",
        stdout
    );
}

#[test]
fn test_presence_help() {
    let dir = tempdir().unwrap();
    let data = dir.path();

    let stdout = run_cpop_ok(data, &["presence", "--help"]);
    assert!(
        stdout.contains("presence") || stdout.contains("Presence") || stdout.contains("challenge"),
        "presence --help should show usage. Got: {}",
        stdout
    );
}





#[test]
fn test_corrupted_database() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    
    let doc = data.join("corrupt_db.txt");
    fs::write(&doc, "Content before corruption").unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Before"]);

    
    let db_path = data.join("events.db");
    if db_path.exists() {
        fs::write(&db_path, "CORRUPTED DATABASE CONTENT").unwrap();
    }

    
    let (_, stderr, code) = run_cpop(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "After corruption"],
    );
    assert_ne!(code, 0, "Commit on corrupted DB should fail");
    assert!(
        stderr.contains("Error")
            || stderr.to_lowercase().contains("database")
            || stderr.to_lowercase().contains("corrupt")
            || stderr.to_lowercase().contains("not a database"),
        "Should report database error. stderr: {}",
        stderr
    );
}

#[test]
fn test_permission_denied_data_dir() {
    
    if !cfg!(unix) {
        return;
    }

    let dir = tempdir().unwrap();
    let data = dir.path().join("readonly_data");
    fs::create_dir_all(&data).unwrap();
    init_cpop(&data);

    
    let mut perms = fs::metadata(&data).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o444);
    fs::set_permissions(&data, perms).unwrap();

    let doc = dir.path().join("readonly_test.txt");
    fs::write(&doc, "Content for readonly test").unwrap();

    let (_, stderr, code) = run_cpop(
        &data,
        &["commit", doc.to_str().unwrap(), "-m", "Should fail"],
    );

    
    let mut perms = fs::metadata(&data).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&data, perms).unwrap();

    assert_ne!(code, 0, "Commit with read-only data dir should fail");
    assert!(
        stderr.to_lowercase().contains("permission")
            || stderr.to_lowercase().contains("denied")
            || stderr.to_lowercase().contains("read-only")
            || stderr.contains("Error"),
        "Should mention permission error. stderr: {}",
        stderr
    );
}

#[test]
fn test_missing_data_dir_recovery() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("recovery_test.txt");
    fs::write(&doc, "Content before data dir removal").unwrap();
    run_cpop_ok(data, &["commit", doc.to_str().unwrap(), "-m", "Before"]);

    
    let db_path = data.join("events.db");
    if db_path.exists() {
        fs::remove_file(&db_path).unwrap();
    }

    
    fs::write(&doc, "Content after recovery").unwrap();
    let (stdout, stderr, code) = run_cpop(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "After recovery"],
    );
    
    assert!(
        (code == 0 && stdout.contains("Checkpoint #1"))
            || stderr.contains("Error")
            || stderr.contains("HMAC"),
        "Should recover or give clear error. exit={}, stdout={}, stderr={}",
        code,
        stdout,
        stderr
    );
}





#[test]
fn test_commit_json_output() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("commit_json.txt");
    fs::write(&doc, "Content for JSON commit output test").unwrap();

    let stdout = run_cpop_ok(
        data,
        &[
            "commit",
            doc.to_str().unwrap(),
            "-m",
            "JSON commit",
            "--json",
        ],
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("commit --json should be valid JSON: {}\nGot: {}", e, stdout));
    assert_eq!(
        parsed.get("checkpoint").and_then(|v| v.as_u64()),
        Some(1),
        "JSON commit should report checkpoint 1"
    );
    assert!(
        parsed.get("content_hash").is_some(),
        "JSON commit should include content_hash"
    );
    assert!(
        parsed.get("event_hash").is_some(),
        "JSON commit should include event_hash"
    );
    assert!(
        parsed.get("vdf_iterations").is_some(),
        "JSON commit should include vdf_iterations"
    );
}

#[test]
fn test_commit_quiet_mode() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("quiet_commit.txt");
    fs::write(&doc, "Content for quiet commit").unwrap();

    let stdout = run_cpop_ok(
        data,
        &["commit", doc.to_str().unwrap(), "-m", "Quiet", "--quiet"],
    );
    assert!(
        stdout.trim().is_empty(),
        "Quiet mode should produce no stdout. Got: {}",
        stdout
    );
}





#[test]
fn test_export_invalid_tier() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let doc = data.join("bad_tier.txt");
    create_min_checkpoints(data, &doc);

    let out = data.join("bad_tier.json");
    let (_, stderr, code) = run_cpop_with_stdin(
        data,
        &[
            "export",
            doc.to_str().unwrap(),
            "-t",
            "nonexistent",
            "-f",
            "json",
            "-o",
            out.to_str().unwrap(),
            "--no-beacons",
        ],
        Some("n\nDecl\n"),
    );
    assert_ne!(code, 0, "Export with invalid tier should fail");
    assert!(
        stderr.to_lowercase().contains("tier")
            || stderr.to_lowercase().contains("unknown")
            || stderr.contains("Error"),
        "Should mention invalid tier. stderr: {}",
        stderr
    );
}





#[test]
fn test_commit_blocked_extension() {
    let dir = tempdir().unwrap();
    let data = dir.path();
    init_cpop(data);

    let exe_file = data.join("malware.exe");
    fs::write(&exe_file, "pretend binary").unwrap();

    let (_, stderr, code) = run_cpop(
        data,
        &["commit", exe_file.to_str().unwrap(), "-m", "Should fail"],
    );
    assert_ne!(code, 0, "Commit of .exe should be blocked");
    assert!(
        stderr.to_lowercase().contains("not a supported")
            || stderr.to_lowercase().contains("blocked")
            || stderr.contains("Error"),
        "Should mention unsupported file type. stderr: {}",
        stderr
    );
}
