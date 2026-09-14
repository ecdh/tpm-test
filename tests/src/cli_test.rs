use std::path::{Path, PathBuf};
use std::process::Command;
use tpm_test_support::tpm_test;

fn find_tpm_tool() -> PathBuf {
    let candidates = [
        PathBuf::from("tpm_tool/tpm_tool"),
        PathBuf::from("../tpm_tool/tpm_tool"),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }
    if let Ok(runfiles_dir) = std::env::var("RUNFILES_DIR") {
        let dir = Path::new(&runfiles_dir);
        for workspace in ["_main", "tpm_test"] {
            let p = dir.join(workspace).join("tpm_tool/tpm_tool");
            if p.exists() {
                return p;
            }
        }
    }
    panic!("Cannot find tpm_tool binary in runfiles");
}

fn run_cli(args: &[&str]) -> String {
    let bin = find_tpm_tool();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {:?} {:?}: {}", bin, args, e));
    assert!(
        output.status.success(),
        "tpm_tool {:?} failed with status {:?}\nstdout: {}\nstderr: {}",
        args,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[tpm_test(
    categories = "Compliance | Smoke",
    hierarchies = "Owner | Endorsement",
    description = "Validates tpm_tool CLI subcommands end-to-end against live TPM"
)]
fn test_tpm_tool_cli() {
    run_cli(&["startup", "--clear"]);

    let random_out = run_cli(&["get-random", "32"]);
    assert_eq!(random_out.trim().len(), 64, "Expected 32 random bytes (64 hex chars)");

    let hash_out = run_cli(&["hash", "--data", "hello world"]);
    assert_eq!(
        hash_out.trim(),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    run_cli(&["pcr", "read", "10"]);
    run_cli(&[
        "pcr",
        "extend",
        "10",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ]);
    run_cli(&["pcr", "read", "10"]);

    run_cli(&["ek", "get", "--ecc", "nist-p256"]);

    let quote_out = run_cli(&["quote", "10", "--data", "nonce-1234"]);
    assert!(
        quote_out.contains("Verify: true"),
        "Quote signature verification should succeed"
    );
}
