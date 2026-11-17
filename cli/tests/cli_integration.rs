use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn oursecret_bin() -> &'static str {
    env!("CARGO_BIN_EXE_oursecret")
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oursecret_cli_test_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_hide_and_extract_roundtrip_append() {
    let dir = unique_temp_dir("roundtrip");
    let carrier = dir.join("portador.bin");
    let secret = dir.join("secreto.txt");
    let stego = dir.join("salida.bin");
    let out_dir = dir.join("extraido");

    fs::write(&carrier, b"contenido portador de prueba").unwrap();
    fs::write(&secret, b"datos confidenciales").unwrap();

    let hide_out = Command::new(oursecret_bin())
        .args([
            "hide",
            "--carrier",
            carrier.to_str().unwrap(),
            "--output",
            stego.to_str().unwrap(),
            "--file",
            secret.to_str().unwrap(),
            "--message",
            "Aviso:hola desde cli",
            "--mode",
            "append",
            "--password",
            "clave-segura",
        ])
        .output()
        .unwrap();
    assert!(
        hide_out.status.success(),
        "hide falló: {}",
        String::from_utf8_lossy(&hide_out.stderr)
    );

    let extract_out = Command::new(oursecret_bin())
        .args([
            "extract",
            "--input",
            stego.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--password",
            "clave-segura",
        ])
        .output()
        .unwrap();
    assert!(
        extract_out.status.success(),
        "extract falló: {}",
        String::from_utf8_lossy(&extract_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&extract_out.stdout);
    assert!(stdout.contains("Aviso"), "{stdout}");
    assert!(stdout.contains("hola desde cli"), "{stdout}");
    assert_eq!(
        fs::read(out_dir.join("secreto.txt")).unwrap(),
        b"datos confidenciales"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_rejects_empty_subject_and_duplicate_filenames() {
    let dir = unique_temp_dir("validation");
    let sub1 = dir.join("a");
    let sub2 = dir.join("b");
    fs::create_dir_all(&sub1).unwrap();
    fs::create_dir_all(&sub2).unwrap();

    let carrier = dir.join("c.bin");
    let out = dir.join("o.bin");
    let f1 = sub1.join("nota.txt");
    let f2 = sub2.join("nota.txt");
    fs::write(&carrier, b"portador").unwrap();
    fs::write(&f1, b"1").unwrap();
    fs::write(&f2, b"2").unwrap();

    let empty_subj = Command::new(oursecret_bin())
        .args([
            "hide",
            "-c",
            carrier.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-m",
            ":texto",
            "-p",
            "pw",
        ])
        .output()
        .unwrap();
    assert!(!empty_subj.status.success());

    let dup_files = Command::new(oursecret_bin())
        .args([
            "hide",
            "-c",
            carrier.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-f",
            f1.to_str().unwrap(),
            "-f",
            f2.to_str().unwrap(),
            "-p",
            "pw",
        ])
        .output()
        .unwrap();
    assert!(!dup_files.status.success());

    let _ = fs::remove_dir_all(&dir);
}
