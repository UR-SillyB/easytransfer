#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct ManifestFile {
    path: String,
    size: usize,
    sha256: String,
    compression: String,
    source_symbol_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
struct ReceivedRec {
    symbol_id: String,
    data_b64: String,
}

#[derive(Debug, Deserialize)]
struct AndroidPayloadRec {
    symbol_id: Option<String>,
    data_b64: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    ok: bool,
    files_written: Vec<String>,
    files_failed: Vec<String>,
    missing_source_symbols: Vec<String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UploadReport {
    ok: bool,
    status_line: String,
    bytes_sent: usize,
    response_body: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let rel = Path::new(relative);
    if rel.is_absolute() || relative.contains("..") {
        return Err("unsafe output path".to_string());
    }
    let full = root.join(rel).canonicalize().unwrap_or_else(|_| root.join(rel));
    let base = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !full.starts_with(&base) {
        return Err("unsafe output path".to_string());
    }
    Ok(full)
}

fn decompress(codec: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match codec.to_lowercase().as_str() {
        "none" => Ok(data.to_vec()),
        "zlib" => {
            let mut d = ZlibDecoder::new(data);
            let mut out = Vec::new();
            d.read_to_end(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        }
        "gzip" => {
            let mut d = GzDecoder::new(data);
            let mut out = Vec::new();
            d.read_to_end(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        }
        "deflate" => {
            let mut d = DeflateDecoder::new(data);
            let mut out = Vec::new();
            d.read_to_end(&mut out).map_err(|e| e.to_string())?;
            Ok(out)
        }
        _ => Ok(data.to_vec()),
    }
}

#[tauri::command]
fn upload_to_android(android_addr: String, file_path: String) -> Result<UploadReport, String> {
    let addr = if android_addr.contains(':') {
        android_addr
    } else {
        format!("{}:18777", android_addr)
    };

    let payload = fs::read(&file_path).map_err(|e| format!("读取文件失败: {}", e))?;
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("连接 Android 失败: {}", e))?;

    let request_head = format!(
        "POST /upload HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr,
        payload.len()
    );
    stream
        .write_all(request_head.as_bytes())
        .map_err(|e| format!("发送请求头失败: {}", e))?;
    stream
        .write_all(&payload)
        .map_err(|e| format!("发送请求体失败: {}", e))?;
    stream.flush().map_err(|e| format!("刷新发送失败: {}", e))?;

    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("读取响应失败: {}", e))?;

    let mut lines = resp.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 000 UNKNOWN").to_string();
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    let ok = status_line.contains(" 200 ");

    Ok(UploadReport {
        ok,
        status_line,
        bytes_sent: payload.len(),
        response_body: body,
    })
}

#[tauri::command]
fn reconstruct(received_path: String, manifest_path: String, output_dir: String) -> Result<Report, String> {
    let manifest_str = fs::read_to_string(&manifest_path).map_err(|e| e.to_string())?;
    let manifest: Manifest = serde_json::from_str(&manifest_str).map_err(|e| e.to_string())?;

    let symbol_map = load_symbol_map(&received_path)?;

    let out_dir = PathBuf::from(output_dir);
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

    let mut report = Report {
        ok: true,
        files_written: vec![],
        files_failed: vec![],
        missing_source_symbols: vec![],
        errors: vec![],
    };

    for file in manifest.files {
        let mut chunks: Vec<u8> = vec![];
        let mut missing = false;
        for sid in &file.source_symbol_ids {
            if let Some(bytes) = symbol_map.get(sid) {
                chunks.extend_from_slice(bytes);
            } else {
                report.missing_source_symbols.push(sid.clone());
                missing = true;
            }
        }
        if missing {
            report.files_failed.push(file.path.clone());
            report.ok = false;
            continue;
        }

        match decompress(&file.compression, &chunks) {
            Ok(raw) => {
                if raw.len() != file.size {
                    report.errors.push(format!("size mismatch: {}", file.path));
                    report.files_failed.push(file.path.clone());
                    report.ok = false;
                    continue;
                }
                let got = sha256_hex(&raw);
                if got != file.sha256 {
                    report.errors.push(format!("sha mismatch: {}", file.path));
                    report.files_failed.push(file.path.clone());
                    report.ok = false;
                    continue;
                }
                let out_path = safe_join(&out_dir, &file.path)?;
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                fs::write(&out_path, raw).map_err(|e| e.to_string())?;
                report.files_written.push(file.path.clone());
            }
            Err(e) => {
                report.errors.push(format!("decompress error {}: {}", file.path, e));
                report.files_failed.push(file.path.clone());
                report.ok = false;
            }
        }
    }

    let report_path = out_dir.join("receiver_report.json");
    fs::write(
        report_path,
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    Ok(report)
}

fn load_symbol_map(path: &str) -> Result<HashMap<String, Vec<u8>>, String> {
    let mut symbol_map: HashMap<String, Vec<u8>> = HashMap::new();
    let received_text = fs::read_to_string(path).map_err(|e| e.to_string())?;

    let mut parsed_jsonl = false;
    for line in received_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<ReceivedRec>(line) {
            let bytes = B64.decode(rec.data_b64).map_err(|e| e.to_string())?;
            symbol_map.insert(rec.symbol_id, bytes);
            parsed_jsonl = true;
        }
    }
    if parsed_jsonl {
        return Ok(symbol_map);
    }

    for line in received_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<AndroidPayloadRec>(line) {
            if let (Some(symbol_id), Some(data_b64)) = (rec.symbol_id, rec.data_b64) {
                let bytes = B64.decode(data_b64).map_err(|e| e.to_string())?;
                symbol_map.insert(symbol_id, bytes);
            }
        }
    }

    Ok(symbol_map)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![reconstruct, upload_to_android])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
