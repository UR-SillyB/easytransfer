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
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::api::dialog::blocking::FileDialogBuilder;

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

#[derive(Debug, Deserialize, Serialize)]
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
struct ServerReport {
    ok: bool,
    listen_addr: String,
    received_path: String,
    message: String,
}

struct ReceiverServerState {
    running: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    manifest_path: Arc<Mutex<Option<String>>>,
}

impl Default for ReceiverServerState {
    fn default() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            worker: None,
            manifest_path: Arc::new(Mutex::new(None)),
        }
    }
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
fn start_receiver_server(
    listen_addr: String,
    received_path: String,
    state: tauri::State<'_, Mutex<ReceiverServerState>>,
) -> Result<ServerReport, String> {
    let mut guard = state.lock().map_err(|_| "状态锁失败".to_string())?;
    if guard.running.load(Ordering::SeqCst) {
        return Ok(ServerReport {
            ok: true,
            listen_addr,
            received_path,
            message: "接收服务已在运行".to_string(),
        });
    }

    let listener = TcpListener::bind(&listen_addr).map_err(|e| format!("监听失败: {}", e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败: {}", e))?;

    let path = PathBuf::from(received_path.clone());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {}", e))?;
    }

    let manifest_auto = if let Some(parent) = path.parent() {
        parent.join("manifest.auto.json")
    } else {
        PathBuf::from("manifest.auto.json")
    };
    {
        let mut mg = guard
            .manifest_path
            .lock()
            .map_err(|_| "manifest路径锁失败".to_string())?;
        *mg = Some(manifest_auto.to_string_lossy().to_string());
    }

    let running = guard.running.clone();
    let manifest_path_arc = guard.manifest_path.clone();
    running.store(true, Ordering::SeqCst);

    let worker = thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mp = manifest_path_arc
                        .lock()
                        .ok()
                        .and_then(|x| x.clone())
                        .unwrap_or_default();
                    let _ = handle_windows_client(&mut stream, &path, Path::new(&mp));
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        std::thread::sleep(std::time::Duration::from_millis(120));
                    }
                }
            }
        }
    });

    guard.worker = Some(worker);

    Ok(ServerReport {
        ok: true,
        listen_addr,
        received_path,
        message: "接收服务已启动".to_string(),
    })
}

#[tauri::command]
fn stop_receiver_server(
    state: tauri::State<'_, Mutex<ReceiverServerState>>,
) -> Result<ServerReport, String> {
    let mut guard = state.lock().map_err(|_| "状态锁失败".to_string())?;
    if !guard.running.load(Ordering::SeqCst) {
        return Ok(ServerReport {
            ok: true,
            listen_addr: "".to_string(),
            received_path: "".to_string(),
            message: "接收服务未运行".to_string(),
        });
    }
    guard.running.store(false, Ordering::SeqCst);
    if let Some(worker) = guard.worker.take() {
        let _ = worker.join();
    }
    Ok(ServerReport {
        ok: true,
        listen_addr: "".to_string(),
        received_path: "".to_string(),
        message: "接收服务已停止".to_string(),
    })
}

#[tauri::command]
fn reconstruct(received_path: String, manifest_path: String, output_dir: String) -> Result<Report, String> {
    let mpath = if manifest_path.trim().is_empty() {
        let p = PathBuf::from(&received_path);
        if let Some(parent) = p.parent() {
            parent.join("manifest.auto.json")
        } else {
            PathBuf::from("manifest.auto.json")
        }
    } else {
        PathBuf::from(manifest_path)
    };
    let manifest_str = fs::read_to_string(&mpath).map_err(|e| e.to_string())?;
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

fn handle_windows_client(stream: &mut TcpStream, received_path: &Path, manifest_auto_path: &Path) -> Result<(), String> {
    let mut req = Vec::new();
    stream
        .read_to_end(&mut req)
        .map_err(|e| format!("读取请求失败: {}", e))?;
    let req_text = String::from_utf8_lossy(&req).to_string();
    if req_text.starts_with("POST /upload-manifest") {
        let parts: Vec<&str> = req_text.split("\r\n\r\n").collect();
        if parts.len() < 2 {
            write_http(stream, 400, "Bad Request", "{\"ok\":false,\"error\":\"body\"}")?;
            return Ok(());
        }
        fs::write(manifest_auto_path, parts[1]).map_err(|e| format!("写manifest失败: {}", e))?;
        write_http(stream, 200, "OK", "{\"ok\":true,\"saved\":\"manifest\"}")?;
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }

    if !req_text.starts_with("POST /upload-symbol") {
        write_http(stream, 404, "Not Found", "{\"ok\":false,\"error\":\"path\"}")?;
        return Ok(());
    }
    let parts: Vec<&str> = req_text.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        write_http(stream, 400, "Bad Request", "{\"ok\":false,\"error\":\"body\"}")?;
        return Ok(());
    }
    let body = parts[1];
    let rec: ReceivedRec = serde_json::from_str(body).map_err(|e| format!("解析JSON失败: {}", e))?;
    let _ = B64.decode(rec.data_b64.clone()).map_err(|e| format!("base64失败: {}", e))?;
    let line = serde_json::to_string(&rec).map_err(|e| format!("序列化失败: {}", e))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(received_path)
        .map_err(|e| format!("写入文件失败: {}", e))?;
    file.write_all(line.as_bytes())
        .map_err(|e| format!("写入失败: {}", e))?;
    file.write_all(b"\n").map_err(|e| format!("换行失败: {}", e))?;

    write_http(stream, 200, "OK", "{\"ok\":true,\"received\":true}")?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn write_http(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> Result<(), String> {
    let bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code,
        reason,
        bytes.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|e| format!("响应头失败: {}", e))?;
    stream
        .write_all(bytes)
        .map_err(|e| format!("响应体失败: {}", e))?;
    stream.flush().map_err(|e| format!("刷新失败: {}", e))?;
    Ok(())
}

#[tauri::command]
fn pick_file(filter_ext: String) -> Result<String, String> {
    let mut builder = FileDialogBuilder::new();
    if !filter_ext.trim().is_empty() {
        builder = builder.add_filter("文件", &[filter_ext.as_str()]);
    }
    let picked = builder.pick_file();
    Ok(picked
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default())
}

#[tauri::command]
fn pick_folder() -> Result<String, String> {
    let picked = FileDialogBuilder::new().pick_folder();
    Ok(picked
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default())
}

fn main() {
    tauri::Builder::default()
        .manage(Mutex::new(ReceiverServerState::default()))
        .invoke_handler(tauri::generate_handler![
            reconstruct,
            start_receiver_server,
            stop_receiver_server,
            pick_file,
            pick_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
