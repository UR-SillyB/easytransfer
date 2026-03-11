# EasyTransfer Three-End Delivery

## Delivered Components

1. **Browser Sender Extension**
   - Path: `apps/extension-sender`
   - Package: `packaging/deliverables/extension-sender.zip`
   - Features: file selection, size-based compression choice for small files, symbol+repair frame generation, frame playback canvas.

2. **Android Scanner App (source package)**
   - Path: `apps/android-scanner`
   - Package: `packaging/deliverables/android-scanner-source.zip`
   - Features: CameraX preview, ZXing decode, symbol deduplication, `received.jsonl` + `feedback.json` export.

3. **Windows Receiver App (Tauri source package)**
   - Path: `apps/windows-receiver-tauri`
   - Features: receive Android uploads (`/upload-manifest`, `/upload-symbol`), reconstruct files, verify size/hash, generate `receiver_report.json`.

4. **Core Protocol/Tooling Package**
   - Python dist: `dist/easytransfer-0.1.0-py3-none-any.whl`, `dist/easytransfer-0.1.0.tar.gz`

## Verification Results

- Python unit/integration tests: PASS (`9 passed`)
- End-to-end pipeline demo: PASS (`out/e2e-demo` generated with sender/scan/recv artifacts)
- Compression policy check from manifest (interop profile):
  - Sender now constrains transfer codecs to `none/zlib/gzip/deflate` for cross-end compatibility.
  - Typical demo outputs: `small.txt` -> `deflate`, `medium.txt` -> `zlib`, `blob.bin` -> `none`.

## Environment Constraints Encountered

- Android build can be compiled in this environment with Gradle, but requires standard Android SDK/toolchain setup on CI/build hosts.

Source projects and packaging scripts are provided for build on proper Windows/Android build hosts.
