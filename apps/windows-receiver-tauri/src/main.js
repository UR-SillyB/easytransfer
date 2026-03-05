const logEl = document.getElementById('log');
const runBtn = document.getElementById('runBtn');
const sendBtn = document.getElementById('sendBtn');

function log(msg) {
  logEl.textContent += `${msg}\n`;
}

runBtn.addEventListener('click', async () => {
  const receivedPath = document.getElementById('uploadFilePath').value.trim();
  const manifestPath = document.getElementById('manifestPath').value.trim();
  const outputDir = document.getElementById('outputDir').value.trim();

  if (!receivedPath || !manifestPath || !outputDir) {
    log('请填写重组所需路径');
    return;
  }

  try {
    const { invoke } = window.__TAURI__.tauri;
    const res = await invoke('reconstruct', { receivedPath, manifestPath, outputDir });
    log(JSON.stringify(res, null, 2));
  } catch (e) {
    log(`重组失败：${e}`);
  }
});

sendBtn.addEventListener('click', async () => {
  const androidAddr = document.getElementById('androidAddr').value.trim();
  const uploadFilePath = document.getElementById('uploadFilePath').value.trim();
  if (!androidAddr || !uploadFilePath) {
    log('请填写 Android 地址和文件路径');
    return;
  }
  try {
    const { invoke } = window.__TAURI__.tauri;
    const res = await invoke('upload_to_android', { androidAddr, filePath: uploadFilePath });
    log(JSON.stringify(res, null, 2));
  } catch (e) {
    log(`发送失败：${e}`);
  }
});
