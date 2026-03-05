const logEl = document.getElementById('log');
const statusInput = document.getElementById('statusText');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const runBtn = document.getElementById('runBtn');
const pickReceivedBtn = document.getElementById('pickReceivedBtn');
const pickManifestBtn = document.getElementById('pickManifestBtn');
const pickOutputBtn = document.getElementById('pickOutputBtn');

function log(msg) {
  logEl.textContent += `${msg}\n`;
}

function setStatus(text) {
  statusInput.value = text;
}

function getInvoke() {
  const tauriGlobal = window.__TAURI__;
  if (!tauriGlobal) {
    throw new Error('未检测到 Tauri 运行时，请使用打包后的应用启动。');
  }
  const invoke = tauriGlobal?.tauri?.invoke || tauriGlobal?.core?.invoke || tauriGlobal?.invoke;
  if (typeof invoke !== 'function') {
    throw new Error('Tauri invoke API 不可用。');
  }
  return invoke;
}

async function call(name, payload) {
  const invoke = getInvoke();
  return invoke(name, payload || {});
}

pickReceivedBtn.addEventListener('click', async () => {
  try {
    const path = await call('pick_file', { filterExt: 'jsonl' });
    if (path) document.getElementById('receivedPath').value = path;
  } catch (e) {
    log(`选择文件失败：${e}`);
  }
});

pickManifestBtn.addEventListener('click', async () => {
  try {
    const path = await call('pick_file', { filterExt: 'json' });
    if (path) document.getElementById('manifestPath').value = path;
  } catch (e) {
    log(`选择文件失败：${e}`);
  }
});

pickOutputBtn.addEventListener('click', async () => {
  try {
    const path = await call('pick_folder');
    if (path) document.getElementById('outputDir').value = path;
  } catch (e) {
    log(`选择目录失败：${e}`);
  }
});

startBtn.addEventListener('click', async () => {
  const listenAddr = document.getElementById('listenAddr').value.trim();
  const receivedPath = document.getElementById('receivedPath').value.trim();
  if (!listenAddr || !receivedPath) {
    log('请填写监听地址和接收文件保存路径');
    return;
  }
  try {
    const res = await call('start_receiver_server', { listenAddr, receivedPath });
    setStatus(`运行中：${listenAddr}`);
    log(JSON.stringify(res, null, 2));
  } catch (e) {
    setStatus('启动失败');
    log(`启动失败：${e}`);
  }
});

stopBtn.addEventListener('click', async () => {
  try {
    const res = await call('stop_receiver_server');
    setStatus('已停止');
    log(JSON.stringify(res, null, 2));
  } catch (e) {
    log(`停止失败：${e}`);
  }
});

runBtn.addEventListener('click', async () => {
  const receivedPath = document.getElementById('receivedPath').value.trim();
  const manifestPath = document.getElementById('manifestPath').value.trim();
  const outputDir = document.getElementById('outputDir').value.trim();
  if (!receivedPath || !outputDir) {
    log('请填写接收文件路径与输出目录');
    return;
  }
  try {
    const res = await call('reconstruct', { receivedPath, manifestPath, outputDir });
    log(JSON.stringify(res, null, 2));
  } catch (e) {
    log(`重组失败：${e}`);
  }
});
