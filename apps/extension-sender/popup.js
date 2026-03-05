const fileInput = document.getElementById('fileInput');
const fpsInput = document.getElementById('fpsInput');
const symbolInput = document.getElementById('symbolInput');
const redundancyInput = document.getElementById('redundancyInput');
const prepareBtn = document.getElementById('prepareBtn');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const frameCanvas = document.getElementById('frameCanvas');
const logEl = document.getElementById('log');

const ctx = frameCanvas.getContext('2d');

let frames = [];
let timer = null;
let frameIndex = 0;

function log(msg) {
  logEl.textContent += `${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(hash);
}

async function compressBestForSmallFile(raw) {
  const size = raw.byteLength;
  if (size <= 1024 * 1024 && 'CompressionStream' in self) {
    const candidates = ['gzip', 'deflate'];
    let best = { codec: 'none', payload: raw };
    for (const codec of candidates) {
      try {
        const cs = new CompressionStream(codec);
        const writer = cs.writable.getWriter();
        writer.write(raw);
        writer.close();
        const payload = await new Response(cs.readable).arrayBuffer();
        if (payload.byteLength < best.payload.byteLength) {
          best = { codec, payload };
        }
      } catch (_e) {
      }
    }
    return best;
  }
  return { codec: 'none', payload: raw };
}

function bytesToSymbols(bytes, symbolSize) {
  const u8 = new Uint8Array(bytes);
  const symbols = [];
  for (let i = 0; i < u8.length; i += symbolSize) {
    symbols.push(u8.slice(i, i + symbolSize));
  }
  if (symbols.length === 0) symbols.push(new Uint8Array());
  return symbols;
}

function xorSymbols(symbols, indices) {
  const maxLen = Math.max(...indices.map(i => symbols[i].length), 0);
  const out = new Uint8Array(maxLen);
  for (const idx of indices) {
    const src = symbols[idx];
    for (let i = 0; i < maxLen; i += 1) {
      out[i] ^= (i < src.length ? src[i] : 0);
    }
  }
  return out;
}

function encodeFrameText(obj) {
  return JSON.stringify(obj);
}

function drawFrameText(text) {
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, frameCanvas.width, frameCanvas.height);
  const bytes = new TextEncoder().encode(text);
  const grid = 64;
  const cell = Math.floor(frameCanvas.width / grid);
  for (let i = 0; i < grid * grid; i += 1) {
    const b = bytes[i % bytes.length] ?? 0;
    const x = (i % grid) * cell;
    const y = Math.floor(i / grid) * cell;
    const v = (b % 2) ? 0 : 255;
    ctx.fillStyle = `rgb(${v},${v},${v})`;
    ctx.fillRect(x, y, cell, cell);
  }
}

async function prepareFrames() {
  const files = [...fileInput.files];
  if (!files.length) {
    log('未选择文件');
    return;
  }
  const symbolSize = Math.max(128, Number(symbolInput.value || 1024));
  const redundancy = Math.max(0, Number(redundancyInput.value || 0.2));
  frames = [];

  let fileId = 0;
  for (const file of files) {
    const raw = await file.arrayBuffer();
    const hash = await sha256Hex(raw);
    const compressed = await compressBestForSmallFile(raw);
    const symbols = bytesToSymbols(compressed.payload, symbolSize);
    const k = symbols.length;
    const repairCount = Math.ceil(k * redundancy);
    const sourceIds = [];

    frames.push(encodeFrameText({ kind: 'file_header', fileId, name: file.name, size: file.size, codec: compressed.codec }));
    for (let i = 0; i < symbols.length; i += 1) {
      const sid = `f${fileId}:b0:s${i}`;
      sourceIds.push(sid);
      frames.push(encodeFrameText({
        kind: 'symbol',
        fileId,
        block: 0,
        symbol: i,
        symbol_id: sid,
        k,
        redundant: false,
        payload_b64: btoa(String.fromCharCode(...symbols[i])),
      }));
    }
    for (let r = 0; r < repairCount; r += 1) {
      const width = Math.min(Math.max(2, Math.floor(Math.sqrt(k)) + 1), k);
      const start = (r * width) % Math.max(1, k);
      const indices = [];
      for (let i = 0; i < width; i += 1) indices.push((start + i) % Math.max(1, k));
      const unique = [...new Set(indices)].sort((a, b) => a - b);
      const parity = xorSymbols(symbols, unique);
      frames.push(encodeFrameText({
        kind: 'symbol',
        fileId,
        block: 0,
        symbol: k + r,
        symbol_id: `f${fileId}:b0:r${r}`,
        k,
        redundant: true,
        xor_of: unique.map(i => `f${fileId}:b0:s${i}`),
        payload_b64: btoa(String.fromCharCode(...parity)),
      }));
    }
    frames.push(encodeFrameText({
      kind: 'file_footer',
      fileId,
      name: file.name,
      sha256: hash,
      compression: compressed.codec,
      source_symbol_ids: sourceIds,
      compressed_bytes: compressed.payload.byteLength,
    }));
    log(`已处理 ${file.name} -> 源符号=${k}，修复符号=${repairCount}，压缩=${compressed.codec}`);
    fileId += 1;
  }
  startBtn.disabled = false;
  log(`码帧总数：${frames.length}`);
}

function startPlayback() {
  if (!frames.length) return;
  const fps = Math.max(1, Number(fpsInput.value || 30));
  const interval = Math.floor(1000 / fps);
  if (timer) clearInterval(timer);
  frameIndex = 0;
  startBtn.disabled = true;
  stopBtn.disabled = false;
  timer = setInterval(() => {
    const frame = frames[frameIndex % frames.length];
    drawFrameText(frame);
    frameIndex += 1;
  }, interval);
  log(`已开始播放，帧率 ${fps} FPS`);
}

function stopPlayback() {
  if (timer) clearInterval(timer);
  timer = null;
  startBtn.disabled = false;
  stopBtn.disabled = true;
  log('已停止播放');
}

prepareBtn.addEventListener('click', () => {
  prepareFrames().catch(err => log(`生成失败：${err.message || err}`));
});
startBtn.addEventListener('click', startPlayback);
stopBtn.addEventListener('click', stopPlayback);
