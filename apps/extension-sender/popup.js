const fileInput = document.getElementById('fileInput');
const fpsInput = document.getElementById('fpsInput');
const symbolInput = document.getElementById('symbolInput');
const blockInput = document.getElementById('blockInput');
const redundancyInput = document.getElementById('redundancyInput');
const prepareBtn = document.getElementById('prepareBtn');
const exportMissingBtn = document.getElementById('exportMissingBtn');
const startBtn = document.getElementById('startBtn');
const repairBtn = document.getElementById('repairBtn');
const stopBtn = document.getElementById('stopBtn');
const missingInput = document.getElementById('missingInput');
const frameCanvas = document.getElementById('frameCanvas');
const stats = document.getElementById('stats');
const logEl = document.getElementById('log');

const ctx = frameCanvas.getContext('2d');

let allFrames = [];
let playFrames = [];
let timer = null;
let frameIndex = 0;
let currentTransferId = '';
let symbolIndex = new Map();

function log(msg) {
  logEl.textContent += `${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
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

function iterChunks(u8, size) {
  const arr = [];
  for (let i = 0; i < u8.length; i += size) {
    arr.push(u8.slice(i, i + size));
  }
  if (!arr.length) arr.push(new Uint8Array());
  return arr;
}

function xorSymbols(symbols, indices) {
  const maxLen = Math.max(...indices.map((i) => symbols[i].length), 0);
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

function makeSymbolId(tid, fileId, blockId, symbolId) {
  return `${tid}:f${fileId}:b${blockId}:s${symbolId}`;
}

function crc32(u8) {
  let c = -1;
  for (let i = 0; i < u8.length; i += 1) {
    c ^= u8[i];
    for (let j = 0; j < 8; j += 1) {
      const m = -(c & 1);
      c = (c >>> 1) ^ (0xEDB88320 & m);
    }
  }
  return (c ^ -1) >>> 0;
}

function randomTransferId() {
  return `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

async function prepareFrames() {
  const files = [...fileInput.files];
  if (!files.length) {
    log('未选择文件');
    return;
  }

  const symbolSize = Math.max(128, Number(symbolInput.value || 1024));
  const blockSize = Math.max(symbolSize, Number(blockInput.value || 65536));
  const redundancy = Math.max(0, Number(redundancyInput.value || 0.2));
  currentTransferId = randomTransferId();
  allFrames = [];
  symbolIndex = new Map();

  let frameSeq = 0;
  let totalSymbols = 0;
  const indexRows = [];

  for (let fileId = 0; fileId < files.length; fileId += 1) {
    const file = files[fileId];
    const rawBuf = await file.arrayBuffer();
    const raw = new Uint8Array(rawBuf);
    const fileHash = await sha256Hex(rawBuf);
    const compressed = await compressBestForSmallFile(rawBuf);
    const compU8 = new Uint8Array(compressed.payload);
    const blocks = iterChunks(compU8, blockSize);

    allFrames.push(encodeFrameText({
      v: 1,
      kind: 'file_header',
      transfer_id: currentTransferId,
      frame_seq: frameSeq,
      file_id: fileId,
      file_name: file.name,
      file_size: file.size,
      file_sha256: fileHash,
      compression: compressed.codec,
      block_total: blocks.length,
      ts: Date.now(),
    }));
    frameSeq += 1;

    for (let blockId = 0; blockId < blocks.length; blockId += 1) {
      const symbols = iterChunks(blocks[blockId], symbolSize);
      const symbolTotal = symbols.length;
      const repairCount = Math.ceil(symbolTotal * redundancy);

      for (let symbolId = 0; symbolId < symbolTotal; symbolId += 1) {
        const sid = makeSymbolId(currentTransferId, fileId, blockId, symbolId);
        const payload = symbols[symbolId];
        const rec = {
          v: 1,
          kind: 'symbol',
          transfer_id: currentTransferId,
          frame_seq: frameSeq,
          file_id: fileId,
          block_id: blockId,
          block_total: blocks.length,
          symbol_id: symbolId,
          symbol_total: symbolTotal,
          is_repair: false,
          stable_symbol_id: sid,
          payload_b64: btoa(String.fromCharCode(...payload)),
          payload_sha256: await sha256Hex(payload.buffer),
          payload_crc32: crc32(payload),
          ts: Date.now(),
        };
        const text = encodeFrameText(rec);
        allFrames.push(text);
        symbolIndex.set(sid, text);
        indexRows.push(sid);
        frameSeq += 1;
        totalSymbols += 1;
      }

      for (let r = 0; r < repairCount; r += 1) {
        const width = Math.min(Math.max(2, Math.floor(Math.sqrt(symbolTotal)) + 1), symbolTotal);
        const start = (r * width) % Math.max(1, symbolTotal);
        const indices = [];
        for (let i = 0; i < width; i += 1) indices.push((start + i) % Math.max(1, symbolTotal));
        const uniq = [...new Set(indices)].sort((a, b) => a - b);
        const parity = xorSymbols(symbols, uniq);
        const sid = `${currentTransferId}:f${fileId}:b${blockId}:r${r}`;
        const rec = {
          v: 1,
          kind: 'symbol',
          transfer_id: currentTransferId,
          frame_seq: frameSeq,
          file_id: fileId,
          block_id: blockId,
          block_total: blocks.length,
          symbol_id: symbolTotal + r,
          symbol_total: symbolTotal + repairCount,
          is_repair: true,
          stable_symbol_id: sid,
          repair_of: uniq.map((x) => makeSymbolId(currentTransferId, fileId, blockId, x)),
          payload_b64: btoa(String.fromCharCode(...parity)),
          payload_sha256: await sha256Hex(parity.buffer),
          payload_crc32: crc32(parity),
          ts: Date.now(),
        };
        const text = encodeFrameText(rec);
        allFrames.push(text);
        symbolIndex.set(sid, text);
        frameSeq += 1;
      }
    }
  }

  startBtn.disabled = false;
  repairBtn.disabled = false;
  stats.textContent = `传输ID: ${currentTransferId} | 分片总数: ${totalSymbols} | 总帧数: ${allFrames.length}`;
  log(`已生成完成，传输ID=${currentTransferId}`);

  const indexBlob = new Blob([JSON.stringify({ transfer_id: currentTransferId, symbol_ids: indexRows }, null, 2)], { type: 'application/json' });
  exportMissingBtn.onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(indexBlob);
    a.download = `symbol-index-${currentTransferId}.json`;
    a.click();
  };
}

function startPlayback(mode) {
  if (!allFrames.length) return;
  if (timer) clearInterval(timer);

  if (mode === 'missing') {
    let missingIds = [];
    try {
      const parsed = JSON.parse(missingInput.value || '{}');
      missingIds = Array.isArray(parsed.missing_symbol_ids) ? parsed.missing_symbol_ids : [];
    } catch (_e) {
      log('缺失分片 JSON 解析失败');
      return;
    }
    playFrames = missingIds.map((id) => symbolIndex.get(id)).filter(Boolean);
    if (!playFrames.length) {
      log('未匹配到缺失分片');
      return;
    }
    log(`进入补传播放，缺失分片数=${playFrames.length}`);
  } else {
    playFrames = allFrames;
    log('开始全量播放');
  }

  const fps = Math.max(1, Number(fpsInput.value || 30));
  const interval = Math.floor(1000 / fps);
  frameIndex = 0;
  startBtn.disabled = true;
  repairBtn.disabled = true;
  stopBtn.disabled = false;

  timer = setInterval(() => {
    const frame = playFrames[frameIndex % playFrames.length];
    drawFrameText(frame);
    frameIndex += 1;
  }, interval);
}

function stopPlayback() {
  if (timer) clearInterval(timer);
  timer = null;
  startBtn.disabled = false;
  repairBtn.disabled = false;
  stopBtn.disabled = true;
  log('已停止播放');
}

prepareBtn.addEventListener('click', () => {
  prepareFrames().catch((err) => log(`生成失败：${err.message || err}`));
});
startBtn.addEventListener('click', () => startPlayback('all'));
repairBtn.addEventListener('click', () => startPlayback('missing'));
stopBtn.addEventListener('click', stopPlayback);
