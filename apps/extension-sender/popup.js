const fileInput = document.getElementById('fileInput');
const fpsInput = document.getElementById('fpsInput');
const symbolInput = document.getElementById('symbolInput');
const blockInput = document.getElementById('blockInput');
const redundancyInput = document.getElementById('redundancyInput');
const prepareBtn = document.getElementById('prepareBtn');
const exportMissingBtn = document.getElementById('exportMissingBtn');
const startBtn = document.getElementById('startBtn');
const startDataBtn = document.getElementById('startDataBtn');
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
let controlObject = null;
let manifestFrames = [];
let dataFrames = [];

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
        if (payload.byteLength < best.payload.byteLength) best = { codec, payload };
      } catch (_e) {
      }
    }
    return best;
  }
  return { codec: 'none', payload: raw };
}

function iterChunks(u8, size) {
  const out = [];
  for (let i = 0; i < u8.length; i += size) out.push(u8.slice(i, i + size));
  if (!out.length) out.push(new Uint8Array());
  return out;
}

function xorSymbols(symbols, indices) {
  const maxLen = Math.max(...indices.map((i) => symbols[i].length), 0);
  const out = new Uint8Array(maxLen);
  for (const idx of indices) {
    const src = symbols[idx];
    for (let i = 0; i < maxLen; i += 1) out[i] ^= (i < src.length ? src[i] : 0);
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

function buildControlFrame(control, transferId, frameSeqStart) {
  const controlData = JSON.stringify({
    transfer_id: transferId,
    payload_name: control.payload_name,
    payload_size: control.payload_size,
    payload_symbol_count: control.payload_symbol_count,
    protocol: control.protocol,
  });
  const controlBytes = new TextEncoder().encode(controlData);
  if (controlBytes.length > 1200) {
    throw new Error(`控制帧过大（${controlBytes.length}字节），请减少文件数量或缩短文件名`);
  }
  const frame = encodeFrameText({
    v: 1,
    kind: 'control',
    transfer_id: transferId,
    frame_seq: frameSeqStart,
    payload_name: control.payload_name,
    payload_size: control.payload_size,
    payload_symbol_count: control.payload_symbol_count,
    payload_data_b64: btoa(String.fromCharCode(...controlBytes)),
    payload_data_crc32: crc32(controlBytes),
    protocol: control.protocol,
    ts: Date.now(),
  });
  return { frames: [frame], nextSeq: frameSeqStart + 1 };
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
  manifestFrames = [];
  dataFrames = [];
  symbolIndex = new Map();

  let frameSeq = 0;
  let totalSymbols = 0;
  const indexRows = [];
  const manifestFiles = [];

  for (let fileId = 0; fileId < files.length; fileId += 1) {
    const file = files[fileId];
    const rawBuf = await file.arrayBuffer();
    const raw = new Uint8Array(rawBuf);
    const fileHash = await sha256Hex(rawBuf);
    const compressed = await compressBestForSmallFile(rawBuf);
    const compU8 = new Uint8Array(compressed.payload);
    const blocks = iterChunks(compU8, blockSize);

    const sourceSymbolIds = [];

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
      const blockLen = blocks[blockId].length;

      for (let symbolId = 0; symbolId < symbolTotal; symbolId += 1) {
        const sid = makeSymbolId(currentTransferId, fileId, blockId, symbolId);
        const payload = symbols[symbolId];
        const payloadB64 = btoa(String.fromCharCode(...payload));
        const payloadCrc32 = crc32(payload);
        const rec = {
          v: 1,
          kind: 'symbol',
          transfer_id: currentTransferId,
          stream_id: currentTransferId,
          frame_seq: frameSeq,
          frame: frameSeq,
          file_id: fileId,
          path: file.name,
          block_id: blockId,
          block: blockId,
          block_len: blockLen,
          block_total: blocks.length,
          symbol_index: symbolId,
          symbol: symbolId,
          source_symbol_total: symbolTotal,
          k: symbolTotal,
          is_repair: false,
          redundant: false,
          symbol_id: sid,
          payload_b64: payloadB64,
          data_b64: payloadB64,
          payload_sha256: await sha256Hex(payload.buffer),
          payload_crc32: payloadCrc32,
          crc32: payloadCrc32,
          payload_file_name: file.name,
          file_name: file.name,
          payload_file_size: file.size,
          file_size: file.size,
          payload_file_sha256: fileHash,
          file_sha256: fileHash,
          payload_compression: compressed.codec,
          compression: compressed.codec,
          ts: Date.now(),
        };
        const text = encodeFrameText(rec);
        allFrames.push(text);
        symbolIndex.set(sid, text);
        sourceSymbolIds.push(sid);
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
        const payloadB64 = btoa(String.fromCharCode(...parity));
        const payloadCrc32 = crc32(parity);
        const xorOf = uniq.map((x) => makeSymbolId(currentTransferId, fileId, blockId, x));
        const rec = {
          v: 1,
          kind: 'symbol',
          transfer_id: currentTransferId,
          stream_id: currentTransferId,
          frame_seq: frameSeq,
          frame: frameSeq,
          file_id: fileId,
          path: file.name,
          block_id: blockId,
          block: blockId,
          block_len: blockLen,
          block_total: blocks.length,
          symbol_index: symbolTotal + r,
          symbol: symbolTotal + r,
          source_symbol_total: symbolTotal,
          k: symbolTotal,
          is_repair: true,
          redundant: true,
          symbol_id: sid,
          repair_of: xorOf,
          xor_of: xorOf,
          payload_b64: payloadB64,
          data_b64: payloadB64,
          payload_sha256: await sha256Hex(parity.buffer),
          payload_crc32: payloadCrc32,
          crc32: payloadCrc32,
          payload_file_name: file.name,
          file_name: file.name,
          payload_file_size: file.size,
          file_size: file.size,
          payload_file_sha256: fileHash,
          file_sha256: fileHash,
          payload_compression: compressed.codec,
          compression: compressed.codec,
          ts: Date.now(),
        };
        const text = encodeFrameText(rec);
        allFrames.push(text);
        symbolIndex.set(sid, text);
        frameSeq += 1;
      }
    }

    manifestFiles.push({
      id: fileId,
      path: file.name,
      size: file.size,
      sha256: fileHash,
      compression: compressed.codec,
      source_symbol_ids: sourceSymbolIds,
    });
  }

  const controlBase = {
    protocol: 'easytransfer/1',
    transfer_id: currentTransferId,
    payload_name: manifestFiles.length === 1 ? manifestFiles[0].path : 'bundle.bin',
    payload_size: manifestFiles.reduce((acc, item) => acc + (item.size || 0), 0),
    payload_symbol_count: totalSymbols,
  };
  controlObject = { ...controlBase };

  const mf = buildControlFrame(controlObject, currentTransferId, 0);
  manifestFrames = [...mf.frames];
  dataFrames = [...allFrames.map((txt, idx) => {
    try {
      const o = JSON.parse(txt);
      o.frame_seq = idx + mf.frames.length;
      return JSON.stringify(o);
    } catch (_e) {
      return txt;
    }
  })];
  allFrames = [...manifestFrames, ...dataFrames];

  startBtn.disabled = false;
  startDataBtn.disabled = false;
  repairBtn.disabled = false;
  stats.textContent = `传输ID: ${currentTransferId} | 分片总数: ${totalSymbols} | 总帧数: ${allFrames.length}`;
  log(`已生成完成，控制帧=${mf.frames.length}，传输ID=${currentTransferId}`);

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

  if (mode === 'manifest') {
    playFrames = manifestFrames;
    log(`开始播放控制帧，帧数=${playFrames.length}`);
  } else if (mode === 'data') {
    playFrames = dataFrames;
    log(`开始播放数据帧，帧数=${playFrames.length}`);
  } else if (mode === 'missing') {
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
  startDataBtn.disabled = true;
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
  startDataBtn.disabled = false;
  repairBtn.disabled = false;
  stopBtn.disabled = true;
  log('已停止播放');
}

prepareBtn.addEventListener('click', () => {
  prepareFrames().catch((err) => log(`生成失败：${err.message || err}`));
});
startBtn.addEventListener('click', () => startPlayback('manifest'));
startDataBtn.addEventListener('click', () => startPlayback('data'));
repairBtn.addEventListener('click', () => startPlayback('missing'));
stopBtn.addEventListener('click', stopPlayback);
