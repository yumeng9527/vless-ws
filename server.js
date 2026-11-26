// VLESS over WebSocket — 纯 Node.js 实现，无外部依赖
// 部署目标：Render / Railway / 任何支持 Node 的平台
// 端口：process.env.PORT

const http = require('http');
const net = require('net');
const crypto = require('crypto');

const UUID = process.env.UUID || '';
if (!UUID) {
  console.error('FATAL: 环境变量 UUID 未设置');
  process.exit(1);
}
const UID = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const log = (...a) => console.log(new Date().toISOString(), ...a);

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

/** 编码服务端 -> 客户端帧（不掩码） */
function encodeFrame(payload, opcode = 0x2) {
  const len = payload.length;
  let head;
  if (len < 126) {
    head = Buffer.alloc(2);
    head[0] = 0x80 | opcode;
    head[1] = len;
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([head, payload]);
}

/** 从累积缓冲里尽可能多地切出完整帧，返回 {frames, rest} */
function drainFrames(buf) {
  const frames = [];
  let off = 0;
  for (;;) {
    if (off + 2 > buf.length) break;
    const b0 = buf[off];
    const b1 = buf[off + 1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f;
    let p = off + 2;
    if (len === 126) {
      if (p + 2 > buf.length) break;
      len = buf.readUInt16BE(p);
      p += 2;
    } else if (len === 127) {
      if (p + 8 > buf.length) break;
      len = Number(buf.readBigUInt64BE(p));
      p += 8;
    }
    let mask = null;
    if (masked) {
      if (p + 4 > buf.length) break;
      mask = buf.subarray(p, p + 4);
      p += 4;
    }
    if (p + len > buf.length) break;
    let payload = buf.subarray(p, p + len);
    if (mask) {
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    }
    frames.push({ opcode, payload });
    off = p + len;
  }
  return { frames, rest: buf.subarray(off) };
}

/** 解析 VLESS 请求头，返回 null 表示数据不够 */
function parseVlessHead(buf) {
  if (buf.length < 24) return null;
  let p = 17;
  const addonLen = buf[p];
  p += 1 + addonLen;
  if (p + 3 > buf.length) return null;
  const cmd = buf[p]; p += 1;
  const port = buf.readUInt16BE(p); p += 2;
  const atyp = buf[p]; p += 1;

  let host;
  if (atyp === 1) {
    if (p + 4 > buf.length) return null;
    host = `${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`;
    p += 4;
  } else if (atyp === 2) {
    if (p + 1 > buf.length) return null;
    const l = buf[p]; p += 1;
    if (p + l > buf.length) return null;
    host = buf.subarray(p, p + l).toString('utf8');
    p += l;
  } else if (atyp === 3) {
    if (p + 16 > buf.length) return null;
    const seg = [];
    for (let i = 0; i < 8; i++) seg.push(buf.readUInt16BE(p + i * 2).toString(16));
    host = '[' + seg.join(':') + ']';
    p += 16;
  } else {
    return { error: 'bad atyp ' + atyp };
  }
  return { cmd, host, port, dataOffset: p, version: buf[0] };
}

const server = http.createServer((req, res) => {
  // 普通请求：伪装
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', server: 'nginx' });
  res.end('<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>');
});

server.on('upgrade', (req, socket, headBuf) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const accept = wsAccept(key);
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  socket.setNoDelay(true);

  let acc = headBuf && headBuf.length ? Buffer.from(headBuf) : Buffer.alloc(0);
  let remote = null;
  let inited = false;
  let closed = false;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    try { if (remote) remote.destroy(); } catch (e) {}
    try { socket.destroy(); } catch (e) {}
  };

  const sendToClient = (payload) => {
    if (closed) return;
    try { socket.write(encodeFrame(payload)); } catch (e) { cleanup(); }
  };

  const handleData = (chunk) => {
    if (closed) return;
    if (inited) {
      try { remote.write(chunk); } catch (e) { cleanup(); }
      return;
    }
    acc = Buffer.concat([acc, chunk]);
    const parsed = parseVlessHead(acc);
    if (!parsed) return;
    if (parsed.error) { log('parse error:', parsed.error); cleanup(); return; }

    // UUID 校验
    if (!acc.subarray(1, 17).equals(UID)) {
      log('uuid mismatch');
      cleanup();
      return;
    }
    if (parsed.cmd !== 1) {
      log('unsupported cmd', parsed.cmd);
      cleanup();
      return;
    }

    log('CONNECT ->', parsed.host + ':' + parsed.port);
    const rest = acc.subarray(parsed.dataOffset);
    acc = Buffer.alloc(0);

    remote = net.connect({ host: parsed.host, port: parsed.port }, () => {
      inited = true;
      sendToClient(Buffer.from([parsed.version || 0, 0]));
      if (rest.length) {
        try { remote.write(rest); } catch (e) { cleanup(); }
      }
      log('connected', parsed.host + ':' + parsed.port);
    });
    remote.setNoDelay(true);
    remote.on('data', (d) => sendToClient(d));
    remote.on('end', () => { log('remote end'); cleanup(); });
    remote.on('close', () => cleanup());
    remote.on('error', (e) => { log('remote err:', e.message); cleanup(); });
  };

  socket.on('data', (chunk) => {
    const { frames, rest } = drainFrames(chunk);
    acc = Buffer.concat([acc, rest]);
    for (const f of frames) {
      if (f.opcode === 0x8) { cleanup(); return; }           // close
      if (f.opcode === 0x9) {                                   // ping
        try { socket.write(encodeFrame(f.payload, 0xA)); } catch (e) {}
        continue;
      }
      if (f.opcode === 0xA) continue;                           // pong
      handleData(f.payload);
    }
  });

  socket.on('close', cleanup);
  socket.on('error', cleanup);
});

// 先处理可能已跟随 upgrade 到达的早期数据
const origEmit = server.emit.bind(server);

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  log(`VLESS-WS server listening on 0.0.0.0:${PORT}`);
  log(`UUID: ${UUID}`);
});

process.on('uncaughtException', (e) => log('uncaught:', e && e.message));
process.on('unhandledRejection', (e) => log('unhandled:', e));
