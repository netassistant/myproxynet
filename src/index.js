import { connect } from 'cloudflare:sockets';

const userID = 'ca84ac69-e4f0-4a9b-af52-68e5dde01b47';
const proxyIP = 'ts.hpc.tw';

export default {
  async fetch(request, env) {
    const id = env.UUID || userID;
    const proxy = env.PROXYIP || proxyIP;
    const url = new URL(request.url);
    const host = request.headers.get('Host');

    if (request.headers.get('Upgrade') === 'websocket') {
      return handleWS(request, id, proxy);
    }
    if (url.pathname === `/${id}`) {
      return new Response(getConfig(id, host), {
        headers: { 'Content-Type': 'text/plain;charset=utf-8' }
      });
    }
    return new Response('Not Found', { status: 404 });
  }
};

async function handleWS(request, userID, proxyIP) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  const earlyData = request.headers.get('sec-websocket-protocol') || '';
  const stream = wsToStream(server, earlyData);

  let remoteSocket = { value: null };
  let udpWrite = null;
  let headerSent = false;

  stream.pipeTo(new WritableStream({
    async write(chunk) {
      if (udpWrite) { udpWrite(chunk); return; }
      if (remoteSocket.value) {
        const writer = remoteSocket.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const { hasError, addressRemote, portRemote, rawDataIndex, vlessVersion, isUDP } =
        parseVless(chunk, userID);
      if (hasError) return;

      const resHeader = new Uint8Array([vlessVersion[0], 0]);
      const clientData = chunk.slice(rawDataIndex);

      if (isUDP && portRemote === 53) {
        const { write } = await handleDNS(server, resHeader);
        udpWrite = write;
        udpWrite(clientData);
        return;
      }

      await tcpConnect(remoteSocket, addressRemote, portRemote, clientData, server, resHeader, proxyIP);
    }
  })).catch(() => { server.close(); });

  return new Response(null, { status: 101, webSocket: client });
}

async function tcpConnect(remoteSocket, addr, port, data, ws, resHeader, proxyIP) {
  async function tryConnect(target) {
    const socket = connect({ hostname: target, port });
    remoteSocket.value = socket;
    const writer = socket.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
    let firstChunk = true;
    await socket.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (firstChunk) {
          const combined = new Uint8Array(resHeader.length + chunk.byteLength);
          combined.set(resHeader);
          combined.set(new Uint8Array(chunk), resHeader.length);
          ws.send(combined);
          firstChunk = false;
        } else {
          ws.send(chunk);
        }
      },
      close() { ws.close(); }
    }));
  }

  try {
    await tryConnect(addr);
  } catch {
    try {
      await tryConnect(proxyIP);
    } catch {
      ws.close();
    }
  }
}

async function handleDNS(ws, resHeader) {
  let controller;
  const stream = new ReadableStream({ start(c) { controller = c; } });
  stream.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch('https://1.1.1.1/dns-query', {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message' },
        body: chunk
      });
      const data = new Uint8Array(await resp.arrayBuffer());
      const combined = new Uint8Array(resHeader.length + data.length);
      combined.set(resHeader);
      combined.set(data, resHeader.length);
      ws.send(combined);
    }
  }));
  return { write: (chunk) => controller.enqueue(chunk) };
}

function wsToStream(ws, earlyData) {
  return new ReadableStream({
    start(controller) {
      if (earlyData) {
        try {
          const s = atob(earlyData.replace(/-/g, '+').replace(/_/g, '/'));
          const buf = new Uint8Array(s.length);
          for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
          controller.enqueue(buf.buffer);
        } catch {}
      }
      ws.addEventListener('message', e => controller.enqueue(e.data));
      ws.addEventListener('close', () => controller.close());
      ws.addEventListener('error', e => controller.error(e));
    }
  });
}

function parseVless(buffer, uid) {
  const bytes = new Uint8Array(buffer);
  const ver = bytes.slice(0, 1);
  const id = bytesToUUID(bytes.slice(1, 17));
  if (id !== uid) return { hasError: true };
  const optLen = bytes[17];
  const cmd = bytes[18 + optLen];
  const isUDP = cmd === 2;
  const port = (bytes[19 + optLen] << 8) | bytes[20 + optLen];
  const atype = bytes[21 + optLen];
  let addr = '', idx = 22 + optLen;
  if (atype === 1) {
    addr = bytes.slice(idx, idx + 4).join('.'); idx += 4;
  } else if (atype === 2) {
    const len = bytes[idx++];
    addr = new TextDecoder().decode(bytes.slice(idx, idx + len)); idx += len;
  } else if (atype === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((bytes[idx] << 8) | bytes[idx + 1]).toString(16)); idx += 2;
    }
    addr = parts.join(':'); idx += 0;
  }
  return { hasError: false, addressRemote: addr, portRemote: port, rawDataIndex: idx, vlessVersion: ver, isUDP };
}

function bytesToUUID(b) {
  const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

function getConfig(id, host) {
  return [
    `vless://${id}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&path=%2F%3Fed%3D2048#CF-443`,
    `vless://${id}@${host}:8443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&path=%2F%3Fed%3D2048#CF-8443`,
  ].join('\n');
}
