const userID = 'ca84ac69-e4f0-4a9b-af52-68e5dde01b47';
const proxyIP = 'ts.hpc.tw';

function getConfig(id, host) {
  return [
    `vless://${id}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&path=%2F%3Fed%3D2048#CF-443`,
    `vless://${id}@${host}:8443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&path=%2F%3Fed%3D2048#CF-8443`,
  ].join('\n');
}

export default {
  async fetch(request, env) {
    const id = env.UUID || userID;
    const proxy = env.PROXYIP || proxyIP;
    const host = request.headers.get('Host');
    const url = new URL(request.url);

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
  const stream = makeReadable(server, request.headers.get('sec-websocket-protocol') || '');
  handleStream(stream, server, userID, proxyIP);
  return new Response(null, { status: 101, webSocket: client });
}

function makeReadable(ws, early) {
  return new ReadableStream({
    start(c) {
      if (early) {
        try {
          const s = atob(early.replace(/-/g, '+').replace(/_/g, '/'));
          const a = new Uint8Array(s.length);
          for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
          c.enqueue(a.buffer);
        } catch {}
      }
      ws.addEventListener('message', e => c.enqueue(e.data));
      ws.addEventListener('close', () => c.close());
      ws.addEventListener('error', () => c.close());
    }
  });
}

async function handleStream(stream, ws, userID, proxyIP) {
  const reader = stream.getReader();
  let first = true;
  let socket = null;
  let headerSent = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (first) {
      first = false;
      const p = parseVless(value, userID);
      if (p.hasError) { ws.close(); return; }
      const resHeader = new Uint8Array([p.ver, 0]);
      for (const t of [p.addr, proxyIP].filter(Boolean)) {
        try {
          socket = connect({ hostname: t, port: p.port });
          const w = socket.writable.getWriter();
          await w.write(p.data);
          w.releaseLock();
          socket.readable.pipeTo(new WritableStream({
            write(chunk) {
              if (!headerSent) {
                const merged = new Uint8Array(resHeader.length + chunk.byteLength);
                merged.set(resHeader);
                merged.set(new Uint8Array(chunk), resHeader.length);
                ws.send(merged);
                headerSent = true;
              } else {
                ws.send(chunk);
              }
            },
            close() { ws.close(); }
          })).catch(() => ws.close());
          break;
        } catch { socket = null; }
      }
      if (!socket) { ws.close(); return; }
    } else if (socket) {
      const w = socket.writable.getWriter();
      await w.write(value).catch(() => {});
      w.releaseLock();
    }
  }
}

function parseVless(buf, uid) {
  const b = new Uint8Array(buf);
  const hex = [...b.slice(1,17)].map(x => x.toString(16).padStart(2,'0')).join('');
  const uuid = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  if (uuid !== uid) return { hasError: true };
  const opt = b[17];
  const port = (b[19+opt] << 8) | b[20+opt];
  const atype = b[21+opt];
  let addr = '', idx = 22+opt;
  if (atype === 1) { addr = b.slice(idx,idx+4).join('.'); idx += 4; }
  else if (atype === 2) { const l=b[idx++]; addr=new TextDecoder().decode(b.slice(idx,idx+l)); idx+=l; }
  else if (atype === 3) {
    const p=[];
    for(let
