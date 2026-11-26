import { AwsClient } from 'aws4fetch';

// 统一响应头（同源调用也需要，便于OPTIONS预检与调试）
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Key, X-File-Key, X-Content-Type',
  'Access-Control-Max-Age': '86400',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}
function text(msg, status = 400) {
  return new Response(msg, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS },
  });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

// 鉴权：优先读请求头，其次读 query（便于 GET 场景扩展）
function getAuth(request) {
  return request.headers.get('X-Auth-Key') || new URL(request.url).searchParams.get('auth');
}

function makeAws(env) {
  return new AwsClient({
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APP_KEY,
    service: 's3',
    region: env.B2_REGION || 'us-west-004',
  });
}
function baseUrl(env) {
  return `${String(env.B2_ENDPOINT || '').replace(/\/$/, '')}/${env.B2_BUCKET}`;
}
function objectUrl(env, key) {
  // 让 URL 构造函数负责编码空格/中文等字符，避免手工编码造成签名不一致
  return new URL(`${baseUrl(env)}/${key}`);
}
function decodeXml(s) {
  return String(s)
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#39;/g, "'");
}
function displayName(key) {
  const m = String(key).match(/^\d+-[a-z0-9]+-(.+)$/);
  let name = m ? m[1] : String(key);
  try { name = decodeURIComponent(name); } catch (e) { /* 未编码的旧 key，保持原样 */ }
  return name;
}

// ============================================================
// 临时分享链接：HMAC-SHA256 签名 token
// token = base64url(payload) + '.' + base64url(HMAC-SHA256(payload))
// payload = { k:文件key, n:文件名, s:大小, e:过期时间戳(ms), r:随机串 }
// 密钥：优先 SHARE_SECRET，未配置则复用 AUTH_KEY（无需用户额外配置）
// ============================================================
function shareSecret(env) {
  return env.SHARE_SECRET || env.AUTH_KEY || '';
}
function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  let t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  const bin = atob(t);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const bytes = new Uint8Array(sig);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
// 校验 token：签名正确 + 未过期，成功返回 payload，失败返回 null
async function verifyShareToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [p, sig] = parts;
  let expected;
  try { expected = await hmacSign(secret, p); } catch { return null; }
  if (sig.length !== expected.length || sig !== expected) return null;
  let data;
  try { data = JSON.parse(b64urlDecode(p)); } catch { return null; }
  if (!data || !data.k || !data.e || Date.now() > Number(data.e)) return null;
  return data;
}

export async function onRequestPost({ request, env }) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return text('Bad JSON', 400);
  }
  const action = payload && payload.action;
  const key = payload && payload.key;
  const contentType = payload && payload.contentType;

  // 分享链接的读取（share_info / share_download）面向公众，凭 token 鉴权，不需要访问码
  const isPublicShare = action === 'share_info' || action === 'share_download';

  if (!env.AUTH_KEY) return text('服务端未配置 AUTH_KEY，请在 Cloudflare Pages 环境变量中添加', 500);
  if (!isPublicShare && getAuth(request) !== env.AUTH_KEY) return text('Unauthorized', 401);

  const aws = makeAws(env);

  // ---------- 1. 列出文件（支持分页 + 正确解析每个对象） ----------
  if (action === 'list') {
    try {
      const files = [];
      let token = null;
      let guard = 0;
      do {
        const u = new URL(baseUrl(env));
        u.searchParams.set('list-type', '2');
        if (token) u.searchParams.set('continuation-token', token);
        const signed = await aws.sign(new Request(u, { method: 'GET' }));
        const resp = await fetch(signed.url, { headers: signed.headers });
        if (!resp.ok) {
          const detail = (await resp.text()).slice(0, 300);
          return text(`B2 列表读取失败 (${resp.status}): ${detail}`, 502);
        }
        const xml = await resp.text();
        // 按 <Contents> 块解析，避免 Key/Size/LastModified 数量不一致时错位
        const blocks = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) || [];
        for (const block of blocks) {
          const km = block.match(/<Key>([\s\S]*?)<\/Key>/);
          if (!km) continue;
          const sm = block.match(/<Size>([\s\S]*?)<\/Size>/);
          const dm = block.match(/<LastModified>([\s\S]*?)<\/LastModified>/);
          files.push({
            key: decodeXml(km[1]),
            size: sm ? parseInt(sm[1], 10) || 0 : 0,
            addedAt: dm ? new Date(dm[1]).getTime() : 0,
          });
        }
        const cm = xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/);
        token = cm ? decodeXml(cm[1]) : null;
        guard++;
      } while (token && guard < 20 && files.length < 5000);

      files.sort((a, b) => b.addedAt - a.addedAt);
      return json({ files });
    } catch (e) {
      return text(`列表异常: ${e.message}`, 500);
    }
  }

  // ---------- 2. 删除（改用 query 签名并回传 B2 原始错误，便于定位权限问题） ----------
  if (action === 'delete') {
    if (!key) return text('Missing key', 400);
    try {
      const signed = await aws.sign(
        new Request(objectUrl(env, key), { method: 'DELETE' }),
        { aws: { signQuery: true } }
      );
      const resp = await fetch(signed.url, { method: 'DELETE' });
      if (resp.ok) return json({ success: true });
      const detail = (await resp.text()).slice(0, 300);
      return text(`删除失败 (${resp.status}): ${detail}`, 502);
    } catch (e) {
      return text(`删除异常: ${e.message}`, 500);
    }
  }

  // ---------- 3. 生成直传/直链签名 ----------
  if (action === 'upload' || action === 'download') {
    if (!key) return text('Missing key', 400);
    const method = action === 'upload' ? 'PUT' : 'GET';
    const headers = contentType && action === 'upload' ? { 'Content-Type': contentType } : {};
    const signed = await aws.sign(
      new Request(objectUrl(env, key), { method, headers }),
      { aws: { signQuery: true } }
    );
    return json({ url: signed.url, method });
  }

  // ---------- 4. 代理读取（下载/预览走同源，避免跳转与 CORS 依赖） ----------
  if (action === 'get') {
    if (!key) return text('Missing key', 400);
    try {
      const signed = await aws.sign(new Request(objectUrl(env, key), { method: 'GET' }));
      const resp = await fetch(signed.url, { headers: signed.headers });
      if (!resp.ok) {
        const detail = (await resp.text()).slice(0, 200);
        return text(`读取文件失败 (${resp.status}): ${detail}`, 502);
      }
      const buf = await resp.arrayBuffer();
      const name = displayName(key);
      const disposition = `attachment; filename="${name.replace(/["\\]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name)}`;
      return new Response(buf, {
        status: 200,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'application/octet-stream',
          'Content-Disposition': disposition,
          'Cache-Control': 'private, max-age=0',
          ...CORS,
        },
      });
    } catch (e) {
      return text(`读取异常: ${e.message}`, 500);
    }
  }

  // ---------- 5a. 创建临时分享链接（需访问码） ----------
  if (action === 'share_create') {
    if (!key) return text('Missing key', 400);
    const now = Date.now();
    let ttl = Number(payload.ttl);
    if (!isFinite(ttl) || ttl <= 0) ttl = 86400;
    ttl = Math.min(Math.max(ttl, 300), 30 * 86400); // 限制 5 分钟 ~ 30 天
    const exp = now + ttl * 1000;
    const name = payload.name || displayName(key);
    const size = Number(payload.size) || 0;
    const nonce = (typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : String(now) + '-' + Math.random().toString(36).slice(2);

    const p = { k: key, n: name, s: size, e: exp, r: nonce };
    const payloadB64 = b64urlEncode(JSON.stringify(p));
    const sig = await hmacSign(shareSecret(env), payloadB64);
    const token = payloadB64 + '.' + sig;
    const origin = new URL(request.url).origin;
    const shareUrl = origin + '/share.html?t=' + encodeURIComponent(token);
    return json({ token, url: shareUrl, expiresAt: exp, name, size, ttl });
  }

  // ---------- 5b. 查询分享信息（公开，凭 token） ----------
  if (action === 'share_info') {
    const data = await verifyShareToken(payload.token, shareSecret(env));
    if (!data) return json({ error: '链接无效或已过期' }, 403);
    return json({ name: data.n || displayName(data.k), size: Number(data.s) || 0, expiresAt: Number(data.e) });
  }

  // ---------- 5c. 分享下载（公开，凭 token 代理读取文件） ----------
  if (action === 'share_download') {
    const data = await verifyShareToken(payload.token, shareSecret(env));
    if (!data) return text('链接无效或已过期', 403);
    try {
      const signed = await aws.sign(new Request(objectUrl(env, data.k), { method: 'GET' }));
      const resp = await fetch(signed.url, { headers: signed.headers });
      if (!resp.ok) {
        const detail = (await resp.text()).slice(0, 200);
        return text(`读取文件失败 (${resp.status}): ${detail}`, 502);
      }
      const buf = await resp.arrayBuffer();
      const name = data.n || displayName(data.k);
      const disposition = `attachment; filename="${name.replace(/["\\]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name)}`;
      return new Response(buf, {
        status: 200,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'application/octet-stream',
          'Content-Disposition': disposition,
          'Cache-Control': 'private, max-age=0',
          ...CORS,
        },
      });
    } catch (e) {
      return text(`读取异常: ${e.message}`, 500);
    }
  }

  return text('Bad action', 400);
}

// ---------- 代理上传：Worker 接收二进制 body 后转发 B2，彻底绕开浏览器 CORS ----------
export async function onRequestPut({ request, env }) {
  if (!env.AUTH_KEY) return text('服务端未配置 AUTH_KEY', 500);
  if (getAuth(request) !== env.AUTH_KEY) return text('Unauthorized', 401);

  const key = request.headers.get('X-File-Key');
  if (!key) return text('Missing X-File-Key', 400);
  const contentType = request.headers.get('X-Content-Type') || 'application/octet-stream';

  try {
    const aws = makeAws(env);
    const body = await request.arrayBuffer();
    const req = new Request(objectUrl(env, key), {
      method: 'PUT',
      body,
      headers: { 'Content-Type': contentType },
    });
    const signed = await aws.sign(req);
    const resp = await fetch(signed.url, { method: 'PUT', body, headers: signed.headers });
    if (!resp.ok) {
      const detail = (await resp.text()).slice(0, 300);
      return text(`B2 代理上传失败 (${resp.status}): ${detail}`, 502);
    }
    return json({ success: true, key, size: body.byteLength });
  } catch (e) {
    return text(`代理上传异常: ${e.message}`, 500);
  }
}
