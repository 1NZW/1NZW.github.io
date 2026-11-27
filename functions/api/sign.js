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
// KV 状态存储（分享撤销 / 下载次数 / 文件删除失效）
// 绑定名：SHARE_KV。未绑定时所有函数降级为 no-op，现有功能不受影响。
// 设计要点：撤销/次数/删除校验必须在「边缘缓存查询之前」执行，
//          否则缓存命中会绕过这些拦截。
// ============================================================
function kvOf(env) { return env.SHARE_KV || null; }

// FNV-1a 32 位 hash：把访问码/文件 key 映射为固定短 key，避免明文入 KV
function hash32(s) {
  let h = 2166136261 >>> 0;
  s = String(s);
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h.toString(36);
}
function ownerOf(auth) { return 'o_' + hash32(auth || ''); }
function keyOfToken(token) { return 's_' + hash32(token); }
function keyOfDeleted(fileKey) { return 'd_' + hash32(fileKey); }

async function kvGetJSON(kv, k) {
  if (!kv) return null;
  try { return await kv.get(k, 'json'); } catch (e) { return null; }
}
async function kvPutJSON(kv, k, v, ttl) {
  if (!kv) return false;
  try {
    const opt = (ttl && ttl > 0) ? { expirationTtl: Math.floor(ttl) } : undefined;
    await kv.put(k, JSON.stringify(v), opt);
    return true;
  } catch (e) { return false; }
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
// 校验 token：返回 { data } 或 { error: 'expired'|'invalid' }
// 区分"过期"与"无效"便于前端给出准确提示（过期→410，无效→403）
async function verifyShareToken(token, secret) {
  const invalid = { error: 'invalid' };
  if (!token || typeof token !== 'string') return invalid;
  const parts = token.split('.');
  if (parts.length !== 2) return invalid;
  const [p, sig] = parts;
  let expected;
  try { expected = await hmacSign(secret, p); } catch { return invalid; }
  if (sig.length !== expected.length || sig !== expected) return invalid;
  let data;
  try { data = JSON.parse(b64urlDecode(p)); } catch { return invalid; }
  if (!data || !data.k || !data.e) return invalid;
  if (Date.now() > Number(data.e)) return { error: 'expired', data };
  return { data };
}

// 从 KV 读取分享记录并做状态校验，返回 { rec, blocked } 或 { rec:null }
// blocked = { status, msg } 表示应拦截（撤销/次数用尽/文件已删除）
async function checkShareState(env, token, data) {
  const kv = kvOf(env);
  if (!kv) return { rec: null };
  const rec = await kvGetJSON(kv, keyOfToken(token));
  if (!rec) return { rec: null }; // KV 后配/记录已过期清理 → 兼容旧链接，放行

  if (rec.revoked) return { rec, blocked: { status: 403, msg: '链接已被撤销' } };
  if (rec.maxDownloads > 0 && (rec.downloads || 0) >= rec.maxDownloads) {
    return { rec, blocked: { status: 410, msg: '下载次数已用完' } };
  }
  // 文件删除失效标记
  const delMark = await kvGetJSON(kv, keyOfDeleted(rec.key || data.k));
  if (delMark) return { rec, blocked: { status: 410, msg: '文件已被删除' } };
  return { rec };
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

  // ---------- 2. 删除（同步写 KV 失效标记，让该文件的分享链接立即失效） ----------
  if (action === 'delete') {
    if (!key) return text('Missing key', 400);
    try {
      const signed = await aws.sign(
        new Request(objectUrl(env, key), { method: 'DELETE' }),
        { aws: { signQuery: true } }
      );
      const resp = await fetch(signed.url, { method: 'DELETE' });
      if (resp.ok) {
        // 写删除失效标记：即使边缘缓存仍有旧文件，share_download 也会因 KV 校验而拒绝
        const kv = kvOf(env);
        if (kv) await kvPutJSON(kv, keyOfDeleted(key), { at: Date.now() }, 30 * 86400);
        return json({ success: true, cachePurged: !!kv });
      }
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

  // ---------- 5a. 创建临时分享链接（需访问码），可写 KV 记录支持撤销/次数 ----------
  if (action === 'share_create') {
    if (!key) return text('Missing key', 400);
    const now = Date.now();
    let ttl = Number(payload.ttl);
    if (!isFinite(ttl) || ttl <= 0) ttl = 86400;
    ttl = Math.min(Math.max(ttl, 300), 30 * 86400); // 限制 5 分钟 ~ 30 天
    const exp = now + ttl * 1000;
    const name = payload.name || displayName(key);
    const size = Number(payload.size) || 0;
    let maxDownloads = Math.floor(Number(payload.maxDownloads) || 0);
    if (!isFinite(maxDownloads) || maxDownloads < 0) maxDownloads = 0;
    maxDownloads = Math.min(maxDownloads, 10000); // 0 = 不限
    const nonce = (typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : String(now) + '-' + Math.random().toString(36).slice(2);

    const p = { k: key, n: name, s: size, e: exp, r: nonce };
    const payloadB64 = b64urlEncode(JSON.stringify(p));
    const sig = await hmacSign(shareSecret(env), payloadB64);
    const token = payloadB64 + '.' + sig;
    const origin = new URL(request.url).origin;
    const shareUrl = origin + '/share?t=' + encodeURIComponent(token);

    // 写 KV 记录（密钥未绑定则跳过，功能降级）
    const kv = kvOf(env);
    let persisted = false;
    if (kv) {
      const rec = {
        id: hash32(token), token, key, name, size,
        createdAt: now, expiresAt: exp,
        maxDownloads, downloads: 0, revoked: false,
        owner: ownerOf(getAuth(request)),
      };
      persisted = await kvPutJSON(kv, keyOfToken(token), rec, ttl + 86400);
    }
    return json({ token, url: shareUrl, expiresAt: exp, name, size, ttl, maxDownloads, persisted });
  }

  // ---------- 5b. 查询分享信息（公开，凭 token）----------
  if (action === 'share_info') {
    const result = await verifyShareToken(payload.token, shareSecret(env));
    if (result.error === 'expired') return json({ error: '链接已过期' }, 410);
    if (result.error) return json({ error: '链接无效或已被篡改' }, 403);
    const data = result.data;

    // 撤销/次数/删除校验（在返回信息前）
    const state = await checkShareState(env, payload.token, data);
    if (state.blocked) return json({ error: state.blocked.msg }, state.blocked.status);

    const remaining = state.rec && state.rec.maxDownloads > 0
      ? Math.max(0, state.rec.maxDownloads - (state.rec.downloads || 0))
      : null;
    return json({
      name: data.n || displayName(data.k),
      size: Number(data.s) || 0,
      expiresAt: Number(data.e),
      remainingDownloads: remaining,
    });
  }

  // ---------- 5c. 分享下载（公开，凭 token 代理读取 + CF 边缘缓存） ----------
  // 链路：浏览器 → CF Worker（校验 token + KV 状态）→ CF 边缘缓存 → 未命中才回源 B2
  // 关键：KV 状态校验在缓存查询之前，确保撤销/次数/删除标记不会被缓存绕过。
  // 全程 try/catch 兜底：缓存读写失败一律退回直连 B2，绝不影响分享下载。
  if (action === 'share_download') {
    const result = await verifyShareToken(payload.token, shareSecret(env));
    if (result.error === 'expired') return text('链接已过期', 410);
    if (result.error) return text('链接无效或已被篡改', 403);
    const data = result.data;

    // ① 状态校验（撤销 / 次数 / 删除）—— 必须先于缓存
    const state = await checkShareState(env, payload.token, data);
    if (state.blocked) return text(state.blocked.msg, state.blocked.status);

    // ② 有次数限制则递增计数（KV 非原子，极端并发下可能略微超出，可接受）
    if (state.rec && state.rec.maxDownloads > 0) {
      const kv = kvOf(env);
      state.rec.downloads = (state.rec.downloads || 0) + 1;
      const ttlLeft = Math.max(60, Math.floor((Number(state.rec.expiresAt) - Date.now()) / 1000) + 86400);
      await kvPutJSON(kv, keyOfToken(payload.token), state.rec, ttlLeft);
    }

    const name = data.n || displayName(data.k);
    const disposition = `attachment; filename="${name.replace(/["\\]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name)}`;
    const size = Number(data.s) || 0;
    const CACHE_MAX = 20 * 1024 * 1024; // 超过 20MB 不缓存，避免 Workers 内存限制与 413

    // 构造 GET 缓存 key（内部标识，不对外暴露；基于文件 key）
    const reqOrigin = new URL(request.url).origin;
    const cacheReq = new Request(
      new URL('/__sharecache__/' + encodeURIComponent(data.k), reqOrigin).toString(),
      { method: 'GET' }
    );
    let cache = null;
    try { cache = caches.default; } catch (e) { cache = null; }

    // ③ 查缓存
    if (cache && size > 0 && size <= CACHE_MAX) {
      try {
        const hit = await cache.match(cacheReq);
        if (hit && hit.ok) {
          return new Response(hit.body, {
            status: 200,
            headers: {
              'Content-Type': hit.headers.get('Content-Type') || 'application/octet-stream',
              'Content-Disposition': disposition,
              'Cache-Control': 'private, max-age=0',
              'X-Share-Cache': 'HIT',
              ...CORS,
            },
          });
        }
      } catch (e) { /* 缓存读取异常 → 回源 */ }
    }

    // ④ 缓存未命中/不可用 → 回源 B2
    try {
      const signed = await aws.sign(new Request(objectUrl(env, data.k), { method: 'GET' }));
      const resp = await fetch(signed.url, { headers: signed.headers });
      if (!resp.ok) {
        const detail = (await resp.text()).slice(0, 200);
        return text(`读取文件失败 (${resp.status}): ${detail}`, 502);
      }
      const buf = await resp.arrayBuffer();
      const contentType = resp.headers.get('Content-Type') || 'application/octet-stream';

      // ⑤ 异步写缓存（失败不影响本次下载）
      if (cache && size > 0 && size <= CACHE_MAX) {
        try {
          const cacheResp = new Response(buf.slice(0), {
            status: 200,
            headers: { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=21600' },
          });
          await cache.put(cacheReq, cacheResp);
        } catch (e) { /* 缓存写入失败 → 忽略 */ }
      }

      return new Response(buf, {
        status: 200,
        headers: {
          'Content-Type': contentType,
          'Content-Disposition': disposition,
          'Cache-Control': 'private, max-age=0',
          'X-Share-Cache': 'MISS',
          ...CORS,
        },
      });
    } catch (e) {
      return text(`读取异常: ${e.message}`, 500);
    }
  }

  // ---------- 5d. 列出我创建的分享（需访问码，按 owner 隔离） ----------
  if (action === 'share_list') {
    const kv = kvOf(env);
    if (!kv) return json({ supported: false, shares: [] });
    try {
      const owner = ownerOf(getAuth(request));
      let keys = [];
      let cursor = null;
      do {
        const res = await kv.list({ prefix: 's_', cursor, limit: 1000 });
        keys = keys.concat(res.keys || []);
        cursor = res.list_complete ? null : res.cursor;
      } while (cursor && keys.length < 5000);

      const now = Date.now();
      const shares = [];
      for (const k of keys) {
        const rec = await kvGetJSON(kv, k.name);
        if (!rec || rec.owner !== owner) continue;
        let status = 'active';
        if (rec.revoked) status = 'revoked';
        else if (now > Number(rec.expiresAt)) status = 'expired';
        else if (rec.maxDownloads > 0 && (rec.downloads || 0) >= rec.maxDownloads) status = 'exhausted';
        shares.push({
          id: rec.id, token: rec.token, name: rec.name, size: rec.size,
          expiresAt: rec.expiresAt, createdAt: rec.createdAt,
          maxDownloads: rec.maxDownloads, downloads: rec.downloads || 0,
          revoked: !!rec.revoked, status,
        });
      }
      shares.sort((a, b) => b.createdAt - a.createdAt);
      return json({ supported: true, shares });
    } catch (e) {
      return text(`读取分享列表异常: ${e.message}`, 500);
    }
  }

  // ---------- 5e. 撤销分享链接（需访问码，仅 owner 本人可撤销） ----------
  if (action === 'share_revoke') {
    const kv = kvOf(env);
    if (!kv) return json({ error: '服务端未绑定 KV，无法撤销链接' }, 501);
    const token = payload.token;
    if (!token) return text('Missing token', 400);
    try {
      const k = keyOfToken(token);
      const rec = await kvGetJSON(kv, k);
      if (!rec || rec.owner !== ownerOf(getAuth(request))) {
        return json({ error: '链接不存在或无权撤销' }, 403);
      }
      rec.revoked = true;
      await kvPutJSON(kv, k, rec);
      return json({ success: true });
    } catch (e) {
      return text(`撤销异常: ${e.message}`, 500);
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
