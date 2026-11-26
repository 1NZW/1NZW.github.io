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
  return m ? m[1] : String(key);
}

export async function onRequestPost({ request, env }) {
  if (!env.AUTH_KEY) return text('服务端未配置 AUTH_KEY，请在 Cloudflare Pages 环境变量中添加', 500);
  if (getAuth(request) !== env.AUTH_KEY) return text('Unauthorized', 401);

  let payload;
  try {
    payload = await request.json();
  } catch {
    return text('Bad JSON', 400);
  }
  const action = payload && payload.action;
  const key = payload && payload.key;
  const contentType = payload && payload.contentType;

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
