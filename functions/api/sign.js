import { AwsClient } from 'aws4fetch';

// 初始化 B2 客户端的辅助函数
function getAwsClient(env) {
  return new AwsClient({
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APP_KEY,
    service: 's3',
    region: env.B2_REGION,
  });
}

// ==========================================
// 处理 GET 请求：用于前端的直接下载和图片预览
// ==========================================
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');
  
  if (!key) return new Response("Missing key", { status: 400 });

  const aws = getAwsClient(env);
  const targetUrl = new URL(`${env.B2_ENDPOINT}/${env.B2_BUCKET}/${key}`);
  
  // 生成一个 GET 请求的签名
  const req = new Request(targetUrl, { method: 'GET' });
  const signed = await aws.sign(req, { aws: { signQuery: true } });

  // Pages 去 B2 获取文件流
  const b2Resp = await fetch(signed.url);
  
  if (!b2Resp.ok) {
    return new Response(`Download failed from B2: ${b2Resp.status}`, { status: b2Resp.status });
  }

  // 直接透传 B2 的文件流和响应头给浏览器
  // 注意：不要加 Content-Disposition，否则前端图片无法预览
  const newHeaders = new Headers(b2Resp.headers);
  
  return new Response(b2Resp.body, {
    status: b2Resp.status,
    headers: newHeaders,
  });
}

// ==========================================
// 处理 POST 请求：用于上传签名、获取列表、删除
// ==========================================
export async function onRequestPost({ request, env }) {
  if (request.headers.get("X-Auth-Key") !== env.AUTH_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  const { action, key, contentType } = await request.json();
  const aws = getAwsClient(env);
  const baseUrl = `${env.B2_ENDPOINT}/${env.B2_BUCKET}`;

  // 1. 获取文件列表
  if (action === 'list') {
    const listUrl = new URL(`${baseUrl}?list-type=2`);
    const req = new Request(listUrl, { method: 'GET' });
    const signed = await aws.sign(req);
    
    const resp = await fetch(signed.url, { headers: signed.headers });
    const xml = await resp.text();

    const keys = [...xml.matchAll(/<Key>(.*?)<\/Key>/g)].map(m => m[1]);
    const sizes = [...xml.matchAll(/<Size>(.*?)<\/Size>/g)].map(m => parseInt(m[1], 10));
    const dates = [...xml.matchAll(/<LastModified>(.*?)<\/LastModified>/g)].map(m => new Date(m[1]).getTime());

    const files = keys.map((k, i) => ({
      key: k,
      size: sizes[i],
      addedAt: dates[i]
    }));

    files.sort((a, b) => b.addedAt - a.addedAt);
    return Response.json({ files });
  }

  // 2. 删除文件
  if (action === 'delete') {
    const targetUrl = new URL(`${baseUrl}/${key}`);
    const req = new Request(targetUrl, { method: 'DELETE' });
    const signed = await aws.sign(req);
    
    const resp = await fetch(signed.url, { headers: signed.headers });
    if (resp.ok) return Response.json({ success: true });
    return new Response("Delete failed", { status: 500 });
  }

  // 3. 上传签名
  if (action === 'upload') {
    const targetUrl = new URL(`${baseUrl}/${key}`);
    const req = new Request(targetUrl, { method: 'PUT', headers: {} });
    const signed = await aws.sign(req, { aws: { signQuery: true } });
    
    // 上传直接走 B2 原始域名，不经过 Worker 替换
    return Response.json({ url: signed.url });
  }

  return new Response("Bad action", { status: 400 });
}
