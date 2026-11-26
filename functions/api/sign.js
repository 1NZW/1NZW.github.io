import { AwsClient } from 'aws4fetch';

export async function onRequestPost({ request, env }) {
  if (request.headers.get("X-Auth-Key") !== env.AUTH_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  const { action, key, contentType } = await request.json();

  const aws = new AwsClient({
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APP_KEY,
    service: 's3',
    region: env.B2_REGION,
  });

  const baseUrl = `${env.B2_ENDPOINT}/${env.B2_BUCKET}`;

  // 1. 获取文件列表
  if (action === 'list') {
    // B2 的 S3 List 接口，list-type=2 是标准格式
    const listUrl = new URL(`${baseUrl}?list-type=2`);
    const req = new Request(listUrl, { method: 'GET' });
    const signed = await aws.sign(req);
    
    const resp = await fetch(signed.url, { headers: signed.headers });
    const xml = await resp.text();

    // 简单解析 S3 返回的 XML（提取 Key, Size, LastModified）
    const keys = [...xml.matchAll(/<Key>(.*?)<\/Key>/g)].map(m => m[1]);
    const sizes = [...xml.matchAll(/<Size>(.*?)<\/Size>/g)].map(m => parseInt(m[1], 10));
    const dates = [...xml.matchAll(/<LastModified>(.*?)<\/LastModified>/g)].map(m => new Date(m[1]).getTime());

    const files = keys.map((k, i) => ({
      key: k,
      size: sizes[i],
      addedAt: dates[i]
    }));

    // 按时间倒序排列
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

  // 3. 上传 / 下载 预签名
  let method = 'GET';
  const headers = {};

  if (action === 'upload') {
    method = 'PUT';
  } else if (action === 'download') {
    method = 'GET';
  } else {
    return new Response("Bad action", { status: 400 });
  }

  const targetUrl = new URL(`${env.B2_ENDPOINT}/${env.B2_BUCKET}/${key}`);
  const req = new Request(targetUrl, { method, headers });
  const signed = await aws.sign(req, { aws: { signQuery: true } });

  let finalUrl = signed.url;

  // 👇 只有下载才替换域名，且使用字符串完全替换
  if (action === 'download') {
    finalUrl = finalUrl.replace(env.B2_ENDPOINT, 'https://files.007588.xyz');
  }

  return Response.json({ url: finalUrl });
}
