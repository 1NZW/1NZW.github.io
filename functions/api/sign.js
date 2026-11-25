import { AwsClient } from 'aws4fetch';

export async function onRequestPost({ request, env }) {
  // 1. 校验前端密码
  if (request.headers.get("X-Auth-Key") !== env.AUTH_KEY) {
    return new Response("Unauthorized", { status: 401 });
  }

  const { action, key, contentType } = await request.json();

  // 2. 初始化 B2 客户端
  const aws = new AwsClient({
    accessKeyId: env.B2_KEY_ID,
    secretAccessKey: env.B2_APP_KEY,
    service: 's3',
    region: env.B2_REGION,
  });

  // 3. 拼接 B2 的 Path-style URL
  const targetUrl = new URL(`${env.B2_ENDPOINT}/${env.B2_BUCKET}/${key}`);
  
  let method = 'GET';
  const headers = {};

  if (action === 'upload') {
    method = 'PUT';
  } else if (action === 'download') {
    method = 'GET';
  } else {
    return new Response("Bad action", { status: 400 });
  }

  // 4. 生成预签名 URL（有效期 600 秒 = 10 分钟）
  const req = new Request(targetUrl, { method, headers });
  const signed = await aws.sign(req, { aws: { signQuery: true } });

  return Response.json({ url: signed.url });
}
