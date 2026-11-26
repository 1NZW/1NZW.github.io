// ============================================================
// 按域名重写：让 pan.007588.xyz 根路径直接打开网盘仓库
// 原理：Cloudflare Pages Functions 中间件在所有请求（含静态文件）前运行，
//       当 Host 为 pan 子域且路径为 / 时，用 env.ASSETS.fetch 内部取回
//       access.html 的内容返回；浏览器地址栏仍显示 pan.007588.xyz（"直达"效果）。
// 主域 007588.xyz / www.007588.xyz 完全不受影响，仍是博客与网盘原路径。
// 注意：Pages Functions 没有 context.rewrite()，正确做法是用 env.ASSETS.fetch()。
// ============================================================
export async function onRequest(context) {
  const url = new URL(context.request.url);
  const host = url.hostname.toLowerCase();

  // 只在 pan 子域的根路径做内部重写，其它路径与域名一律放行
  if ((host === 'pan.007588.xyz' || host === 'www.pan.007588.xyz') &&
      (url.pathname === '/' || url.pathname === '')) {
    // '/access' 是 access.html 的 pretty path（不带扩展名）
    return context.env.ASSETS.fetch('/access');
  }

  return context.next();
}
