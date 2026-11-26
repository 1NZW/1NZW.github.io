// ============================================================
// 按域名重写：让 pan.007588.xyz 根路径直接打开网盘仓库
// 原理：Cloudflare Pages Functions 中间件在静态资源返回前运行，
//       当 Host 为 pan 子域且路径为 / 时，用 env.ASSETS.fetch 内部取回
//       access.html 的内容返回；浏览器地址栏仍显示 pan.007588.xyz（"直达"效果）。
// 主域 007588.xyz / www.007588.xyz 完全不受影响，仍是博客与网盘原路径。
//
// 关键修复（2026-11-26）：Workers 的 fetch 不接受相对路径，
// 必须传完整 URL（含 origin），否则抛 "Invalid URL" → Worker threw exception (1101)。
// ============================================================
export async function onRequest(context) {
  const url = new URL(context.request.url);
  const host = url.hostname.toLowerCase();

  // 只在 pan 子域的根路径做内部重写，其它路径与域名一律放行
  if ((host === 'pan.007588.xyz' || host === 'www.pan.007588.xyz') &&
      (url.pathname === '/' || url.pathname === '')) {
    const target = new URL('/access', url.origin).toString();
    try {
      // 传完整 URL（真正的内部重写，地址栏不变）
      return await context.env.ASSETS.fetch(target);
    } catch (e) {
      // 兜底：万一 ASSETS 重写失败，302 跳转到 /access，避免白屏报错
      return Response.redirect(target, 302);
    }
  }

  return context.next();
}
