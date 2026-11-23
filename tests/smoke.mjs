// Page smoke test (CI, 2026-11-22): the main pages load in Chromium without JS errors or missing local files.
// Outside requests (Supabase etc.) are answered empty so the test never touches production.
// Run: node tests/smoke.mjs   (needs "playwright"; PW_MODULE may point at a local playwright-core)
import http from "node:http"; import fs from "node:fs"; import path from "node:path"; import { fileURLToPath } from "node:url";
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { chromium } = await import(process.env.PW_MODULE || "playwright");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
  ".webmanifest": "application/manifest+json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2" };
const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p.endsWith("/")) p += "index.html";
  const f = path.join(ROOT, p);
  if (!f.startsWith(ROOT) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end("not found"); }
  res.writeHead(200, { "Content-Type": TYPES[path.extname(f)] || "application/octet-stream" }); fs.createReadStream(f).pipe(res);
}).listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const BASE = `http://127.0.0.1:${server.address().port}`;

const PAGES = ["/", "/?panel=users", "/oauth/consent.html", "/support/"];
const browser = await chromium.launch(process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {});
let failed = 0;
for (const vp of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) for (const pg of PAGES) {
  const ctx = await browser.newContext({ viewport: vp, serviceWorkers: "block" });
  const page = await ctx.newPage(), errs = [];
  await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: "{}" }));
  page.on("pageerror", (e) => errs.push("JS: " + e.message));
  page.on("response", (r) => { if (r.url().startsWith(BASE) && r.status() >= 400) errs.push(`${r.status()}: ${r.url()}`); });
  await page.goto(BASE + pg, { waitUntil: "load" });
  await page.waitForTimeout(1500);
  console.log(`${errs.length ? "FAIL" : "ok  "} ${vp.width}px ${pg}${errs.length ? "\n  " + errs.join("\n  ") : ""}`);
  failed += errs.length; await ctx.close();
}
await browser.close(); server.close();
process.exit(failed ? 1 : 0);
