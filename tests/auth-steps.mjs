// Sign-in steps that moved here from the tools (David 23.11.2026, platform map §7.3: no tool has a sign-in screen):
//  1. a tool sends back an error (?err=mail_link), or Supabase refuses the mail link (#error_description=…)
//  2. the reset-password mail (#access_token=…&type=recovery): choose a new password here
//  3. the recovery code (?recover=1)
// Supabase is stubbed; the test records what the page sends. Run: node tests/auth-steps.mjs (needs "playwright";
// PW_MODULE may point at a local playwright-core, PW_EXEC at a local Chromium/Edge).
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
const browser = await chromium.launch(process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {});

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const JWT = (aal = "aal1") => `${b64u({ alg: "none" })}.${b64u({ sub: "u1", aal, exp: 9999999999 })}.sig`;
const MAILTOK = JWT();
const LIVE_SESSION = { access_token: JWT(), refresh_token: "r2", expires_in: 3600, expires_at: 9999999999, user: { id: "u1" } };

async function open(url) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, serviceWorkers: "block" });
  const page = await ctx.newPage(), calls = [], errs = [];
  page.on("pageerror", (e) => errs.push("JS: " + e.message));
  page.on("dialog", (d) => d.accept());
  await page.route(/^https?:\/\/(?!127\.0\.0\.1)/, (r) => {
    const req = r.request(), u = new URL(req.url());
    let body = null; try { body = req.postDataJSON() } catch { }
    calls.push({ path: u.pathname, auth: req.headers()["authorization"] || "", body });
    const J = (o, status = 200) => r.fulfill({ status, contentType: "application/json", body: JSON.stringify(o) });
    if (u.pathname === "/functions/v1/manage_users") {
      if (body?.action === "recovery_set_password") return J({ ok: true, username: "david" });
      if (body?.action === "recover_code") return J({ ok: true, left: 5 });
      return J({ ok: true });
    }
    if (u.pathname === "/auth/v1/token") return J(LIVE_SESSION);
    if (u.pathname === "/auth/v1/user") return J({ id: "u1" });
    if (u.pathname.startsWith("/rest/v1/")) return J([]);
    return J({});
  });
  await page.goto(BASE + url, { waitUntil: "load" });
  await page.waitForTimeout(400);
  return { ctx, page, calls, errs };
}
const fails = [];
const check = (name, ok, detail = "") => { console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : "  " + detail}`); if (!ok) fails.push(name); };
const msg = (p) => p.locator("#gateMsg").textContent();
const fn = (calls, action) => calls.find((c) => c.path === "/functions/v1/manage_users" && c.body?.action === action);

// 1. error from a tool
{
  const { ctx, page, errs } = await open("/?err=mail_link&next=%2Fdeadhead-dashboard%2F");
  check("err=mail_link: message shown", /הקישור מהמייל לא תקף/.test(await msg(page)), await msg(page));
  check("err=mail_link: login fields", await page.locator("#gUser").count() === 1);
  check("err=mail_link: err removed, next kept", new URL(page.url()).search === "?next=%2Fdeadhead-dashboard%2F", page.url());
  check("err=mail_link: no JS errors", !errs.length, errs.join(" | ")); await ctx.close();
}
{
  const { ctx, page } = await open("/?err=%3Cb%3Ehello%3C%2Fb%3E");
  check("unknown err code: nothing shown", (await msg(page)) === "", await msg(page)); await ctx.close();
}
{
  const { ctx, page } = await open("/#error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired");
  check("Supabase hash error: message shown", /הקישור מהמייל לא תקף/.test(await msg(page)), await msg(page));
  check("Supabase hash error: hash removed", !page.url().includes("#"), page.url()); await ctx.close();
}

// 2. reset-password mail
{
  const { ctx, page, calls, errs } = await open(`/#access_token=${MAILTOK}&expires_at=9999999999&expires_in=3600&refresh_token=r1&token_type=bearer&type=recovery`);
  check("recovery: new-password fields, no username", await page.locator("#gpw").count() === 1 && await page.locator("#gpw2").count() === 1 && await page.locator("#gUser").count() === 0);
  check("recovery: tokens removed from the address bar", !page.url().includes("access_token"), page.url());
  await page.fill("#gpw", "short"); await page.fill("#gpw2", "short"); await page.click("#gateBtn"); await page.waitForTimeout(200);
  check("recovery: weak password refused before any call", !fn(calls, "recovery_set_password") && /8 תווים/.test(await msg(page)), await msg(page));
  await page.fill("#gpw", "NewPass123"); await page.fill("#gpw2", "NewPass123"); await page.click("#gateBtn"); await page.waitForTimeout(600);
  const c = fn(calls, "recovery_set_password");
  check("recovery: manage_users recovery_set_password with the mail's session", !!c && c.auth === "Bearer " + MAILTOK && c.body.new_password === "NewPass123", JSON.stringify(c));
  check("recovery: then signs in as the returned user", calls.some((x) => x.path === "/auth/v1/token" && x.body?.email === "david@users.yalla-sa.app"));
  check("recovery: no JS errors", !errs.length, errs.join(" | ")); await ctx.close();
}

// 3. recovery code
{
  const { ctx, page, calls, errs } = await open("/?recover=1");
  check("recover=1: code step shown", await page.locator("#gCode").count() === 1 && await page.locator("#gUser").count() === 1);
  check("recover=1: removed from the address bar", !page.url().includes("recover"), page.url());
  await page.fill("#gUser", " David "); await page.fill("#gCode", "ABCDE-23456");
  await page.fill("#gpw", "NewPass123"); await page.fill("#gpw2", "NewPass124"); await page.click("#gateBtn"); await page.waitForTimeout(200);
  check("recover=1: mismatched passwords refused", !fn(calls, "recover_code") && /לא זהות/.test(await msg(page)), await msg(page));
  await page.fill("#gpw2", "NewPass123"); await page.click("#gateBtn"); await page.waitForTimeout(600);
  const c = fn(calls, "recover_code");
  check("recover=1: manage_users recover_code", !!c && c.body.username === "david" && c.body.code === "ABCDE-23456" && c.body.new_password === "NewPass123", JSON.stringify(c));
  check("recover=1: no JS errors", !errs.length, errs.join(" | ")); await ctx.close();
}
// the login screen's own links: code step and forgot password stay in the portal
{
  const { ctx, page, calls } = await open("/");
  await page.click("[data-gm=help]");
  check("help: no link into a tool", await page.locator("#gHelp a[href*='deadhead']").count() === 0);
  await page.click("#gHelp [data-gm=forgot]"); await page.waitForTimeout(100);
  check("forgot without a username: asks for it, no call", !fn(calls, "forgot") && /שם המשתמש/.test(await msg(page)), await msg(page));
  await page.fill("#gUser", "david"); await page.click("#gHelp [data-gm=forgot]"); await page.waitForTimeout(300);
  check("forgot: manage_users forgot", fn(calls, "forgot")?.body.username === "david" && /נשלח/.test(await msg(page)), await msg(page));
  await page.click("#gHelp [data-gm=code]");
  check("help → code step", await page.locator("#gCode").count() === 1);
  await page.click("#gateAlt [data-gm=login]");
  check("code step → back to sign-in", await page.locator("#gCode").count() === 0 && await page.locator("#gUser").count() === 1);
  await ctx.close();
}
await browser.close(); server.close();
console.log(fails.length ? `${fails.length} failed` : "all passed");
process.exit(fails.length ? 1 : 0);
