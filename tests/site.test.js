// node --test tests/*.test.js  · basic site checks (CI, 2026-11-22): the static site is whole, its scripts parse, no secrets.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs"), path = require("path"), { execFileSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const files = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean);
const read = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
const TEXT = /\.(html|js|css|json|webmanifest|md|yml|yaml|svg|txt)$|^CNAME$/;

// "the site builds": no build step, so every file a page or stylesheet points at must exist
test("every local file referenced by a page or stylesheet exists", () => {
  const missing = [];
  for (const f of files.filter((x) => /\.(html|css)$/.test(x))) {
    const refs = [...read(f).matchAll(/(?:src|href)="([^"]+)"|url\(\s*['"]?([^'")]+)['"]?\s*\)/g)].map((m) => m[1] || m[2]);
    for (const r of refs) {
      if (/^(https?:|mailto:|tel:|data:|#|\/\/)/.test(r) || r.includes("${")) continue;
      const clean = r.split(/[?#]/)[0];
      if (!clean || clean === "./" || clean === "/") continue;
      const p = clean.startsWith("/") ? path.join(ROOT, clean) : path.join(ROOT, path.dirname(f), clean);
      if (!fs.existsSync(p)) missing.push(`${f} -> ${r}`);
    }
  }
  assert.deepEqual(missing, []);
});

test("every script parses", () => {
  for (const f of files.filter((x) => x.endsWith(".js"))) execFileSync(process.execPath, ["--check", path.join(ROOT, f)]);
});

test("JSON files are valid", () => {
  for (const f of files.filter((x) => /\.(json|webmanifest)$/.test(x))) assert.doesNotThrow(() => JSON.parse(read(f)), f);
});

// public repo: only the Supabase publishable key may appear. Anything that looks like a server secret fails.
const SECRET = [
  [/sb_secret_[A-Za-z0-9_-]{10,}/, "Supabase secret key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "JWT (service_role / anon key)"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}/, "GitHub token"],
  [/\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/, "Resend API key"],
  [/\bsk_(live|test)_[A-Za-z0-9]{16,}/, "Stripe key"],
  [/\bAKIA[0-9A-Z]{16}\b/, "AWS key"],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/, "Slack token"],
  [/\bEAA[A-Za-z0-9]{40,}/, "Meta (WhatsApp) token"],
  [/(TOOL_ACCESS_KEY|SERVICE_ROLE_KEY|RESEND_API_KEY|WA_INTERNAL_KEY|CLIENT_SECRET)\s*[:=]\s*['"][^'"]{8,}['"]/i, "secret assigned in code"],
];
test("no keys or secrets in the code", () => {
  const hits = [];
  for (const f of files.filter((x) => TEXT.test(x))) {
    const s = read(f);
    for (const [re, what] of SECRET) if (re.test(s)) hits.push(`${f}: ${what}`);
  }
  assert.deepEqual(hits, []);
});
