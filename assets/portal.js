// yalla-sa portal: entry gate + tool tiles.
// Auth mirrors the deadhead tool (dashboard/assets/app.js): same Supabase project, same internal sign-in address
// <username>@users.yalla-sa.app, same session shape, same error texts.
// Two-step verification is step-up (David, 2026-11-18): sign-in asks only for the password; the code (aal2) is asked
// when the control panel opens (panel.js) and manage_users enforces aal2 on the server. Basis: no personal data in the
// system today; re-check when personal data enters (docs/single-login-design.md).
// The forced password change and the recovery code stay in the deadhead tool; the portal sends the user there.
"use strict";
const SB = "https://xghfcdgettrcdciwwzbl.supabase.co", KEY = "sb_publishable_hCBsqYekz61JY6SFfT_sjw_-wj0QGXT";
const DOMAIN = "users.yalla-sa.app";
const DEADHEAD = "/deadhead-dashboard/";
const SKEY = "ys_session", ACT = "ys_act", TRUST = "ys_trust";
// durations come from assets/auth-settings.js (one place for the portal and the tools)
const AUTHCFG = window.YS_AUTH || { trustHours: 12, idleMinutes: 30 }, TRUST_H = +AUTHCFG.trustHours || 12, IDLE_MIN = +AUTHCFG.idleMinutes || 30;
const trustLabel = () => TRUST_H >= 48 && TRUST_H % 24 === 0 ? `${TRUST_H / 24} יום` : `${TRUST_H} שעות`;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const lsGet = k => { try { return localStorage.getItem(k) } catch { return null } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v) } catch { } };
// idle sign-out after IDLE_MIN minutes; a device marked as personal at sign-in (TRUST = expiry, TRUST_H from sign-in)
// has no idle sign-out until then. The tools read the same keys. Sign-out clears the mark.
const trustUntil = () => { const t = +lsGet(TRUST) || 0; return t > Date.now() ? t : 0 };
const idleMs = () => trustUntil() ? Infinity : IDLE_MIN * 6e4;
if (!lsGet(SKEY)) lsSet(TRUST, null); // no session (signed out, or disconnected from another device): no mark either

// ---------- session ----------
let SES = null; try { SES = JSON.parse(lsGet(SKEY) || "null") } catch { }
// already signed in (e.g. back from a tool): no intro, the gate stays hidden unless a step is still owed (gateMode shows it)
if (SES) document.body.classList.add("signed", "no-intro");
const lastAct = () => +lsGet(ACT) || 0;
const touchAct = () => { const n = Date.now(); if (n - lastAct() > 20000) lsSet(ACT, String(n)) };
if (SES && Date.now() - lastAct() > idleMs()) { // stale session: drop it here and revoke it on the server
  const old = SES; SES = null; lsSet(SKEY, null);
  fetch(SB + "/auth/v1/token?grant_type=refresh_token", { method: "POST", headers: { apikey: KEY, "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: old.refresh_token }) })
    .then(r => r.ok ? r.json() : null).then(j => j && fetch(SB + "/auth/v1/logout", { method: "POST", headers: { apikey: KEY, Authorization: "Bearer " + j.access_token } })).catch(() => { });
}
["pointerdown", "keydown", "wheel", "touchstart"].forEach(t => addEventListener(t, touchAct, { passive: true, capture: true }));
setInterval(async () => {
  if (SES && Date.now() - lastAct() > idleMs()) { await signOut(); location.replace(location.pathname) }
}, 60000);
function setSes(j) {
  SES = j ? { access_token: j.access_token, refresh_token: j.refresh_token, expires_at: +j.expires_at || Math.floor(Date.now() / 1000) + (+j.expires_in || 3600), user: j.user || null } : null;
  lsSet(SKEY, SES ? JSON.stringify(SES) : null);
}
async function http(url, opt = {}, ms = 15000) {
  const ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { ...opt, signal: ctl.signal }); const t = await r.text(); let j = null; try { j = t ? JSON.parse(t) : null } catch { }
    if (!r.ok) { const e = new Error(j ? [j.error_code, j.error, j.code, j.msg, j.message, j.error_description].filter(Boolean).join(" · ") || ("שגיאה " + r.status) : "שגיאה " + r.status); e.status = r.status; throw e }
    return j;
  } finally { clearTimeout(tm) }
}
const authPost = (path, body, tok) => http(SB + "/auth/v1/" + path, { method: "POST", headers: { apikey: KEY, "Content-Type": "application/json", ...(tok ? { Authorization: "Bearer " + tok } : {}) }, body: JSON.stringify(body) });
let refreshing = null;
function refresh() {
  return refreshing ??= (async () => {
    try {
      const o = JSON.parse(lsGet(SKEY) || "null"); // another tab may have refreshed already
      if (o && o.refresh_token !== SES.refresh_token && o.expires_at - 60 > Date.now() / 1000) { SES = o; return }
      setSes(await authPost("token?grant_type=refresh_token", { refresh_token: SES.refresh_token }));
    } catch (e) { if (e.status >= 400 && e.status < 500) setSes(null); throw e } finally { refreshing = null }
  })();
}
async function token() { if (!SES) throw new Error("not_signed_in"); if (SES.expires_at - 60 < Date.now() / 1000) await refresh(); if (!SES) throw new Error("not_signed_in"); return SES.access_token }
async function sb(path, opt = {}, retry = true) {
  try { return await http(SB + path, { ...opt, headers: { apikey: KEY, "Content-Type": "application/json", Authorization: "Bearer " + await token(), ...(opt.headers || {}) } }) }
  catch (e) { if (e.status === 401 && retry && SES) { await refresh(); return sb(path, opt, false) } throw e }
}
const getRows = (t, qs) => sb(`/rest/v1/${t}?${qs}`);
const authReq = async (method, path, body) => http(SB + "/auth/v1/" + path, { method, headers: { apikey: KEY, "Content-Type": "application/json", Authorization: "Bearer " + await token() }, ...(body ? { body: JSON.stringify(body) } : {}) });
const fnCall = (body) => http(SB + "/functions/v1/manage_users", { method: "POST", headers: { apikey: KEY, "Content-Type": "application/json" }, body: JSON.stringify(body) }, 30000);

// same texts as the deadhead tool
const ERR = {
  invalid_credentials: "שם משתמש או סיסמה שגויים", "Invalid login credentials": "שם משתמש או סיסמה שגויים", user_banned: "החשבון הושבת. פנה למנהל המערכת", disabled: "החשבון הושבת. פנה למנהל המערכת",
  not_signed_in: "צריך להיכנס מחדש", "rate limit": "יותר מדי ניסיונות. נסה שוב בעוד כמה דקות", over_request_rate_limit: "יותר מדי ניסיונות. נסה שוב בעוד כמה דקות",
  server_error: "שגיאה בשרת. נסה שוב", mfa_required: "צריך להיכנס מחדש עם קוד האימות הדו־שלבי",
  "Invalid TOTP code": "הקוד שגוי או שפג תוקפו. הקלד את הקוד שמוצג עכשיו באפליקציה", mfa_verification_failed: "הקוד שגוי או שפג תוקפו. הקלד את הקוד שמוצג עכשיו באפליקציה",
  "Failed to fetch": "אין חיבור לשרת. בדוק את החיבור לאינטרנט ונסה שוב"
};
const errText = e => { const m = String(e && e.message || e); for (const k in ERR) if (m.includes(k)) return ERR[k]; return /abort/i.test(m) ? "אין תשובה מהשרת. נסה שוב" : m };

// username: trimmed + lower-case. An account with a recovery email has a real Auth email: manage_users signs it in.
async function signIn(user, pw) {
  user = String(user || "").trim().toLowerCase();
  try { setSes(await authPost("token?grant_type=password", { email: user + "@" + DOMAIN, password: pw })) }
  catch (e) {
    if (!/invalid_credentials|Invalid login/i.test(e.message)) throw e;
    let r = null; try { r = await fnCall({ action: "sign_in", username: user, password: pw }) } catch (e2) { if (/rate limit/i.test(e2.message)) throw e2 }
    if (!r || !r.session) throw e; setSes(r.session);
  }
  lsSet("ys_user", user); touchAct();
}
async function signOut() { try { if (SES) await authPost("logout", {}, SES.access_token) } catch { } setSes(null); lsSet(TRUST, null) }

// ---------- MFA (TOTP) ----------
const jwtOf = t => { try { return JSON.parse(atob(String(t).split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) } catch { return {} } };
const aal = () => SES ? jwtOf(SES.access_token).aal : null;
async function mfaVerify(fid, code) {
  code = String(code || "").replace(/\D/g, ""); if (code.length !== 6) throw new Error("mfa_verification_failed");
  const ch = await authReq("POST", `factors/${fid}/challenge`, {});
  setSes(await authReq("POST", `factors/${fid}/verify`, { challenge_id: ch.id, code }));
}

// ---------- access ----------
let ME = null, PROFILE = null, PLATFORM = false, OPS = [], MS = [], OP = null, MFAF = null, TILES = null;
const ROLEHE = { admin: "מנהל", editor: "עורך", viewer: "צופה" };
async function loadAccess() {
  ME = SES.user && SES.user.id ? SES.user : await authReq("GET", "user");
  if (!SES.user) { SES.user = ME; lsSet(SKEY, JSON.stringify(SES)) }
  const [pr, pa, ms, ops] = await Promise.all([
    getRows("profiles", "select=username,display_name,must_change_password,disabled&user_id=eq." + encodeURIComponent(ME.id)),
    getRows("platform_admins", "select=user_id&user_id=eq." + encodeURIComponent(ME.id)),
    getRows("memberships", "select=operator_id,role&user_id=eq." + encodeURIComponent(ME.id)),
    getRows("operators", "select=id,slug,name,logo_url&order=name")]);
  PROFILE = pr[0] || null; PLATFORM = pa.length > 0; MS = ms || [];
  OPS = (ops || []).filter(o => PLATFORM || MS.some(m => m.operator_id === o.id));
  // a platform admin is not a member of an operator: the default view is "all operators" (OP = null); picking an
  // operator in the switcher only narrows the view. A member starts at his last (or first) operator.
  const urlOp = new URLSearchParams(location.search).get("op");
  OP = PLATFORM ? (OPS.find(o => o.slug === urlOp) || null) : (OPS.find(o => o.slug === (urlOp || lsGet("ys_op"))) || OPS[0] || null);
}
const roleAt = op => PLATFORM ? "admin" : op ? (MS.find(m => m.operator_id === op.id)?.role || null) : null;

// ---------- gate ----------
let GMODE = "login";
const EYE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const fld = (id, label, type, ac, extra = "") => `<div class="field"><label for="${id}">${label}</label>${type === "password"
  ? `<div class="pw-wrap"><input id="${id}" type="password" autocomplete="${ac}" dir="ltr" required ${extra}><button type="button" class="eye" data-eye="${id}" aria-label="הצגת הסיסמה" aria-pressed="false">${EYE}</button></div>`
  : `<input id="${id}" type="${type}" autocomplete="${ac}" dir="ltr" required ${extra}>`}</div>`;
function gateMode(m, { err = "", msg = "" } = {}) {
  GMODE = m; document.body.classList.remove("signed"); const uname = (PROFILE && PROFILE.username) || lsGet("ys_user") || "";
  const F = $("#gateFields"), A = $("#gateAlt"), B = $("#gateBtn"), S = $("#gateSub"); B.disabled = false; B.hidden = false;
  if (m === "login") {
    S.textContent = "שם משתמש וסיסמה של yalla-sa";
    F.innerHTML = fld("gUser", "שם משתמש", "text", "username", `value="${esc(uname)}" autocapitalize="off" spellcheck="false"`) + fld("gpw", "סיסמה", "password", "current-password")
      + `<label class="trust"><input type="checkbox" id="gTrust" aria-describedby="gTrustHint"${trustUntil() ? " checked" : ""}><span>זה המכשיר האישי שלי: להישאר מחובר ${trustLabel()}</span></label>
      <p class="trust-hint" id="gTrustHint">רק במכשיר אישי עם נעילת מסך. במחשב משותף לא לסמן.</p>`;
    B.textContent = "כניסה";
    A.innerHTML = `<button type="button" class="link-btn dim" data-gm="help" aria-expanded="false" aria-controls="gHelp">אין לי גישה</button>
      <div id="gHelp" class="help" hidden>
        <p><b>שכחת סיסמה או שאין לך חשבון?</b> פנה למנהל המערכת אצל המפעיל שלך. הוא יכול לאפס לך סיסמה או ליצור לך משתמש.</p>
        <p><b>מנהל מערכת עם קוד שחזור?</b> <a href="${esc(DEADHEAD)}?recover=1">כניסה עם קוד שחזור</a> (נפתח בכלי תכנון נסיעות ריקות).</p>
      </div>`;
  } else if (m === "finish") { // forced password change: done in the deadhead tool (manage_users)
    S.textContent = `צריך לבחור סיסמה חדשה${uname ? " לחשבון " + uname : ""}. עושים את זה פעם אחת בכלי תכנון נסיעות ריקות, ואז חוזרים לכאן.`;
    F.innerHTML = ""; B.textContent = "המשך להשלמת החשבון";
    A.innerHTML = `<button type="button" class="link-btn dim" data-gm="logout">יציאה</button>`;
  } else if (m === "noaccess") {
    S.textContent = `החשבון ${uname} עוד לא שויך לאף מפעיל. פנה למנהל המערכת.`;
    F.innerHTML = ""; B.textContent = "יציאה"; A.innerHTML = "";
  }
  const gm = $("#gateMsg"); gm.className = "msg" + (err ? " err" : msg ? " ok" : ""); gm.textContent = err || msg; $("#gateWarn").textContent = "";
  (F.querySelector("input") || B).focus();
}
// ?next=<path>: a tool sent the user here to sign in; back only to a live tool's own path on this site (allow-list)
async function nextUrl() {
  const n = new URLSearchParams(location.search).get("next") || "";
  if (!/^\/[a-z0-9-]+\/[^\\]*$/i.test(n) || n.startsWith("//")) return "";
  try { await loadTiles() } catch { return "" }
  const ok = TILES.some(t => t.status === "live" && typeof t.url === "string" && t.url.startsWith("/") && n.startsWith(t.url));
  return ok ? n : "";
}
// returns true when the portal can open
async function unlock() {
  await loadAccess();
  if (PROFILE && PROFILE.disabled) { await signOut(); gateMode("login", { err: ERR.disabled }); return false }
  if (PROFILE && PROFILE.must_change_password) { gateMode("finish"); return false }
  if (!OP && !PLATFORM) { gateMode("noaccess"); return false }
  const nx = await nextUrl(); if (nx) { location.replace(nx); return true }
  await showPortal();
  return true;
}

$("#gateAlt").addEventListener("click", async e => {
  const b = e.target.closest("[data-gm]"); if (!b) return; const m = b.dataset.gm;
  if (m === "help") { const h = $("#gHelp"); h.hidden = !h.hidden; b.setAttribute("aria-expanded", String(!h.hidden)) }
  else if (m === "logout") { await signOut(); gateMode("login") }
});
$("#gateFields").addEventListener("click", e => {
  const b = e.target.closest("[data-eye]"); if (!b) return; const i = document.getElementById(b.dataset.eye);
  const show = i.type === "password"; i.type = show ? "text" : "password"; b.setAttribute("aria-pressed", String(show));
  b.setAttribute("aria-label", show ? "הסתרת הסיסמה" : "הצגת הסיסמה");
});
$("#gateFields").addEventListener("focusout", e => { if (e.target.id === "gUser") e.target.value = e.target.value.trim().toLowerCase() });
// keyboard warnings, as in the deadhead tool: Hebrew layout or Caps Lock
let CAPS = false;
const kbWarn = () => {
  const heb = [...document.querySelectorAll("#gateFields input")].some(i => /[֐-׿]/.test(i.value));
  $("#gateWarn").textContent = heb ? "שים לב: יש אותיות בעברית. כנראה המקלדת בעברית: עבור לאנגלית (Alt+Shift) והקלד שוב." : CAPS ? "שים לב: Caps Lock פועל (אותיות גדולות)." : "";
};
$("#gateForm").addEventListener("keydown", e => {
  if (!(e.target instanceof HTMLInputElement)) return;
  if (e.getModifierState) CAPS = e.getModifierState("CapsLock");
  if (/[֐-׿]/.test(e.key || "")) { $("#gateWarn").textContent = "שים לב: המקלדת בעברית. עבור לאנגלית (Alt+Shift) לפני הקלדת שם המשתמש והסיסמה."; return }
  kbWarn();
});
$("#gateForm").addEventListener("input", kbWarn);
$("#gateForm").addEventListener("submit", async e => {
  e.preventDefault(); const m = $("#gateMsg"); m.className = "msg"; m.textContent = "רגע…"; $("#gateBtn").disabled = true;
  try {
    if (GMODE === "login") {
      const user = $("#gUser").value.trim().toLowerCase(), pw = $("#gpw").value; $("#gUser").value = user;
      if (!user || !pw) throw new Error("invalid_credentials");
      const trust = !!$("#gTrust")?.checked;
      await signIn(user, pw); lsSet(TRUST, null);
      // personal device: recorded on the server for this session (listed and disconnectable in the control panel)
      if (trust) try { const r = await fnAuth({ action: "trust_device", hours: TRUST_H }); lsSet(TRUST, String(Date.parse(r.expires_at))) } catch (e) { console.warn("trust_device", e) }
      await unlock();
    } else if (GMODE === "finish") { location.assign(DEADHEAD) }
    else if (GMODE === "noaccess") { await signOut(); gateMode("login") }
  } catch (err) {
    m.className = "msg err"; m.textContent = errText(err); $("#gateBtn").disabled = false;
    if (GMODE === "login") $("#gpw")?.select();
  }
});

// ---------- portal ----------
const ICONS = {
  "bus": '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="12" y="7" width="22" height="24" rx="4"/><path d="M12 19h22M16 13h14"/><circle cx="17" cy="25.5" r="1.6"/><circle cx="29" cy="25.5" r="1.6"/><path d="M15 31v3M31 31v3"/><path d="M6 40h26" stroke-dasharray="2.5 3"/><path d="M40 33.5c-2.6-2.7-4-4.9-4-6.7a4 4 0 0 1 8 0c0 1.8-1.4 4-4 6.7z"/><circle class="dot" cx="40" cy="26.8" r="1.4"/></svg>',
  "doc-check": '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M30 6H13a3 3 0 0 0-3 3v30a3 3 0 0 0 3 3h12"/><path d="M30 6l8 8v12"/><path d="M30 6v8h8"/><path d="M16 18h14M16 24h14M16 30h8"/><path d="M29 36l4 4 8-9"/></svg>',
  "doc-pen": '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M30 6H13a3 3 0 0 0-3 3v30a3 3 0 0 0 3 3h11"/><path d="M30 6l8 8v6"/><path d="M30 6v8h8"/><path d="M16 18h14M16 24h14M16 30h7"/><path d="M41 25l3 3-12 12-4.5 1.5L29 37z"/></svg>',
  "map": '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M6 12l11-4 14 4 11-4v28l-11 4-14-4-11 4z"/><path d="M17 8v28M31 12v12"/><path d="M36 37c-3-3.1-4.5-5.6-4.5-7.6a4.5 4.5 0 0 1 9 0c0 2-1.5 4.5-4.5 7.6z"/><circle cx="36" cy="29.4" r="1.5"/></svg>'
};
async function loadTiles() {
  if (TILES) return TILES;
  const r = await fetch("tiles.json", { cache: "no-cache" }); if (!r.ok) throw new Error("tiles " + r.status);
  return TILES = await r.json();
}
// Until the identity migration (docs/identity-migration.sql) is approved: a live tile needs a membership at the chosen
// operator with role >= min_role (platform admins see all). "soon" tiles show to everyone, not clickable.
const RANK = { viewer: 1, editor: 2, admin: 3 };
const canOpen = t => { const r = roleAt(OP); return !!r && (RANK[r] || 0) >= (RANK[t.min_role] || 1) };
// ?op= only for tools on this site; another domain (app.yalla-sa.app) has its own sign-in and operator choice
function tileUrl(t) { const u = new URL(t.url, location.href); if (OP && u.origin === location.origin) u.searchParams.set("op", OP.slug); return u.href }
const ALLOPS = "כל המפעילים";
function drawTiles() {
  const list = (TILES || []).filter(t => t.status === "soon" || (t.status === "live" && t.url && canOpen(t)));
  $("#tiles").innerHTML = list.map(t => {
    const icon = ICONS[t.icon] || "";
    if (t.status === "live") return `<a class="tile live" href="${esc(tileUrl(t))}" rel="noopener">
        <span class="ic">${icon}</span><h2>${esc(t.title)}</h2><p>${esc(t.desc)}</p>
        <span class="st"><span class="on">פעיל</span><span class="bar" aria-hidden="true"></span><span class="go">כניסה לכלי ←</span></span></a>`;
    return `<div class="tile soon" aria-disabled="true"><span class="ic">${icon}</span><h2>${esc(t.title)}</h2><p>${esc(t.desc)}</p>
        <span class="st"><span class="pill-soon">בקרוב</span></span></div>`;
  }).join("");
}
function drawOperator() {
  const sel = $("#opSel"), wrap = $("#opWrap");
  sel.innerHTML = (PLATFORM ? `<option value=""${OP ? "" : " selected"}>${ALLOPS}</option>` : "") +
    OPS.map(o => `<option value="${esc(o.slug)}"${o === OP ? " selected" : ""}>${esc(o.name)}</option>`).join("");
  const single = !PLATFORM && OPS.length < 2; sel.disabled = single; wrap.classList.toggle("single", single);
  // operators.logo_url is a site-relative path (assets/operators/<slug>.png, copied here from the deadhead tool);
  // external URLs are not loaded (CSP img-src 'self')
  const lg = $("#opLogo"), src = OP && OP.logo_url && /^assets\/operators\/[a-z0-9-]+\.(png|svg|webp)$/.test(OP.logo_url) ? OP.logo_url : "";
  lg.hidden = !src; if (src) { lg.src = src; lg.alt = "" }
  if (OP && !PLATFORM) lsSet("ys_op", OP.slug);
  const r = roleAt(OP); $("#menuRole").textContent = PLATFORM ? "מנהל מערכת" : r ? `${ROLEHE[r]} · ${OP.name}` : "";
}
$("#opLogo").addEventListener("error", e => { e.target.hidden = true });
$("#opSel").addEventListener("change", e => {
  OP = OPS.find(o => o.slug === e.target.value) || (PLATFORM ? null : OP); drawOperator(); drawTiles();
  const u = new URL(location.href); if (OP) u.searchParams.set("op", OP.slug); else u.searchParams.delete("op");
  history.replaceState(null, "", u.pathname + u.search);
});
async function showPortal() {
  const name = (PROFILE && (PROFILE.display_name || PROFILE.username)) || lsGet("ys_user") || "";
  $("#hello").textContent = name ? `שלום ${name}` : "שלום";
  $("#userName").textContent = name; $("#menuName").textContent = name; $("#menuUser").textContent = PROFILE ? PROFILE.username : "";
  drawOperator();
  try { await loadTiles(); drawTiles(); $("#tilesMsg").textContent = "" }
  catch (e) { console.warn(e); $("#tilesMsg").className = "msg err"; $("#tilesMsg").textContent = "לא ניתן לטעון את רשימת הכלים. רענן את הדף." }
  document.title = OP ? `יאללה־סע · ${OP.name}` : "יאללה־סע";
  document.body.classList.remove("signed");
  if (typeof cpSetup === "function") cpSetup();
  $("#gate").hidden = true; $("#portal").hidden = false; document.body.classList.remove("is-gate");
  placeOp();
}
// phone: the operator pill sits under the header (as in the approved image)
const PHONE = matchMedia("(max-width:640px)");
function placeOp() { const w = $("#opWrap"); (PHONE.matches ? $("#opMobileSlot") : $(".top-tools")).prepend(w) }
PHONE.addEventListener("change", placeOp);
// user menu (desktop: name button; phone: hamburger)
function toggleMenu(btn, open) {
  const m = $("#userMenu"); open = open ?? m.hidden; m.hidden = !open;
  [$("#userBtn"), $("#menuBtn")].forEach(b => b.setAttribute("aria-expanded", String(open && b === btn)));
  if (open) m.querySelector(".menu-item").focus();
}
$("#userBtn").addEventListener("click", e => toggleMenu(e.currentTarget));
$("#menuBtn").addEventListener("click", e => toggleMenu(e.currentTarget));
document.addEventListener("click", e => { if (!e.target.closest(".user,#menuBtn")) toggleMenu(null, false) });
document.addEventListener("keydown", e => { if (e.key === "Escape" && !$("#userMenu").hidden) { toggleMenu(null, false); (PHONE.matches ? $("#menuBtn") : $("#userBtn")).focus() } });
const logout = async () => { await signOut(); location.replace(location.pathname) };
$("#logoutBtn").addEventListener("click", logout);
$("#userMenu").addEventListener("click", e => { if (e.target.closest("[data-act=logout]")) logout() });

// ---------- start ----------
(async () => {
  if (SES) {
    try { if (await unlock()) return; return }
    catch (e) { console.warn(e); if (e.status === 401 || e.status === 403 || e.message === "not_signed_in") setSes(null) }
    gateMode("login", SES ? { err: "לא ניתן לטעון את הנתונים. נסה שוב." } : {}); return;
  }
  gateMode("login");
})();
