// yalla-sa control panel (פאנל בקרה), moved here from the deadhead tool's "חדר בקרה · משתמשים והרשאות".
// Tabs: users, permissions per tool, my security. Every write goes through the manage_users Edge Function, which
// checks the caller again (platform admin: everyone; operator admin: viewers/editors of his operators; MFA aal2).
// RLS in the database stays the real enforcement: this screen only shows and asks.
// Per tool, a separate role per operator (bug fixed 2026-11-19: one shared role changed both tools):
//   deadhead -> memberships.role (set_membership / remove_membership); every other live tool -> tool_roles
//   (set_tool_role / remove_tool_role, list returns them as u.tools). "soon" tools show "—".
"use strict";
Object.assign(ERR, {
  "row-level security": "אין לך הרשאה לשנות את זה", not_allowed: "אין לך הרשאה לפעולה הזו", "42501": "אין לך הרשאה לשנות את זה",
  weak_password: "הסיסמה צריכה להיות לפחות 8 תווים, עם אותיות ומספרים", "Password should be": "הסיסמה צריכה להיות לפחות 8 תווים, עם אותיות ומספרים",
  same_password: "הסיסמה החדשה זהה לישנה", wrong_password: "הסיסמה הנוכחית שגויה",
  temp_expired: "הסיסמה הזמנית פגה. לקבלת סיסמה חדשה כתבו לנו: support@yalla-sa.app",
  bad_username: "שם משתמש: 3–32 תווים, אותיות באנגלית, ספרות, נקודה, מקף או קו תחתון", username_taken: "שם המשתמש הזה כבר תפוס",
  bad_input: "הנתונים לא תקינים", mfa_enroll_required: "מנהל חייב אימות דו־שלבי: הפעל אותו בלשונית \"האבטחה שלי\"",
  password_change_not_allowed: "שינוי סיסמה רק דרך המסך של האתר", mfa_change_not_allowed: "לשינוי האימות הדו־שלבי צריך להיכנס עם קוד האימות",
  last_platform_admin: "חייב להישאר לפחות מנהל מערכת פעיל אחד", bad_email: "כתובת המייל לא תקינה", email_taken: "המייל הזה כבר משויך לחשבון אחר",
});
const fnRaw = async body => http(SB + "/functions/v1/manage_users", { method: "POST",
  headers: { apikey: KEY, "Content-Type": "application/json", Authorization: "Bearer " + await token() }, body: JSON.stringify(body) }, 30000);
// step-up (David, 2026-11-18): sign-in is password-only; manage_users refuses sensitive actions without aal2. When it
// does, ask for the code here and try once more. The server stays the enforcement.
async function fnAuth(body) {
  try { return await fnRaw(body) }
  catch (e) {
    if (!/mfa_required|mfa_enroll_required/.test(e.message)) throw e;
    const ver = (await myFactors()).filter(f => f.status === "verified");
    if (!ver.length || await stepDialog(ver[0].id) !== "ok") throw e;
    return fnRaw(body);
  }
}
// the code dialog: resolves "ok" once the session is aal2, "cancel" when closed
function stepDialog(fid) {
  return new Promise(res => {
    const d = $("#dlgStep"), f = $("#stepForm"), m = $("#stMsg"), ok = $("#stOk");
    $("#stOtp").value = ""; m.className = "msg"; m.textContent = "";
    const done = r => { f.onsubmit = null; $("#stCancel").onclick = null; d.onclose = null; if (d.open) d.close(); res(r) };
    f.onsubmit = async e => {
      e.preventDefault(); m.className = "msg"; m.textContent = "בודק…"; ok.disabled = true;
      try { await mfaVerify(fid, $("#stOtp").value); done("ok") }
      catch (err) { m.className = "msg err"; m.textContent = errText(err); $("#stOtp").select() } finally { ok.disabled = false }
    };
    $("#stCancel").onclick = () => done("cancel"); d.onclose = () => done("cancel"); // Escape closes the dialog
    d.showModal(); $("#stOtp").focus();
  });
}
// before the users / permissions tabs: "ok" (aal2 now), "cancel", or "none" (no verified factor yet)
async function stepUp() {
  if (aal() === "aal2") return "ok";
  const ver = (await myFactors()).filter(f => f.status === "verified");
  return ver.length ? stepDialog(ver[0].id) : "none";
}
const NEED_ENROLL = "כדי לנהל משתמשים והרשאות צריך אימות דו־שלבי. הפעל אותו כאן, בלשונית \"האבטחה שלי\", ואז הלשוניות של המשתמשים וההרשאות ייפתחו.";
const USERRE = /^[a-z0-9._-]{3,32}$/;
// password policy (manage_users): at least 8 characters, with a letter and a digit
const weakPw = pw => pw.length < 8 || !/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw);
const pwState = pw => {
  if (!pw) return ["muted", "לפחות 8 תווים, עם אותיות באנגלית ומספרים"];
  const miss = [pw.length < 8 ? `עוד ${8 - pw.length} תווים (לפחות 8)` : "", !/[A-Za-z]/.test(pw) ? "אותיות באנגלית" : "", !/[0-9]/.test(pw) ? "מספרים" : ""].filter(Boolean);
  return miss.length ? ["err", "חסר: " + miss.join(", ") + (/[֐-׿]/.test(pw) && !/[A-Za-z]/.test(pw) ? ". יש אותיות בעברית: המקלדת כנראה בעברית" : "")] : ["ok", "✓ לפחות 8 תווים, עם אותיות ומספרים"];
};
const pwShow = (inp, box) => { if (!inp || !box) return; const [c, t] = pwState(inp.value); box.className = "msg pwchk " + c; box.textContent = t; inp.setAttribute("aria-invalid", c === "err" ? "true" : "false") };
function suggestPw() { const a = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"; for (;;) { const r = crypto.getRandomValues(new Uint32Array(12)), pw = [...r].map(x => a[x % a.length]).join(""); if (!weakPw(pw)) return pw } }
const canManage = () => PLATFORM || MS.some(m => m.role === "admin");
const adminOps = () => OPS.filter(o => PLATFORM || MS.some(m => m.operator_id === o.id && m.role === "admin"));
const opName = id => (OPS.find(o => o.id === id) || {}).name || "מפעיל אחר";
const isAdminAny = () => PLATFORM || MS.some(m => m.role === "admin");
const ROLES = ["viewer", "editor", "admin"];
// contact email + "send details" (welcome-mail spec 2026-11-19 §1): platform admin only; an operator admin only views
const DETAILS_MSG = {
  quota: "המכסה היומית של המיילים נגמרה. הסיסמה לא הוחלפה. נסה שוב מחר.",
  send_failed_locked: "השליחה נכשלה והסיסמה הוחלפה. לחץ שוב על שליחת פרטים או קבע סיסמה זמנית.",
  send_failed: "השליחה נכשלה. הסיסמה לא הוחלפה. נסה שוב בעוד כמה דקות.",
  busy: "שליחה כבר מתבצעת. נסה שוב בעוד דקה.",
  no_email: "אין כתובת מייל שמורה למשתמש.",
  disabled: "המשתמש מושבת. הפעל אותו לפני שליחת פרטים.",
  bad_email: "כתובת המייל לא תקינה.",
};
const detailsErr = e => { const m = String(e && e.message || e); for (const k in DETAILS_MSG) if (m.includes(k)) return DETAILS_MSG[k]; return errText(e) };
const LOCK = '<svg class="lk" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/></svg>';

let CTL = null, CTAB = "users", CFILTER = "", CQ = "", CMENU = null;
const P = () => $("#cp");
const cmsg = (t, cls = "") => { const m = $("#cpMsg"); m.className = "msg " + cls; m.textContent = t; if (t) m.scrollIntoView({ block: "nearest" }) };

// ---------- open / close ----------
function cpSetup() { // called after the portal opens (portal.js showPortal)
  $("#cpBtn").hidden = !canManage();
  for (const t of ["users", "matrix"]) $(`#cpTabs [data-tab="${t}"]`).hidden = !canManage();
  $('#cpTabs [data-tab="status"]').hidden = !PLATFORM; // platform status: platform admins only
  // a tool's "users and permissions" link lands here with ?panel=users|matrix|sec
  const q = new URL(location.href), want = q.searchParams.get("panel");
  if (want) { q.searchParams.delete("panel"); history.replaceState(null, "", q.pathname + q.search); if (["users", "matrix", "sec", "status"].includes(want)) cpOpen(want) }
}
let cpReturn = null;
async function cpOpen(tab) {
  cpReturn = document.activeElement; toggleMenu(null, false);
  CTAB = canManage() ? tab || CTAB : "sec";
  let st = "ok", note = "";
  if (CTAB !== "sec") { // the code is asked here, when the panel opens, not at sign-in
    try { st = await stepUp() } catch (e) { st = "cancel"; alert(errText(e)) }
    if (st === "cancel") { (cpReturn && cpReturn.isConnected ? cpReturn : $("#cpBtn")).focus?.(); return }
    if (st === "none") { CTAB = "sec"; note = NEED_ENROLL }
  }
  P().hidden = false; document.body.classList.add("cp-open"); window.scrollTo(0, 0);
  // a screen of its own: the address shows it, and the browser's back button / the logo return home
  if (!/[?&]panel=/.test(location.search)) history.pushState({ cp: 1 }, "", "?panel=" + CTAB);
  $("#cpBtn").setAttribute("aria-pressed", "true"); cmsg(note, note ? "err" : ""); cpDraw(true);
  $("#cpClose").focus();
}
function cpClose(fromHistory) {
  if (P().hidden) return;
  if (!fromHistory && /[?&]panel=/.test(location.search)) history.replaceState(null, "", location.pathname);
  P().hidden = true; $("#cpShade").hidden = true; document.body.classList.remove("cp-open"); $("#cpBtn").setAttribute("aria-pressed", "false");
  const d = $("#dlgNew"); if (d.open) d.close(); closeRowMenu();
  (cpReturn && cpReturn.isConnected ? cpReturn : $("#cpBtn")).focus?.();
}
$("#cpBtn").addEventListener("click", () => P().hidden ? cpOpen("users") : cpClose());
$("#cpClose").addEventListener("click", () => cpClose());
// the logo goes back to the home page (as in the deadhead dashboard), without reloading when the panel is open
document.querySelector("header.top .brand").addEventListener("click", e => { if (!P().hidden) { e.preventDefault(); cpClose() } });
window.addEventListener("popstate", () => { if (!/[?&]panel=/.test(location.search)) cpClose(true) });
$("#cpShade").addEventListener("click", () => cpClose());
$("#userMenu").addEventListener("click", e => { if (e.target.closest("[data-act=security]")) cpOpen("sec") });
document.addEventListener("keydown", e => {
  if (e.key !== "Escape" || P().hidden || $("#dlgNew").open) return;
  if (CMENU) { closeRowMenu(true); return } cpClose();
});
$("#cpTabs").addEventListener("click", e => { const b = e.target.closest("[data-tab]"); if (b) { CTAB = b.dataset.tab; cmsg(""); cpDraw() } });
$("#cpTabs").addEventListener("keydown", e => { // arrow keys move between tabs (RTL: right = previous)
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
  const tabs = [...$("#cpTabs").querySelectorAll("[data-tab]:not([hidden])")], i = tabs.indexOf(document.activeElement); if (i < 0) return;
  const n = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowLeft" ? 1 : -1) + tabs.length) % tabs.length;
  e.preventDefault(); CTAB = tabs[n].dataset.tab; cpDraw(); tabs[n].focus();
});

async function cpDraw(reload = false) {
  for (const b of $("#cpTabs").querySelectorAll("[data-tab]")) { const on = b.dataset.tab === CTAB; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1 }
  const box = $("#cpBody");
  if (CTAB === "sec") return drawSec();
  if (aal() !== "aal2") { // e.g. a tab clicked after the session dropped to aal1 (password change): ask again
    const st = await stepUp();
    if (st !== "ok") { box.innerHTML = `<p class="cp-empty">${st === "none" ? esc(NEED_ENROLL) : "צריך להקליד את קוד האימות כדי לראות את המשתמשים וההרשאות."}</p>`; return }
  }
  if (CTAB === "status") return drawStatus();
  if (reload || !CTL) {
    box.innerHTML = '<p class="cp-empty">טוען…</p>';
    try { [CTL] = await Promise.all([fnAuth({ action: "list" }), loadTiles()]) }
    catch (e) { box.innerHTML = `<p class="msg err">${esc(errText(e))}</p>`; return }
  }
  if (CTAB === "users") drawUsers(); else drawMatrix();
}

// ---------- users ----------
// last sign-in: date and time, Israel time, for every user (also disabled / two-step users)
const dtm = x => { const d = x ? new Date(x) : null; return d && !isNaN(d) ? d.toLocaleString("he-IL", { timeZone: "Asia/Jerusalem", day: "numeric", month: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "" };
const lastSeen = u => u.last_sign_in && dtm(u.last_sign_in)
  ? `<time datetime="${esc(u.last_sign_in)}" dir="ltr">${esc(dtm(u.last_sign_in))}</time>` : '<span class="muted">עוד לא נכנס</span>';
function statusOf(u) {
  if (u.disabled) return `<span class="st-off">${LOCK}מושבת</span>`;
  if (u.must_change) return '<span class="muted">צריך להחליף סיסמה</span>';
  if (u.mfa) return `<span class="st-mfa">${LOCK}אימות דו־שלבי</span>`;
  return '<span class="muted">פעיל</span>';
}
// grants of one tool: deadhead = memberships, any other tool = its own rows in u.tools
const grantsOf = (u, mod) => mod === "deadhead" ? u.memberships : (u.tools || []).filter(m => m.module === mod);
const toolName = mod => ((TILES || []).find(t => t.module === mod) || {}).title || mod;
const ROLEACT = { viewer: "צפייה", editor: "עריכה", admin: "ניהול" };
// every grant of the user: deadhead (memberships) + the other tools (tool_roles)
const allGrants = u => [...u.memberships.map(m => ({ ...m, module: "deadhead" })), ...(u.tools || [])];
// the organizations the user belongs to (operators of his grants). Name and type come from the operators table
// (operators.name, operators.org_type), set in the settings, not in code.
const orgsOf = u => [...new Set(allGrants(u).map(g => g.operator_id))];
function orgOf(u) {
  const ids = orgsOf(u);
  if (!ids.length) return '<span class="muted">—</span>';
  return ids.map(id => { const o = OPS.find(x => x.id === id);
    return `<span class="org"><span class="org-n">${esc(o ? o.name : "ארגון אחר")}</span>${o && o.org_type ? `<span class="org-t">${esc(o.org_type)}</span>` : ""}</span>` }).join("")
    + (u.other_access ? '<span class="muted small">+ ארגונים אחרים</span>' : "");
}
// access: only the tools the user can open, each with its role ("כלי התכנון · עריכה"); no organization names
function accessOf(u) {
  if (u.platform) return '<span class="chip chip-plat">מנהל מערכת</span>';
  const order = (TILES || []).map(t => t.module), seen = new Set(), c = [];
  for (const g of allGrants(u).sort((a, b) => order.indexOf(a.module) - order.indexOf(b.module) || (RANK[b.role] || 0) - (RANK[a.role] || 0))) {
    const k = g.module + "|" + g.role; if (seen.has(k)) continue; seen.add(k);
    c.push(`<span class="chip">${esc(toolName(g.module))} · ${esc(ROLEACT[g.role] || g.role)}</span>`);
  }
  return c.join("") || '<span class="muted">אין גישה</span>';
}
const shown = () => (CTL.users || []).filter(u => !CQ || (u.username + " " + (u.display_name || "")).toLowerCase().includes(CQ.toLowerCase()));
function drawUsers() {
  const rows = shown();
  $("#cpBody").innerHTML = `<div class="cp-tools">
      <label class="cp-search"><span class="sr">חיפוש משתמש</span><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5l5 5"/></svg>
        <input id="cpQ" type="search" placeholder="חיפוש משתמש" value="${esc(CQ)}" autocomplete="off"></label>
      ${PLATFORM ? '<button type="button" class="btn-blue" id="cpNew">+ משתמש חדש</button>' : ""}</div>
    ${PLATFORM ? "" : '<p class="hint">שינויים במשתמשים נעשים על ידי מנהל המערכת.</p>'}
    <div class="cp-table" role="table" aria-label="משתמשים">
      <div class="cp-tr cp-th" role="row"><span role="columnheader">שם</span><span role="columnheader">שיוך ארגוני</span><span role="columnheader">גישה</span><span role="columnheader">מצב</span><span role="columnheader">כניסה אחרונה</span><span role="columnheader"><span class="sr">פעולות</span></span></div>
      ${rows.map(u => `<div class="cp-tr" role="row" data-u="${esc(u.user_id)}">
        <span role="cell" class="cp-name"><b>${esc(u.display_name || u.username)}${u.me ? ' <span class="muted small">(אתה)</span>' : ""}</b><span dir="ltr">${esc(u.username)}</span>${u.has_email ? '<span class="cp-mail" title="יש כתובת מייל" aria-label="יש כתובת מייל">✉</span>' : ""}</span>
        <span role="cell" class="cp-org"><span class="cp-lbl">שיוך ארגוני: </span>${orgOf(u)}</span>
        <span role="cell" class="cp-acc">${accessOf(u)}</span>
        <span role="cell" class="cp-st">${statusOf(u)}</span>
        <span role="cell" class="cp-last"><span class="cp-lbl">כניסה אחרונה: </span>${lastSeen(u)}</span>
        <span role="cell" class="cp-act">${u.manageable || u.me ? `<button type="button" class="dots" data-menu aria-haspopup="true" aria-expanded="false" aria-label="פעולות על ${esc(u.username)}">⋯</button>` : ""}</span>
        <div class="cp-reset" data-resetbox hidden></div></div>`).join("") || '<p class="cp-empty">אין משתמשים שמתאימים לחיפוש</p>'}
    </div>
    <p class="hint">מי ששכח סיסמה פונה למנהל המערכת, שלוחץ "איפוס סיסמה": למשתמש עם מייל נשלחת סיסמה זמנית במייל; בלי מייל המנהל מעביר לו אותה. בכניסה הבאה הוא בוחר סיסמה חדשה.</p>`;
}
const userOf = id => CTL.users.find(u => u.user_id === id);
function closeRowMenu(focusBack) {
  if (!CMENU) return; const b = CMENU.btn; CMENU.el.remove(); b.setAttribute("aria-expanded", "false"); CMENU = null; if (focusBack) b.focus();
}
function openRowMenu(btn) {
  closeRowMenu(); const u = userOf(btn.closest("[data-u]").dataset.u);
  const items = u.manageable ? [["name", "עריכת שם"], ["reset", "איפוס סיסמה"], PLATFORM ? ["mail", "עדכון כתובת מייל"] : null, u.mfa ? ["mfar", "איפוס אימות דו־שלבי"] : null,
    PLATFORM ? ["plat", u.platform ? "הסרת מנהל מערכת" : "הפיכה למנהל מערכת"] : null,
    ["dis", u.disabled ? "הפעלה" : "השבתה"], ["del", "מחיקה"]].filter(Boolean) : [["name", "עריכת השם שלי"]];
  const el = document.createElement("div"); el.className = "rowmenu"; el.setAttribute("role", "menu");
  el.innerHTML = items.map(([k, t]) => `<button type="button" role="menuitem" data-do="${k}"${k === "del" ? ' class="danger"' : ""}>${t}</button>`).join("");
  btn.parentNode.append(el); btn.setAttribute("aria-expanded", "true"); CMENU = { el, btn }; el.querySelector("button").focus();
}
async function ctlDo(body, okText) {
  cmsg("שומר…");
  try { await fnAuth(body); CTL = await fnAuth({ action: "list" }); cpDraw(); cmsg(okText, "ok"); return true }
  catch (e) { cmsg(errText(e), "err"); return false }
}
$("#cpBody").addEventListener("input", e => {
  const t = e.target;
  if (t.id === "cpQ") { CQ = t.value; const pos = t.selectionStart; drawUsers(); const q = $("#cpQ"); q.focus(); q.setSelectionRange(pos, pos) }
  else if (t.dataset.rpw != null) pwShow(t, t.parentNode.parentNode.querySelector("[data-rpwchk]"));

});
$("#cpBody").addEventListener("click", async e => {
  const t = e.target;
  if (t.id === "cpNew") return newOpen();
  if (t.closest("[data-menu]")) { const b = t.closest("[data-menu]"); return CMENU && CMENU.btn === b ? closeRowMenu(true) : openRowMenu(b) }
  const row = t.closest("[data-u]"); if (!row) return; const u = userOf(row.dataset.u), n = u.username;
  const k = t.dataset.do; if (k) closeRowMenu();
  if (k === "reset" && u.has_email) return resetByMail(u);
  if (k === "reset") {
    const b = row.querySelector("[data-resetbox]"); b.hidden = false;
    b.innerHTML = `<label for="rpw-${esc(u.user_id)}">סיסמה זמנית ל־${esc(n)}</label><div class="copyrow"><input id="rpw-${esc(u.user_id)}" data-rpw dir="ltr" value="${suggestPw()}" autocomplete="off" aria-describedby="rpwc-${esc(u.user_id)}">
      <button type="button" class="btn-blue small" data-rsave>קביעה</button><button type="button" class="link-btn" data-rcancel>ביטול</button></div>
      <div class="msg pwchk" id="rpwc-${esc(u.user_id)}" data-rpwchk aria-live="polite"></div>`;
    const i = b.querySelector("input"); pwShow(i, b.querySelector("[data-rpwchk]")); i.focus(); i.select(); return;
  }
  if (k === "name") {
    const b = row.querySelector("[data-resetbox]"); b.hidden = false;
    b.innerHTML = `<label for="rnm-${esc(u.user_id)}">שם תצוגה ל־${esc(n)}</label><div class="copyrow"><input id="rnm-${esc(u.user_id)}" data-rnm maxlength="80" value="${esc(u.display_name || "")}" autocomplete="off">
      <button type="button" class="btn-blue small" data-nsave>שמירה</button><button type="button" class="link-btn" data-rcancel>ביטול</button></div>`;
    const i = b.querySelector("input"); i.focus(); i.select(); return;
  }
  if (k === "mail") return openMailBox(row, u);
  if (t.dataset.msave != null || t.dataset.mdel != null) return saveMail(row, u, t.dataset.mdel != null);
  if (t.dataset.nsave != null) return saveName(row, u);
  if (t.dataset.rcancel != null) { const b = row.querySelector("[data-resetbox]"); b.hidden = true; b.innerHTML = ""; row.querySelector("[data-menu]")?.focus(); return }
  if (t.dataset.rsave != null) {
    const i = row.querySelector("[data-rpw]"), pw = i.value;
    if (weakPw(pw)) { pwShow(i, row.querySelector("[data-rpwchk]")); i.focus(); return }
    if (await ctlDo({ action: "reset_password", user_id: u.user_id, password: pw }, "")) cmsg(`נקבעה סיסמה זמנית ל־${n}: ${pw} . העבר לו אותה. בכניסה הבאה הוא יבחר סיסמה חדשה.`, "ok");
    return;
  }
  if (k === "mfar") { if (confirm(`לאפס את האימות הדו־שלבי של ${n}? (למשל טלפון שאבד). בכניסה הבאה הוא יכנס בסיסמה${u.platform || u.memberships.some(m => m.role === "admin") ? " ויחויב להפעיל אימות חדש" : " בלבד"}.`)) ctlDo({ action: "reset_mfa", user_id: u.user_id }, `האימות הדו־שלבי של ${n} אופס`); return }
  if (k === "plat") { const on = !u.platform; if (confirm(on ? `להפוך את ${n} למנהל מערכת? הוא יראה וינהל הכול, בכל המפעילים.` : `להסיר מ־${n} את הרשאת מנהל המערכת?`)) ctlDo({ action: "set_platform", user_id: u.user_id, on }, on ? `${n} הוא עכשיו מנהל מערכת` : `${n} כבר לא מנהל מערכת`); return }
  if (k === "dis") { const off = !u.disabled; if (off && !confirm(`להשבית את ${n}? הוא לא יוכל להיכנס עד שיופעל שוב.`)) return; ctlDo({ action: "set_disabled", user_id: u.user_id, disabled: off }, off ? `${n} הושבת` : `${n} הופעל`); return }
  if (k === "del") { if (confirm(`למחוק את המשתמש ${n} לצמיתות? אי אפשר לבטל.`)) ctlDo({ action: "delete", user_id: u.user_id }, `${n} נמחק`); return }
});
document.addEventListener("click", e => { if (CMENU && !e.target.closest(".rowmenu,[data-menu]")) closeRowMenu() });
async function openMailBox(row, u) {
  const b = row.querySelector("[data-resetbox]"); b.hidden = false; b.innerHTML = '<p class="muted small">טוען…</p>';
  let em = "";
  try { em = (await fnAuth({ action: "get_contact_email", user_id: u.user_id })).email || "" } catch (e) { b.innerHTML = ""; b.hidden = true; cmsg(errText(e), "err"); return }
  const id = "mem-" + esc(u.user_id);
  b.innerHTML = `<label for="${id}">מייל של ${esc(u.username)}</label><div class="copyrow"><input id="${id}" data-memail type="email" dir="ltr" maxlength="254" value="${esc(em)}" autocomplete="off" data-saved="${esc(em)}">
      <button type="button" class="btn-blue small" data-msave>שמירת המייל</button>${em ? '<button type="button" class="btn-line small danger" data-mdel>הסרה</button>' : ""}<button type="button" class="link-btn" data-rcancel>ביטול</button></div>
    <p class="muted small">הזן כתובת רק אחרי שהעובד הסכים לקבל מייל ממערכת יאללה־סע. השמירה לא שולחת מייל: סיסמה חדשה נשלחת מ"איפוס סיסמה".</p>`;
  b.querySelector("input").focus();
}
async function saveMail(row, u, remove) {
  const i = row.querySelector("[data-memail]"), v = remove ? null : i.value.trim().toLowerCase();
  if (!remove && !i.checkValidity()) { cmsg(DETAILS_MSG.bad_email, "err"); i.focus(); return }
  try { await fnAuth({ action: "set_contact_email", user_id: u.user_id, email: v || null }) }
  catch (e) { cmsg(detailsErr(e), "err"); return }
  CTL = await fnAuth({ action: "list" }).catch(() => CTL); drawUsers();
  cmsg(v ? `המייל של ${u.username} נשמר` : `המייל של ${u.username} הוסר`, "ok");
}
// "איפוס סיסמה" for a user with a saved email: the address is read from the server (the one the mail really goes to)
async function resetByMail(u) {
  let em = "";
  try { em = (await fnAuth({ action: "get_contact_email", user_id: u.user_id })).email || "" } catch (e) { cmsg(errText(e), "err"); return }
  return sendDetailsTo(u, em);
}
async function sendDetailsTo(u, email) {
  if (!email) { cmsg(DETAILS_MSG.no_email, "err"); return }
  if (!confirm(`לאפס את הסיסמה של ${u.display_name || u.username}? תישלח סיסמה זמנית חדשה למייל ${email}, והסיסמה הנוכחית תפסיק לעבוד.`)) return;
  cmsg("שולח…");
  try {
    await fnAuth({ action: "send_details", user_id: u.user_id });
    CTL = await fnAuth({ action: "list" }).catch(() => CTL); drawUsers();
    cmsg(`פרטי הכניסה נשלחו ל־${email}. הסיסמה הזמנית בתוקף 7 ימים.`, "ok");
  } catch (e) { cmsg(detailsErr(e), "err") }
}
$("#cpMsg").addEventListener("click", e => {
  const b = e.target.closest("[data-sendnew]"); if (!b) return;
  sendDetailsTo({ user_id: b.dataset.sendnew, username: b.dataset.uname, display_name: b.dataset.dname }, b.dataset.email);
});
async function saveName(row, u) {
  const i = row.querySelector("[data-rnm]"), v = i.value.trim();
  if (!v) { cmsg("צריך לכתוב שם", "err"); i.focus(); return }
  if (v === (u.display_name || "")) { const b = row.querySelector("[data-resetbox]"); b.hidden = true; b.innerHTML = ""; return }
  if (await ctlDo({ action: "set_name", user_id: u.user_id, display_name: v }, `השם של ${u.username} עודכן ל־${v}`) && u.me) {
    if (PROFILE) PROFILE.display_name = v;
    $("#hello").textContent = `שלום ${v}`; $("#userName").textContent = v; $("#menuName").textContent = v;
  }
}
$("#cpBody").addEventListener("keydown", e => {
  if (e.key === "Enter" && e.target.dataset.rnm != null) { e.preventDefault(); const row = e.target.closest("[data-u]"); return saveName(row, userOf(row.dataset.u)) }
  if (e.key === "Escape" && e.target.dataset.rnm != null) { e.stopPropagation(); const b = e.target.closest("[data-resetbox]"); b.hidden = true; b.innerHTML = ""; return }
  if (!CMENU || !e.target.closest(".rowmenu")) return;
  const items = [...CMENU.el.querySelectorAll("button")], i = items.indexOf(document.activeElement);
  if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); items[(i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length].focus() }
  if (e.key === "Tab") closeRowMenu();
});

// ---------- permissions per tool ----------
function drawMatrix() {
  const AO = adminOps(), tools = (TILES || []).filter(t => t.module);
  if (CFILTER && !AO.some(o => o.id === CFILTER)) CFILTER = "";
  const opF = CFILTER ? OPS.find(o => o.id === CFILTER) : null;
  // the organization a cell edits: the filter if chosen; else the user's only organization; else (no access yet) the
  // caller's only administered organization. A user in several organizations (none today) needs the filter to edit.
  const editOp = u => opF ? opF.id : orgsOf(u).length === 1 ? orgsOf(u)[0] : !orgsOf(u).length && AO.length === 1 ? AO[0].id : "";
  const chips = ms => [...new Set(ms.map(m => m.role))].map(r => `<span class="chip">${esc(ROLEHE[r] || r)}</span>`).join("") || '<span class="muted">—</span>';
  const cell = (u, t) => {
    if (t.status !== "live") return '<span class="muted" title="הכלי עוד לא פעיל">—</span>';
    if (u.platform) return '<span class="chip chip-plat">מנהל מערכת</span>';
    const op = editOp(u), ms = grantsOf(u, t.module).filter(m => !opF || m.operator_id === opF.id);
    if (u.manageable && !op) return `<span title="משויך לכמה ארגונים: כדי לשנות, בחר ארגון בתיבת המפעיל">${chips(ms)}</span>`;
    if (!u.manageable || !AO.some(o => o.id === op)) return chips(ms);
    const cur = (ms.find(m => m.operator_id === op) || {}).role || "";
    const canAdmin = PLATFORM || cur === "admin";
    return `<select class="rsel" data-rset="${esc(u.user_id)}" data-mod="${esc(t.module)}" data-op="${esc(op)}" aria-label="הרשאה של ${esc(u.username)} ב${esc(t.title)}">
        <option value="">אין גישה</option>${ROLES.filter(r => r !== "admin" || canAdmin).map(r => `<option value="${r}"${r === cur ? " selected" : ""}>${ROLEHE[r]}</option>`).join("")}</select>`;
  };
  // the operator box only filters the rows (users who belong to that organization)
  const rowsM = (CTL.users || []).filter(u => !opF || u.platform || orgsOf(u).includes(opF.id));
  $("#cpBody").innerHTML = `<div class="cp-tools">
      <label class="pill-sel"><span>מפעיל:</span><select id="cpOp">${PLATFORM || AO.length > 1 ? `<option value="">כל המפעילים</option>` : ""}${AO.map(o => `<option value="${esc(o.id)}"${o.id === CFILTER ? " selected" : ""}>${esc(o.name)}</option>`).join("")}</select></label>
      <span class="muted small">בחר הרשאה בכל משבצת. השינוי נשמר מיד.</span></div>
    <div class="mx-wrap"><table class="mx"><thead><tr><th scope="col">שם</th>${tools.map(t => `<th scope="col">${esc(t.title)}${t.status !== "live" ? '<span class="soon">בקרוב</span>' : ""}</th>`).join("")}</tr></thead>
      <tbody>${rowsM.map(u => `<tr><th scope="row">${esc(u.display_name || u.username)}<span dir="ltr" class="muted small">${esc(u.username)}</span></th>${tools.map(t => `<td>${cell(u, t)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
    <p class="hint">צופה: רואה הכול. עורך: גם משנה הגדרות, תגבורים ומעברי לילה. מנהל: גם רואה את המשתמשים של המפעיל. מנהל מערכת: הכול, בכל המפעילים.${PLATFORM ? "" : " שינויים במשתמשים נעשים על ידי מנהל המערכת."}</p>`;
}
$("#cpBody").addEventListener("change", e => {
  const t = e.target;
  if (t.id === "cpOp") { CFILTER = t.value; drawMatrix(); $("#cpOp").focus(); return }
  if (t.dataset.rset) {
    const u = userOf(t.dataset.rset), op = t.dataset.op, n = u.username, mod = t.dataset.mod || "deadhead", tn = toolName(mod);
    // each tool keeps its own role: deadhead in memberships, other tools in tool_roles
    const rm = mod === "deadhead" ? { action: "remove_membership" } : { action: "remove_tool_role", module: mod };
    const set = mod === "deadhead" ? { action: "set_membership" } : { action: "set_tool_role", module: mod };
    if (!op) return;
    if (!t.value) { if (confirm(`להסיר את הגישה של ${n} ל${tn}?`)) ctlDo({ ...rm, user_id: u.user_id, operator_id: op }, `הגישה של ${n} ל${tn} הוסרה`); else drawMatrix(); return }
    ctlDo({ ...set, user_id: u.user_id, operator_id: op, role: t.value }, `${n} · ${tn}: ${ROLEHE[t.value]}`);
  }
});

// ---------- new user ----------
function newOpen() {
  const AO = adminOps(), d = $("#dlgNew");
  $("#nOp").innerHTML = (PLATFORM ? '<option value="platform">מנהל מערכת (כל המפעילים)</option>' : "") +
    (AO.length ? `<optgroup label="מפעיל">${AO.map(o => `<option value="${esc(o.id)}">${esc(o.name)}</option>`).join("")}</optgroup>` : "");
  if (!PLATFORM && AO[0]) $("#nOp").value = AO[0].id;
  // a role per live tool (David 2026-11-19); every tool starts at "no access", so nothing is granted by accident
  $("#nTools").innerHTML = (TILES || []).filter(t => t.module && t.status === "live").map(t => `<label class="ntool"><span>${esc(t.title)}</span>
    <select data-mod="${esc(t.module)}" aria-label="הרשאה ב${esc(t.title)}"><option value="none">אין גישה</option>${ROLES.filter(r => r !== "admin" || PLATFORM).map(r => `<option value="${r}">${ROLEHE[r]}</option>`).join("")}</select></label>`).join("");
  for (const id of ["nName", "nUser", "nPw", "nEmail"]) $("#" + id).value = "";
  mailMode();
  $("#nRoleBox").hidden = $("#nOp").value === "platform"; pwShow($("#nPw"), $("#nPwChk")); $("#nMsg").textContent = "";
  d.showModal(); $("#nOp").focus();
}
$("#nOp").addEventListener("change", e => { $("#nRoleBox").hidden = e.target.value === "platform" });
$("#nPw").addEventListener("input", e => pwShow(e.target, $("#nPwChk")));
// a valid email: the server picks the temporary password and mails it, so the password box goes away
const mailOk = () => { const i = $("#nEmail"), v = i.value.trim(); return !!v && i.checkValidity() && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) }; // same rule as the server
function mailMode() { const on = mailOk(); $("#nPwBox").hidden = on; $("#nMailNote").hidden = !on }
$("#nEmail").addEventListener("input", mailMode);
$("#nGen").addEventListener("click", () => { $("#nPw").value = suggestPw(); pwShow($("#nPw"), $("#nPwChk")) });
$("#nCancel").addEventListener("click", () => $("#dlgNew").close());
$("#nUser").addEventListener("focusout", e => { e.target.value = e.target.value.trim().toLowerCase() });
$("#newForm").addEventListener("submit", async e => {
  e.preventDefault(); const m = $("#nMsg"), user = $("#nUser").value.trim().toLowerCase(), pw = $("#nPw").value, op = $("#nOp").value;
  if (!USERRE.test(user)) { m.className = "msg err"; m.textContent = ERR.bad_username; $("#nUser").focus(); return }
  const picks = [...$("#nTools").querySelectorAll("select[data-mod]")].map(s => ({ module: s.dataset.mod, role: s.value }));
  const dh = (picks.find(x => x.module === "deadhead") || { role: "none" }).role, tools = picks.filter(x => x.module !== "deadhead" && x.role !== "none");
  const role = op === "platform" ? "platform" : dh, email = $("#nEmail").value.trim().toLowerCase();
  const noAccess = op !== "platform" && dh === "none" && !tools.length
    ? ` שים לב: למשתמש ${user} אין גישה לאף כלי. אפשר לקבוע בלשונית "הרשאות לפי כלי".` : "";
  if (email && !mailOk()) { m.className = "msg err"; m.textContent = DETAILS_MSG.bad_email; $("#nEmail").focus(); return }
  if (!email && weakPw(pw)) { pwShow($("#nPw"), $("#nPwChk")); m.className = "msg err"; m.textContent = ERR.weak_password; $("#nPw").focus(); return }
  m.className = "msg"; m.textContent = "יוצר…"; $("#nSave").disabled = true;
  try {
    const name = $("#nName").value.trim();
    // with an email the password typed here is never used: send_details replaces it and mails a fresh one
    const r = await fnAuth({ action: "create", username: user, display_name: name, ...(role === "platform" ? {} : { operator_id: op, tools }), role,
      password: email ? suggestPw() : pw, ...(email ? { email } : {}) });
    $("#dlgNew").close(); CTAB = "users"; await cpDraw(true);
    if (!email) { cmsg(`נוצר המשתמש ${user} עם הסיסמה הזמנית ${pw} . העבר לו את שניהם. בכניסה הראשונה הוא יבחר סיסמה חדשה.${noAccess}`, "ok"); return }
    cmsg("נוצר המשתמש. שולח מייל…");
    try {
      await fnAuth({ action: "send_details", user_id: r.user_id });
      CTL = await fnAuth({ action: "list" }).catch(() => CTL); drawUsers();
      cmsg(`נוצר המשתמש ${user} ונשלח אליו מייל עם פרטי הכניסה ל־${email}.${noAccess}`, "ok");
    } catch (se) {
      cmsg(`נוצר המשתמש ${user}, אבל המייל לא נשלח: ${detailsErr(se)} אפשר לשלוח שוב מתפריט ⋯ ← מייל ושליחת פרטים.`, "err");
    }
  } catch (err) { m.className = "msg err"; m.textContent = errText(err) } finally { $("#nSave").disabled = false }
});

// ---------- my security ----------
const smsg = (id, t, cls = "") => { const m = $("#" + id); if (m) { m.className = "msg " + cls; m.textContent = t } };
const pwIn = (id, label, ac) => `<div class="field"><label for="${id}">${label}</label><input id="${id}" type="password" autocomplete="${ac}" dir="ltr"></div>`;
const myFactors = async () => ((await authReq("GET", "user")).factors || []).filter(f => f.factor_type === "totp");
async function mfaEnroll() { // a fresh factor (unfinished ones are removed first): {id, totp:{qr_code, secret}}
  for (const f of (await myFactors()).filter(f => f.status !== "verified")) try { await authReq("DELETE", `factors/${f.id}`) } catch { }
  return authReq("POST", "factors", { factor_type: "totp", friendly_name: "yalla-sa " + new Date().toISOString().slice(0, 16) });
}
const qrSrc = q => String(q).startsWith("data:") ? q : "data:image/svg+xml;charset=utf-8," + encodeURIComponent(q); // GoTrue returns raw SVG
let SEC = null, ENRL = null, CODES = null;
async function drawSec() {
  const box = $("#cpBody"); box.innerHTML = '<p class="cp-empty">טוען…</p>';
  // recovery settings (platform admins) are sensitive: shown only in an aal2 session (manage_users enforces it too)
  try {
    SEC = { on: (await myFactors()).some(f => f.status === "verified"), rec: PLATFORM ? (aal() === "aal2" ? await fnAuth({ action: "my_security" }) : { locked: true }) : null };
    await loadDevices();
  }
  catch (e) { box.innerHTML = `<p class="msg err">${esc(errText(e))}</p>`; return }
  secRender();
}
function secRender() {
  const r = SEC.rec, uname = (PROFILE && PROFILE.username) || "";
  $("#cpBody").innerHTML = `<section class="sec" aria-labelledby="sPwH"><h3 id="sPwH">שינוי סיסמה</h3>
      <form id="sPwForm" autocomplete="on"><input type="text" autocomplete="username" value="${esc(uname)}" hidden>
        ${pwIn("sPw0", "הסיסמה הנוכחית", "current-password")}${pwIn("sPw1", "סיסמה חדשה", "new-password")}
        <div class="msg pwchk muted" id="sPwChk" aria-live="polite">לפחות 8 תווים, עם אותיות באנגלית ומספרים</div>
        ${pwIn("sPw2", "אימות הסיסמה החדשה", "new-password")}
        <button class="btn-blue">שמירת הסיסמה</button> <span class="msg" id="sPwMsg" aria-live="polite"></span></form></section>
    <section class="sec" aria-labelledby="sMfaH"><h3 id="sMfaH">אימות דו־שלבי</h3><div id="sMfa">${mfaHtml()}</div></section>
    <section class="sec" aria-labelledby="sTrH"><h3 id="sTrH">מכשירים אישיים</h3><div id="sTr">${trustHtml()}</div></section>
    ${PLATFORM ? `<section class="sec" aria-labelledby="sAllH"><h3 id="sAllH">מכשירים אישיים של כל המשתמשים (מנהל מערכת)</h3><div id="sAll">${allDevHtml()}</div></section>` : ""}
    ${r ? `<section class="sec" aria-labelledby="sRecH"><h3 id="sRecH">שחזור חשבון (מנהל מערכת)</h3><div id="sRec">${recHtml()}</div></section>` : ""}`;
}
function mfaHtml() {
  if (ENRL) return `<form id="sMfaForm"><p>סרוק את הקוד באפליקציית אימות (Google Authenticator, Microsoft Authenticator וכדומה), והקלד את הקוד שהיא מציגה.</p>
      <img class="qr" src="${esc(qrSrc(ENRL.totp.qr_code))}" alt="קוד QR לאפליקציית האימות" width="180" height="180">
      <p class="hint">אין אפשרות לסרוק? הקלד באפליקציה את המפתח: <b dir="ltr" class="mono">${esc(ENRL.totp.secret)}</b></p>
      <div class="field"><label for="sOtp">קוד בן 6 ספרות</label><input id="sOtp" inputmode="numeric" autocomplete="one-time-code" maxlength="7" dir="ltr"></div>
      <button class="btn-blue">הפעלה</button> <span class="msg" id="sMfaMsg" aria-live="polite"></span></form>`;
  return SEC.on ? `<p><b>פעיל.</b> הכניסה היא בסיסמה בלבד. את הקוד מאפליקציית האימות מקלידים כשפותחים את פאנל הבקרה ולפעולות רגישות.</p>
      ${isAdminAny() ? '<p class="hint">למנהלים זו חובה: בלי אימות דו־שלבי אי אפשר לנהל משתמשים והרשאות.</p>' : ""}
      <button type="button" class="btn-line danger" id="sMfaOff">הסרת האימות הדו־שלבי</button> <span class="msg" id="sMfaMsg" aria-live="polite"></span>`
    : `<p>לא פעיל. עם אימות דו־שלבי, מי שגילה את הסיסמה שלך עדיין לא יכול להיכנס בלי הטלפון שלך.</p>
      <button type="button" class="btn-blue" id="sMfaOn">הפעלה</button> <span class="msg" id="sMfaMsg" aria-live="polite"></span>`;
}
const whenHe = t => new Date(t).toLocaleString("he-IL", { day: "numeric", month: "numeric", hour: "2-digit", minute: "2-digit" });
// personal devices: one Auth session each, recorded on the server (manage_users: trust_device / my_devices / revoke_device).
// Disconnect deletes the session on the server: that device's next request is refused (RLS + GoTrue).
function uaName(ua) {
  ua = String(ua || "");
  const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /CriOS|Chrome\//.test(ua) ? "Chrome"
    : /FxiOS|Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "דפדפן לא מזוהה";
  const o = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad|iPod/.test(ua) ? "iOS" : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "מערכת לא מזוהה";
  return `${b} · ${o}`;
}
async function loadDevices() {
  try { SEC.devs = (await fnAuth({ action: "my_devices" })).devices || [] } catch (e) { SEC.devs = null; SEC.devErr = errText(e) }
  if (SEC.devs) { const cur = SEC.devs.find(d => d.current); lsSet(TRUST, cur ? String(Date.parse(cur.expires_at)) : null) } // the server decides
  SEC.all = PLATFORM && aal() === "aal2" ? await fnAuth({ action: "all_devices" }).then(r => r.devices || [], () => null) : null;
}
const devRows = (list, withUser) => `<div class="dev-list" role="list">${list.map(d => `<div class="dev" role="listitem" data-sid="${esc(d.session_id)}">
    <div class="dev-main"><b>${esc(uaName(d.user_agent))}</b>${d.current ? ' <span class="chip chip-plat">המכשיר הזה</span>' : ""}
      ${withUser ? `<span class="dev-user">${esc(d.display_name || d.username || "")} <span dir="ltr" class="muted">${esc(d.username || "")}</span></span>` : ""}
      <span class="dev-meta">סומן ${esc(whenHe(d.marked_at))} · שימוש אחרון ${esc(whenHe(d.last_used))} · בתוקף עד ${esc(whenHe(d.expires_at))}</span></div>
    <button type="button" class="btn-line small danger" data-revoke="${esc(d.session_id)}" data-who="${esc(withUser ? d.username || "" : "")}" data-cur="${d.current ? 1 : ""}">${d.current ? "ניתוק המכשיר הזה" : "ניתוק"}</button></div>`).join("")}</div>`;
function trustHtml() {
  const t = trustUntil();
  const head = t ? `<p><b>המכשיר הזה מסומן כאישי</b> עד ${esc(whenHe(t))}. עד אז החשבון נשאר מחובר גם בלי פעילות (במקום ניתוק אחרי ${IDLE_MIN} דקות).</p>
      <button type="button" class="btn-line" id="sTrustOff">ביטול סימון המכשיר</button>`
    : `<p>המכשיר הזה לא מסומן כאישי: אחרי ${IDLE_MIN} דקות בלי פעילות החשבון מתנתק.</p>
      <p class="hint">רק במכשיר אישי עם נעילת מסך. במחשב משותף לא לסמן.</p>
      <button type="button" class="btn-line" id="sTrustOn">סימון כמכשיר אישי ל־${trustLabel()}</button>`;
  const others = SEC.devs == null ? `<p class="msg err">${esc(SEC.devErr || "")}</p>`
    : SEC.devs.length ? `<h4>המכשירים האישיים שלך</h4><p class="hint">ניתוק מנתק את המכשיר מיד, גם בשרת: בפעם הבאה שהוא פונה לשרת הוא יתבקש להיכנס מחדש.</p>${devRows(SEC.devs, false)}`
    : '<p class="hint">אין לך מכשירים מסומנים כאישיים.</p>';
  return `${head} <span class="msg" id="sTrMsg" aria-live="polite"></span>${others}`;
}
function allDevHtml() {
  if (SEC.all == null) return aal() === "aal2" ? '<p class="msg err">לא ניתן לטעון את הרשימה</p>'
    : SEC.on ? '<p class="hint">כדי לראות ולנתק מכשירים של משתמשים אחרים צריך להקליד קוד אימות.</p><button type="button" class="btn-line" id="sAllUnlock">הקלדת קוד</button> <span class="msg" id="sAllMsg" aria-live="polite"></span>'
    : '<p class="hint">קודם צריך להפעיל אימות דו־שלבי (למעלה).</p>';
  return (SEC.all.length ? devRows(SEC.all, true) : '<p class="hint">אין מכשירים מסומנים.</p>') + ' <span class="msg" id="sAllMsg" aria-live="polite"></span>';
}
function recHtml() {
  const r = SEC.rec;
  if (r.locked) return SEC.on ? `<p class="hint">ההגדרות האלה רגישות: כדי לראות ולשנות אותן צריך להקליד קוד אימות.</p>
      <button type="button" class="btn-line" id="sRecUnlock">הקלדת קוד</button> <span class="msg" id="sRecMsg" aria-live="polite"></span>`
    : '<p class="hint">ההגדרות האלה רגישות: קודם צריך להפעיל אימות דו־שלבי (למעלה).</p>';
  if (CODES) return `<p><b>קודי השחזור החדשים שלך.</b> הם מוצגים עכשיו פעם אחת בלבד. שמור אותם במקום בטוח, לא באותו מחשב שבו אתה נכנס. כל קוד עובד פעם אחת, והקודים הקודמים כבר לא עובדים.</p>
      <div class="codes">${CODES.map(c => `<span dir="ltr">${esc(c)}</span>`).join("")}</div>
      <button type="button" class="btn-line" id="sDl">הורדה כקובץ</button> <button type="button" class="btn-blue" id="sDone">שמרתי אותם</button>`;
  return `<p class="hint">אם תשכח את הסיסמה ואין מנהל מערכת אחר שיקבע לך סיסמה זמנית, אלה שתי הדרכים לחזור לחשבון.</p>
    <h4>מייל לשחזור</h4>
    <p class="hint">${r.recovery_email ? `מוגדר: <b dir="ltr">${esc(r.recovery_email)}</b>.` : "לא מוגדר."}</p>
    <div class="field"><label for="sEm">כתובת מייל</label><input id="sEm" type="email" dir="ltr" value="${esc(r.recovery_email || "")}"></div>
    <button type="button" class="btn-line" id="sEmSave">שמירת המייל</button>${r.recovery_email ? ' <button type="button" class="btn-line danger" id="sEmDel">הסרה</button>' : ""}
    <h4>קודי שחזור חד־פעמיים</h4>
    <p class="hint">${r.codes_left ? `נותרו ${r.codes_left} קודים שלא נוצלו.` : "עוד אין קודים."} יצירה מחדש מבטלת את הקודים הקודמים.</p>
    <button type="button" class="btn-line" id="sGen">${r.codes_left ? "יצירת קודים חדשים" : "יצירת 8 קודים"}</button>
    ${pwIn("sSecPw", "הסיסמה הנוכחית שלך (נדרשת לשמירת מייל או ליצירת קודים)", "current-password")}
    <span class="msg" id="sRecMsg" aria-live="polite"></span>`;
}
$("#cpBody").addEventListener("submit", async e => {
  e.preventDefault();
  if (e.target.id === "sPwForm") {
    const cur = $("#sPw0").value, pw = $("#sPw1").value;
    if (weakPw(pw)) { pwShow($("#sPw1"), $("#sPwChk")); $("#sPw1").focus(); return }
    if (pw !== $("#sPw2").value) return smsg("sPwMsg", "הסיסמאות לא זהות", "err");
    smsg("sPwMsg", "שומר…");
    try {
      await fnAuth({ action: "change_password", current_password: cur, new_password: pw });
      try { await signIn(PROFILE?.username || lsGet("ys_user") || "", pw) } catch { } // a password change may end the old session
      for (const i of ["sPw0", "sPw1", "sPw2"]) $("#" + i).value = ""; smsg("sPwMsg", "הסיסמה הוחלפה", "ok");
    } catch (err) { smsg("sPwMsg", errText(err), "err") }
  }
  if (e.target.id === "sMfaForm") {
    smsg("sMfaMsg", "בודק…");
    try {
      await mfaVerify(ENRL.id, $("#sOtp").value); ENRL = null; SEC.on = true; $("#sMfa").innerHTML = mfaHtml(); smsg("sMfaMsg", "האימות הדו־שלבי הופעל", "ok");
      if (canManage()) cmsg("האימות הדו־שלבי הופעל. עכשיו אפשר לנהל משתמשים והרשאות.", "ok");
      if (PLATFORM) { try { SEC.rec = await fnAuth({ action: "my_security" }) } catch { } $("#sRec").innerHTML = recHtml() }
    }
    catch (err) { smsg("sMfaMsg", errText(err), "err") }
  }
});
$("#cpBody").addEventListener("input", e => { if (e.target.id === "sPw1") pwShow(e.target, $("#sPwChk")) });
$("#cpBody").addEventListener("click", async e => {
  const id = e.target.id;
  if (id === "sMfaOn") { smsg("sMfaMsg", "מכין קוד…"); try { ENRL = await mfaEnroll(); $("#sMfa").innerHTML = mfaHtml(); $("#sOtp").focus() } catch (err) { smsg("sMfaMsg", errText(err), "err") } return }
  if (id === "sMfaOff") {
    if (!confirm("להסיר את האימות הדו־שלבי? מכאן הכניסה תהיה בסיסמה בלבד.")) return; smsg("sMfaMsg", "מסיר…");
    try { await fnAuth({ action: "remove_my_mfa" }); try { await refresh() } catch { } SEC.on = false; $("#sMfa").innerHTML = mfaHtml(); smsg("sMfaMsg", "הוסר", "ok") } catch (err) { smsg("sMfaMsg", errText(err), "err") }
    return;
  }
  if (id === "sDl" && CODES) {
    const t = `יאללה־סע · קודי שחזור לחשבון ${PROFILE?.username || ""}\nנוצרו ${new Date().toLocaleString("he-IL")}. כל קוד עובד פעם אחת.\n\n${CODES.join("\n")}\n`;
    const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([t], { type: "text/plain;charset=utf-8" })); a.download = "yalla-sa-recovery-codes.txt"; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000); return;
  }
  if (id === "sDone") { CODES = null; drawSec(); return }
  if (id === "sRecUnlock") {
    try { if (await stepUp() !== "ok") return; SEC.rec = await fnAuth({ action: "my_security" }); $("#sRec").innerHTML = recHtml() } catch (err) { smsg("sRecMsg", errText(err), "err") }
    return;
  }
  if (id === "sTrustOff" || id === "sTrustOn") {
    smsg("sTrMsg", "שומר…");
    try {
      if (id === "sTrustOn") { const r = await fnAuth({ action: "trust_device", hours: TRUST_H }); lsSet(TRUST, String(Date.parse(r.expires_at))) }
      else { await fnAuth({ action: "untrust_device" }); lsSet(TRUST, null) }
      await loadDevices(); $("#sTr").innerHTML = trustHtml(); if ($("#sAll")) $("#sAll").innerHTML = allDevHtml();
      smsg("sTrMsg", id === "sTrustOn" ? `המכשיר סומן כאישי ל־${trustLabel()}` : `הסימון בוטל. מעכשיו ניתוק אחרי ${IDLE_MIN} דקות בלי פעילות`, "ok");
      $(id === "sTrustOn" ? "#sTrustOff" : "#sTrustOn")?.focus();
    } catch (err) { smsg("sTrMsg", errText(err), "err") }
    return;
  }
  if (id === "sAllUnlock") {
    try { if (await stepUp() !== "ok") return; await loadDevices(); $("#sAll").innerHTML = allDevHtml() } catch (err) { smsg("sAllMsg", errText(err), "err") }
    return;
  }
  const rv = e.target.closest("[data-revoke]");
  if (rv) {
    const cur = !!rv.dataset.cur, who = rv.dataset.who, box = rv.closest("#sAll") ? "sAllMsg" : "sTrMsg";
    if (!confirm(cur ? "לנתק את המכשיר הזה? תצטרך להיכנס מחדש." : `לנתק את המכשיר${who ? " של " + who : ""}? הוא יתבקש להיכנס מחדש בפעם הבאה שהוא פונה לשרת.`)) return;
    smsg(box, "מנתק…");
    try {
      await fnAuth({ action: "revoke_device", session_id: rv.dataset.revoke });
      if (cur) { setSes(null); lsSet(TRUST, null); location.replace("/"); return }
      await loadDevices(); $("#sTr").innerHTML = trustHtml(); if ($("#sAll")) $("#sAll").innerHTML = allDevHtml();
      smsg(box, "המכשיר נותק", "ok");
    } catch (err) { smsg(box, errText(err), "err") }
    return;
  }
  if (!["sEmSave", "sEmDel", "sGen"].includes(id)) return;
  const pw = $("#sSecPw").value; if (!pw) { smsg("sRecMsg", "צריך להקליד את הסיסמה הנוכחית", "err"); $("#sSecPw").focus(); return }
  smsg("sRecMsg", "שומר…");
  try {
    if (id === "sGen") { CODES = (await fnAuth({ action: "gen_recovery_codes", current_password: pw })).codes; $("#sRec").innerHTML = recHtml(); return }
    await fnAuth({ action: "set_recovery_email", current_password: pw, email: id === "sEmDel" ? null : $("#sEm").value.trim() });
    SEC.rec = await fnAuth({ action: "my_security" }); $("#sRec").innerHTML = recHtml(); smsg("sRecMsg", id === "sEmDel" ? "המייל הוסר" : "המייל נשמר", "ok");
  } catch (err) { smsg("sRecMsg", errText(err), "err") }
});

// ---------- platform status (spec 2026-11-19-platform-status-design.md §6) ----------
// read-only view of the hourly check (public.platform_status(): platform admin + aal2). Colors always come with a word.
const ST_WORD = { ok: "תקין", warn: "אזהרה", bad: "בעיה", unknown: "לא נבדק", manual: "בדיקה ידנית" };
const ST_GRP = [["cost", "עולה כסף"], ["free", "מכסות חינם"], ["runs", "ריצות ותקינות"], ["manual", "בדיקה ידנית"]];
const ST_CH = { email: "מייל", whatsapp: "וואטסאפ", off: "כבוי" };
const stRpc = (fn, args = {}) => sb("/rest/v1/rpc/" + fn, { method: "POST", body: JSON.stringify(args) });
const hm = x => { const d = x ? new Date(x) : null; return d && !isNaN(d) ? d.toLocaleTimeString("he-IL", { timeZone: "Asia/Jerusalem", hour: "2-digit", minute: "2-digit" }) : "" };
function stRow(i) {
  const pct = i.cap > 0 && i.value != null ? Math.min(100, Math.round(i.value / i.cap * 100)) : null;
  const lvl = i.level === "manual" ? "manual" : i.level;
  return `<div class="st-row" data-key="${esc(i.key)}" data-level="${esc(lvl)}">
    <span class="st-dot st-${esc(lvl)}" aria-hidden="true"></span>
    <div class="st-name"><b>${esc(i.title)}</b><span class="sr"> – ${esc(ST_WORD[lvl] || lvl)}</span><span class="muted small">${esc(i.explain)}</span></div>
    <div class="st-read${lvl === "bad" ? " st-badtxt" : ""}">${esc(i.reading)}${i.note ? `<span class="st-note">${esc(i.note)}</span>` : ""}</div>
    <div class="st-side">${pct != null && i.grp !== "manual" ? `<span class="st-bar" role="meter" aria-label="${esc(i.title)}" aria-valuemin="0" aria-valuemax="${esc(i.cap)}" aria-valuenow="${esc(i.value)}"><span class="st-${esc(lvl)}" data-pct="${pct}"></span></span>` : ""}
      ${i.link ? `<a class="st-link" href="${esc(i.link)}" target="_blank" rel="noopener">${i.grp === "manual" ? "ללוח של הספק" : "פתיחה ב־GitHub"}</a>` : ""}
      ${i.grp === "manual" ? '<button type="button" class="btn-line small st-mark">בדקתי עכשיו</button>' : ""}</div>
  </div>`;
}
// the session may drop to aal1 while the tab is open (e.g. another tab signed in): go back through cpDraw, which asks for the code
const stForbidden = e => e && (e.status === 403 || /forbidden|42501/.test(e.message || ""));
let ST_LOAD = 0; // a newer load (or another tab) makes an older response stale
async function drawStatus() {
  if (CTAB !== "status") return;
  if (aal() !== "aal2") return cpDraw();
  const box = $("#cpBody"), my = ++ST_LOAD, live = () => my === ST_LOAD && CTAB === "status";
  box.innerHTML = '<p class="cp-empty">טוען…</p>';
  let S;
  try { S = await stRpc("platform_status") }
  catch (e) {
    if (!live()) return;
    if (stForbidden(e)) { if (aal() !== "aal2") return cpDraw(); box.innerHTML = '<p class="cp-empty">רק מנהל מערכת עם קוד אימות רואה את לוח המדדים.</p>'; return }
    box.innerHTML = `<div class="cp-empty"><p class="msg err">לא ניתן לטעון את לוח המדדים</p><button type="button" class="btn-line small st-retry">נסה שוב</button></div>`; return;
  }
  if (!live()) return;
  const items = S.items || [];
  if (!items.length) { box.innerHTML = '<p class="cp-empty">עוד לא נבדק. הבדיקה הראשונה תרוץ בשעה הקרובה.</p>'; return }
  const attn = items.filter(i => i.level === "bad" || i.level === "warn"), red = attn.some(i => i.level === "bad");
  const head = !attn.length ? "הכול תקין" : attn.length === 1 ? "דבר אחד דורש תשומת לב" : `${attn.length} דברים דורשים תשומת לב`;
  box.innerHTML = `<div class="st-sum st-sum-${attn.length ? (red ? "bad" : "warn") : "ok"}">
      <span class="st-dot st-${attn.length ? (red ? "bad" : "warn") : "ok"}" aria-hidden="true"></span>
      <div><b>${head}</b><span class="muted small">נבדק לאחרונה ${esc(hm(S.checked_at))} · נבדק כל שעה</span></div>
      <button type="button" class="btn-line small st-now">בדיקה עכשיו</button></div>
    ${ST_GRP.map(([g, t]) => { const rows = items.filter(i => i.grp === g); return rows.length ? `<section class="st-grp"><h3>${t}</h3><div class="st-card">${rows.map(stRow).join("")}</div></section>` : "" }).join("")}
    <p class="st-foot muted small">${S.alert_channel === "off" ? "התראות כבויות: לא הוגדרו כתובות מייל" : `התראות במייל${S.alert_count ? ` ל־${esc(S.alert_count)} כתובות` : ""}: אדום – מיד · צהוב – סיכום ב־08:00`}</p>`;
  // bar widths through the CSSOM: the site's CSP (style-src 'self') blocks inline style attributes
  for (const f of box.querySelectorAll(".st-bar [data-pct]")) f.style.width = f.dataset.pct + "%";
}
$("#cpBody").addEventListener("click", async e => {
  if (CTAB !== "status") return;
  if (e.target.closest(".st-retry")) return drawStatus();
  const now = e.target.closest(".st-now"), mark = e.target.closest(".st-mark");
  if (!now && !mark) return;
  if (aal() !== "aal2") return cpDraw();
  const b = now || mark; b.disabled = true;
  try {
    if (now) {
      if (await stRpc("platform_status_refresh") === "too_soon") { cmsg("אפשר לבדוק שוב בעוד דקה–שתיים"); b.disabled = false; return }
      cmsg("הבדיקה רצה…"); await new Promise(r => setTimeout(r, 8000));
      if (CTAB !== "status") return; // the user moved to another tab meanwhile: leave it alone
      cmsg(""); return drawStatus();
    }
    await stRpc("platform_status_mark", { p_key: mark.closest(".st-row").dataset.key }); return drawStatus();
  } catch (err) {
    b.disabled = false;
    if (stForbidden(err)) return cpDraw();
    cmsg(errText(err), "err");
  }
});
