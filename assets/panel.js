// yalla-sa control panel (פאנל בקרה), moved here from the deadhead tool's "חדר בקרה · משתמשים והרשאות".
// Tabs: users, permissions per tool, my security. Every write goes through the manage_users Edge Function, which
// checks the caller again (platform admin: everyone; operator admin: viewers/editors of his operators; MFA aal2).
// RLS in the database stays the real enforcement: this screen only shows and asks.
// Per tool: today only the deadhead tool is live, and its role per operator is the membership (memberships.role).
// Tools marked "soon" get their own column of roles with the identity migration (docs/identity-migration.sql).
"use strict";
Object.assign(ERR, {
  "row-level security": "אין לך הרשאה לשנות את זה", not_allowed: "אין לך הרשאה לפעולה הזו", "42501": "אין לך הרשאה לשנות את זה",
  weak_password: "הסיסמה צריכה להיות לפחות 8 תווים, עם אותיות ומספרים", "Password should be": "הסיסמה צריכה להיות לפחות 8 תווים, עם אותיות ומספרים",
  same_password: "הסיסמה החדשה זהה לישנה", wrong_password: "הסיסמה הנוכחית שגויה",
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
const LOCK = '<svg class="lk" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/></svg>';

let CTL = null, CTAB = "users", CFILTER = "", CQ = "", CMENU = null;
const P = () => $("#cp");
const cmsg = (t, cls = "") => { const m = $("#cpMsg"); m.className = "msg " + cls; m.textContent = t; if (t) m.scrollIntoView({ block: "nearest" }) };

// ---------- open / close ----------
function cpSetup() { // called after the portal opens (portal.js showPortal)
  $("#cpBtn").hidden = !canManage();
  for (const t of ["users", "matrix"]) $(`#cpTabs [data-tab="${t}"]`).hidden = !canManage();
  // a tool's "users and permissions" link lands here with ?panel=users|matrix|sec
  const q = new URL(location.href), want = q.searchParams.get("panel");
  if (want) { q.searchParams.delete("panel"); history.replaceState(null, "", q.pathname + q.search); if (["users", "matrix", "sec"].includes(want)) cpOpen(want) }
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
  P().hidden = false; $("#cpShade").hidden = false; document.body.classList.add("cp-open");
  $("#cpBtn").setAttribute("aria-pressed", "true"); cmsg(note, note ? "err" : ""); cpDraw(true);
  $("#cpClose").focus();
}
function cpClose() {
  P().hidden = true; $("#cpShade").hidden = true; document.body.classList.remove("cp-open"); $("#cpBtn").setAttribute("aria-pressed", "false");
  const d = $("#dlgNew"); if (d.open) d.close(); closeRowMenu();
  (cpReturn && cpReturn.isConnected ? cpReturn : $("#cpBtn")).focus?.();
}
$("#cpBtn").addEventListener("click", () => P().hidden ? cpOpen("users") : cpClose());
$("#cpClose").addEventListener("click", cpClose);
$("#cpShade").addEventListener("click", cpClose);
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
  if (reload || !CTL) {
    box.innerHTML = '<p class="cp-empty">טוען…</p>';
    try { [CTL] = await Promise.all([fnAuth({ action: "list" }), loadTiles()]) }
    catch (e) { box.innerHTML = `<p class="msg err">${esc(errText(e))}</p>`; return }
  }
  if (CTAB === "users") drawUsers(); else drawMatrix();
}

// ---------- users ----------
const dt = x => x ? new Date(x).toLocaleDateString("he-IL", { day: "numeric", month: "numeric" }) : "";
function statusOf(u) {
  if (u.disabled) return `<span class="st-off">${LOCK}מושבת</span>`;
  if (u.must_change) return '<span class="muted">צריך להחליף סיסמה</span>';
  if (u.mfa) return `<span class="st-mfa">${LOCK}אימות דו־שלבי</span>`;
  return u.last_sign_in ? `<span class="muted">נכנס לאחרונה ${dt(u.last_sign_in)}</span>` : '<span class="muted">עוד לא נכנס</span>';
}
function accessOf(u) {
  if (u.platform) return '<span class="chip chip-plat">מנהל מערכת</span>';
  const c = u.memberships.map(m => `<span class="chip">${esc(opName(m.operator_id))} · ${esc(ROLEHE[m.role] || m.role)}</span>`).join("");
  return (c || '<span class="muted">אין גישה</span>') + (u.other_access ? '<span class="muted small">+ מפעילים אחרים</span>' : "");
}
const shown = () => (CTL.users || []).filter(u => !CQ || (u.username + " " + (u.display_name || "")).toLowerCase().includes(CQ.toLowerCase()));
function drawUsers() {
  const rows = shown();
  $("#cpBody").innerHTML = `<div class="cp-tools">
      <label class="cp-search"><span class="sr">חיפוש משתמש</span><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5l5 5"/></svg>
        <input id="cpQ" type="search" placeholder="חיפוש משתמש" value="${esc(CQ)}" autocomplete="off"></label>
      <button type="button" class="btn-blue" id="cpNew">+ משתמש חדש</button></div>
    <div class="cp-table" role="table" aria-label="משתמשים">
      <div class="cp-tr cp-th" role="row"><span role="columnheader">שם</span><span role="columnheader">גישה</span><span role="columnheader">מצב</span><span role="columnheader"><span class="sr">פעולות</span></span></div>
      ${rows.map(u => `<div class="cp-tr" role="row" data-u="${esc(u.user_id)}">
        <span role="cell" class="cp-name"><b>${esc(u.display_name || u.username)}${u.me ? ' <span class="muted small">(אתה)</span>' : ""}</b><span dir="ltr">${esc(u.username)}</span></span>
        <span role="cell" class="cp-acc">${accessOf(u)}</span>
        <span role="cell" class="cp-st">${statusOf(u)}</span>
        <span role="cell" class="cp-act">${u.manageable || u.me ? `<button type="button" class="dots" data-menu aria-haspopup="true" aria-expanded="false" aria-label="פעולות על ${esc(u.username)}">⋯</button>` : ""}</span>
        <div class="cp-reset" data-resetbox hidden></div></div>`).join("") || '<p class="cp-empty">אין משתמשים שמתאימים לחיפוש</p>'}
    </div>
    <p class="hint">אין שחזור סיסמה עצמי: מי ששכח סיסמה פונה למנהל, והמנהל קובע לו סיסמה זמנית. בכניסה הבאה הוא בוחר סיסמה חדשה.</p>`;
}
const userOf = id => CTL.users.find(u => u.user_id === id);
function closeRowMenu(focusBack) {
  if (!CMENU) return; const b = CMENU.btn; CMENU.el.remove(); b.setAttribute("aria-expanded", "false"); CMENU = null; if (focusBack) b.focus();
}
function openRowMenu(btn) {
  closeRowMenu(); const u = userOf(btn.closest("[data-u]").dataset.u);
  const items = u.manageable ? [["name", "עריכת שם"], ["reset", "סיסמה זמנית"], u.mfa ? ["mfar", "איפוס אימות דו־שלבי"] : null,
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
  const cell = (u, t) => {
    if (t.status !== "live") return '<span class="muted" title="הכלי עוד לא פעיל">—</span>';
    if (u.platform) return '<span class="chip chip-plat">מנהל מערכת</span><span class="opl">כל המפעילים</span>';
    const ms = u.memberships.filter(m => !opF || m.operator_id === opF.id);
    if (!opF) return ms.map(m => `<span class="chip">${esc(ROLEHE[m.role])}</span><span class="opl">${esc(opName(m.operator_id))}</span>`).join("") || '<span class="muted">—</span>';
    const cur = ms[0]?.role || "";
    const canAdmin = PLATFORM || cur === "admin";
    if (!u.manageable) return cur ? `<span class="chip">${esc(ROLEHE[cur])}</span><span class="opl">${esc(opF.name)}</span>` : '<span class="muted">—</span>';
    return `<select class="rsel" data-rset="${esc(u.user_id)}" aria-label="הרשאה של ${esc(u.username)} ב${esc(t.title)}, ${esc(opF.name)}">
        <option value="">אין גישה</option>${ROLES.filter(r => r !== "admin" || canAdmin).map(r => `<option value="${r}"${r === cur ? " selected" : ""}>${ROLEHE[r]}</option>`).join("")}</select>
      <span class="opl">${esc(opF.name)}</span>`;
  };
  $("#cpBody").innerHTML = `<div class="cp-tools">
      <label class="pill-sel"><span>מפעיל:</span><select id="cpOp">${PLATFORM || AO.length > 1 ? `<option value="">כל המפעילים</option>` : ""}${AO.map(o => `<option value="${esc(o.id)}"${o.id === CFILTER ? " selected" : ""}>${esc(o.name)}</option>`).join("")}</select></label>
      <span class="muted small">${opF ? "בחר הרשאה בכל משבצת. השינוי נשמר מיד." : "כדי לשנות הרשאה, בחר מפעיל."}</span></div>
    <div class="mx-wrap"><table class="mx"><thead><tr><th scope="col">שם</th>${tools.map(t => `<th scope="col">${esc(t.title)}${t.status !== "live" ? '<span class="soon">בקרוב</span>' : ""}</th>`).join("")}</tr></thead>
      <tbody>${(CTL.users || []).map(u => `<tr><th scope="row">${esc(u.display_name || u.username)}<span dir="ltr" class="muted small">${esc(u.username)}</span></th>${tools.map(t => `<td>${cell(u, t)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
    <p class="hint">צופה: רואה הכול. עורך: גם משנה הגדרות, תגבורים ומעברי לילה. מנהל: גם מנהל את המשתמשים של המפעיל. מנהל מערכת: הכול, בכל המפעילים.</p>`;
  if (!PLATFORM && AO.length === 1 && !CFILTER) { CFILTER = AO[0].id; drawMatrix() }
}
$("#cpBody").addEventListener("change", e => {
  const t = e.target;
  if (t.id === "cpOp") { CFILTER = t.value; drawMatrix(); $("#cpOp").focus(); return }
  if (t.dataset.rset) {
    const u = userOf(t.dataset.rset), op = CFILTER, n = u.username;
    if (!t.value) { if (confirm(`להסיר את הגישה של ${n} ל${opName(op)}?`)) ctlDo({ action: "remove_membership", user_id: u.user_id, operator_id: op }, `הגישה של ${n} ל${opName(op)} הוסרה`); else drawMatrix(); return }
    ctlDo({ action: "set_membership", user_id: u.user_id, operator_id: op, role: t.value }, `${n} · ${opName(op)}: ${ROLEHE[t.value]}`);
  }
});

// ---------- new user ----------
function newOpen() {
  const AO = adminOps(), d = $("#dlgNew");
  $("#nOp").innerHTML = (PLATFORM ? '<option value="platform">מנהל מערכת (כל המפעילים)</option>' : "") +
    (AO.length ? `<optgroup label="מפעיל">${AO.map(o => `<option value="${esc(o.id)}">${esc(o.name)}</option>`).join("")}</optgroup>` : "");
  if (!PLATFORM && AO[0]) $("#nOp").value = AO[0].id;
  $("#nRole").innerHTML = ROLES.filter(r => r !== "admin" || PLATFORM).map(r => `<option value="${r}"${r === "editor" ? " selected" : ""}>${ROLEHE[r]}</option>`).join("");
  for (const id of ["nName", "nUser", "nPw"]) $("#" + id).value = "";
  $("#nRoleBox").hidden = $("#nOp").value === "platform"; pwShow($("#nPw"), $("#nPwChk")); $("#nMsg").textContent = "";
  d.showModal(); $("#nOp").focus();
}
$("#nOp").addEventListener("change", e => { $("#nRoleBox").hidden = e.target.value === "platform" });
$("#nPw").addEventListener("input", e => pwShow(e.target, $("#nPwChk")));
$("#nGen").addEventListener("click", () => { $("#nPw").value = suggestPw(); pwShow($("#nPw"), $("#nPwChk")) });
$("#nCancel").addEventListener("click", () => $("#dlgNew").close());
$("#nUser").addEventListener("focusout", e => { e.target.value = e.target.value.trim().toLowerCase() });
$("#newForm").addEventListener("submit", async e => {
  e.preventDefault(); const m = $("#nMsg"), user = $("#nUser").value.trim().toLowerCase(), pw = $("#nPw").value, op = $("#nOp").value;
  if (!USERRE.test(user)) { m.className = "msg err"; m.textContent = ERR.bad_username; $("#nUser").focus(); return }
  if (weakPw(pw)) { pwShow($("#nPw"), $("#nPwChk")); m.className = "msg err"; m.textContent = ERR.weak_password; $("#nPw").focus(); return }
  const role = op === "platform" ? "platform" : $("#nRole").value;
  m.className = "msg"; m.textContent = "יוצר…"; $("#nSave").disabled = true;
  try {
    await fnAuth({ action: "create", username: user, display_name: $("#nName").value.trim(), ...(role === "platform" ? {} : { operator_id: op }), role, password: pw });
    $("#dlgNew").close(); CTAB = "users"; await cpDraw(true);
    cmsg(`נוצר המשתמש ${user} עם הסיסמה הזמנית ${pw} . העבר לו את שניהם. בכניסה הראשונה הוא יבחר סיסמה חדשה.`, "ok");
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
