// yalla-sa support inbox (/support/). Spec: yalla-sa-support/docs/superpowers/specs/2026-11-18-whatsapp-design.md,
// PRD R7–R13. Same sign-in as the portal (session key ys_session, durations from /assets/auth-settings.js).
// Support data is personal data: RLS gives rows only to a support agent in an aal2 session, so the page asks for the
// two-step code first. Every send goes through the Edge Function wa_send (rules are enforced there, not here).
"use strict";
const SB = "https://xghfcdgettrcdciwwzbl.supabase.co", KEY = "sb_publishable_hCBsqYekz61JY6SFfT_sjw_-wj0QGXT";
const SKEY = "ys_session", ACT = "ys_act", TRUST = "ys_trust";
const AUTHCFG = window.YS_AUTH || { trustHours: 12, idleMinutes: 30 }, IDLE_MIN = +AUTHCFG.idleMinutes || 30;
const POLL_MS = 15000, WINDOW_MS = 24 * 3600e3;
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const lsGet = k => { try { return localStorage.getItem(k) } catch { return null } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v) } catch { } };

// ---------- session (mirrors assets/portal.js) ----------
let SES = null; try { SES = JSON.parse(lsGet(SKEY) || "null") } catch { }
const trustUntil = () => { const t = +lsGet(TRUST) || 0; return t > Date.now() ? t : 0 };
const idleMs = () => trustUntil() ? Infinity : IDLE_MIN * 6e4;
const lastAct = () => +lsGet(ACT) || 0;
const touchAct = () => { const n = Date.now(); if (n - lastAct() > 20000) lsSet(ACT, String(n)) };
["pointerdown", "keydown", "wheel", "touchstart"].forEach(t => addEventListener(t, touchAct, { passive: true, capture: true }));
const toPortal = () => location.replace("/");
if (!SES || Date.now() - lastAct() > idleMs()) { lsSet(SKEY, null); toPortal() }
setInterval(() => { if (Date.now() - lastAct() > idleMs()) { lsSet(SKEY, null); toPortal() } }, 60000);

function setSes(j) {
  SES = j ? { access_token: j.access_token, refresh_token: j.refresh_token, expires_at: +j.expires_at || Math.floor(Date.now() / 1000) + (+j.expires_in || 3600), user: j.user || SES?.user || null } : null;
  lsSet(SKEY, SES ? JSON.stringify(SES) : null);
}
async function http(url, opt = {}, ms = 20000) {
  const ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { ...opt, signal: ctl.signal }); const t = await r.text(); let j = null; try { j = t ? JSON.parse(t) : null } catch { }
    if (!r.ok) {
      const e = new Error(j ? [j.error_code, j.error, j.code, j.msg, j.message, j.block].filter(Boolean).join(" · ") || ("שגיאה " + r.status) : "שגיאה " + r.status);
      e.status = r.status; e.body = j; throw e;
    }
    return j;
  } finally { clearTimeout(tm) }
}
const authPost = (path, body, tok) => http(SB + "/auth/v1/" + path, { method: "POST", headers: { apikey: KEY, "Content-Type": "application/json", ...(tok ? { Authorization: "Bearer " + tok } : {}) }, body: JSON.stringify(body) });
let refreshing = null;
function refresh() {
  return refreshing ??= (async () => {
    try {
      const o = JSON.parse(lsGet(SKEY) || "null");
      if (o && o.refresh_token !== SES.refresh_token && o.expires_at - 60 > Date.now() / 1000) { SES = o; return }
      setSes(await authPost("token?grant_type=refresh_token", { refresh_token: SES.refresh_token }));
    } catch (e) { if (e.status >= 400 && e.status < 500) { setSes(null); toPortal() } throw e } finally { refreshing = null }
  })();
}
async function token() { if (!SES) throw new Error("not_signed_in"); if (SES.expires_at - 60 < Date.now() / 1000) await refresh(); return SES.access_token }
async function sb(path, opt = {}, retry = true) {
  try { return await http(SB + path, { ...opt, headers: { apikey: KEY, "Content-Type": "application/json", Authorization: "Bearer " + await token(), ...(opt.headers || {}) } }) }
  catch (e) { if (e.status === 401 && retry && SES) { await refresh(); return sb(path, opt, false) } throw e }
}
const rows = (t, qs) => sb(`/rest/v1/${t}?${qs}`);
const rpc = (fn, args) => sb(`/rest/v1/rpc/${fn}`, { method: "POST", body: JSON.stringify(args || {}) });
const authReq = async (method, path, body) => http(SB + "/auth/v1/" + path, { method, headers: { apikey: KEY, "Content-Type": "application/json", Authorization: "Bearer " + await token() }, ...(body ? { body: JSON.stringify(body) } : {}) });
async function waSend(body, isForm) {
  const headers = { apikey: KEY, Authorization: "Bearer " + await token(), ...(isForm ? {} : { "Content-Type": "application/json" }) };
  return http(SB + "/functions/v1/wa_send", { method: "POST", headers, body: isForm ? body : JSON.stringify(body) }, 90000);
}
const jwtOf = t => { try { return JSON.parse(atob(String(t).split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) } catch { return {} } };
const aal = () => SES ? jwtOf(SES.access_token).aal : null;
async function mfaVerify(fid, code) {
  code = String(code || "").replace(/\D/g, ""); if (code.length !== 6) throw new Error("mfa_verification_failed");
  const ch = await authReq("POST", `factors/${fid}/challenge`, {});
  setSes(await authReq("POST", `factors/${fid}/verify`, { challenge_id: ch.id, code }));
}

// ---------- texts ----------
const ERR = {
  window_closed: "עברו 24 שעות מההודעה האחרונה של הלקוח. אפשר לחזור אליו בטלפון או במייל",
  opted_out: "הלקוח ביקש לא לקבל הודעות", budget_exceeded: "התקציב החודשי נוצל",
  too_large: "הקובץ גדול מדי", empty: "הקובץ ריק", not_configured: "וואטסאפ עוד לא מחובר", not_allowed: "אין לך הרשאה לפעולה הזו",
  mfa_required: "צריך להקליד שוב את קוד האימות", not_found: "השיחה לא נמצאה", bad_input: "הנתונים לא תקינים",
  "Invalid TOTP code": "הקוד שגוי או שפג תוקפו", mfa_verification_failed: "הקוד שגוי או שפג תוקפו",
  "Failed to fetch": "אין חיבור לשרת. בדוק את החיבור לאינטרנט ונסה שוב", "rate limit": "יותר מדי ניסיונות. נסה שוב בעוד כמה דקות",
};
function errText(e) {
  const b = e && e.body; if (b && b.error === "too_large") return `הקובץ גדול מדי (עד ${b.limitMb}MB)`;
  if (b && b.block && ERR[b.block]) return ERR[b.block];
  const m = String(e && e.message || e); for (const k in ERR) if (m.includes(k)) return ERR[k];
  return "משהו השתבש. נסה שוב";
}
const STATUS_HE = { open: "פתוחה", assigned: "בטיפול", closed: "סגורה" };

// ---------- formatting ----------
function fmtPhone(w) {
  const d = String(w || ""); const m = d.match(/^972(\d{2})(\d{3})(\d{4})$/);
  return m ? `+972 ${m[1]}-${m[2]}-${m[3]}` : (d ? "+" + d : "");
}
const pad = n => String(n).padStart(2, "0");
function fmtTime(iso) {
  if (!iso) return ""; const t = new Date(iso), now = new Date();
  const day = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = (day(now) - day(t)) / 864e5;
  return diff === 0 ? `${pad(t.getHours())}:${pad(t.getMinutes())}` : diff === 1 ? "אתמול" : `${t.getDate()}.${t.getMonth() + 1}`;
}
const clock = iso => { const t = new Date(iso); return `${pad(t.getHours())}:${pad(t.getMinutes())}` };
const initial = s => (String(s || "").trim()[0] || "+");

// ---------- state ----------
let ME = null, PLATFORM = false, AGENTS = {}, CONVS = [], LAST = {}, TAB = "open", SEL = null, MSGS = [], SETTINGS = null, ANSWERS = [];
const contactName = c => c.support_contacts?.wa_name || fmtPhone(c.support_contacts?.wa_id);
const agentName = id => AGENTS[id] || "נציג";

// ---------- boot ----------
function showState(text, actHtml = "") { $("#state").hidden = false; $("#stateText").textContent = text; $("#stateAct").innerHTML = actHtml; $("#app").hidden = true }
async function boot() {
  try {
    ME = SES.user && SES.user.id ? SES.user : await authReq("GET", "user");
    const pr = await rows("profiles", "select=display_name,username&user_id=eq." + encodeURIComponent(ME.id));
    const name = pr[0]?.display_name || pr[0]?.username || "";
    $("#meName").textContent = name; $("#meInit").textContent = initial(name);
    if (!(await rpc("support_is_agent"))) return showState("אין לך הרשאה לשירות הלקוחות.", '<a href="/">חזרה לפורטל</a>');
    if (aal() !== "aal2" && !(await stepUp())) return;
    PLATFORM = (await rows("platform_admins", "select=user_id&user_id=eq." + encodeURIComponent(ME.id))).length > 0;
    $("#btnSettings").hidden = !PLATFORM;
    $("#state").hidden = true; $("#app").hidden = false;
    await loadAgents(); await loadList();
    const want = new URLSearchParams(location.search).get("c"); if (want && CONVS.some(c => c.id === want)) openConv(want);
    setInterval(poll, POLL_MS);
  } catch (e) { showState(errText(e), '<a href="">נסה שוב</a>') }
}
// the code dialog (same flow as the portal's control panel). Resolves true once the session is aal2.
async function stepUp() {
  const f = ((await authReq("GET", "user")).factors || []).filter(x => x.factor_type === "totp" && x.status === "verified");
  if (!f.length) { showState("כדי לראות פניות צריך אימות דו־שלבי. הפעל אותו בפאנל הבקרה, בלשונית \"האבטחה שלי\".", '<a href="/?panel=sec">לפאנל הבקרה</a>'); return false }
  $("#state").hidden = true;
  return new Promise(res => {
    const d = $("#dlgStep"), m = $("#stMsg"); $("#stOtp").value = ""; m.textContent = "";
    $("#stepForm").onsubmit = async e => {
      e.preventDefault(); m.className = "msg"; m.textContent = "בודק…"; $("#stOk").disabled = true;
      try { await mfaVerify(f[0].id, $("#stOtp").value); d.close(); res(true) }
      catch (err) { m.className = "msg err"; m.textContent = errText(err); $("#stOtp").select() } finally { $("#stOk").disabled = false }
    };
    d.oncancel = ev => ev.preventDefault();
    d.showModal(); $("#stOtp").focus();
  });
}
// a call refused for aal (session dropped to aal1 mid-work): ask for the code, then try once more
async function withAal(fn) {
  try { return await fn() } catch (e) {
    if (aal() === "aal2" || !(await stepUp())) throw e; // only when the session really lost the code
    return fn();
  }
}

// ---------- data ----------
async function loadAgents() {
  const ag = await rows("support_agents", "select=user_id");
  const ids = ag.map(a => a.user_id); if (!ids.includes(ME.id)) ids.push(ME.id);
  const pr = await rows("profiles", "select=user_id,display_name,username&user_id=in.(" + ids.map(encodeURIComponent).join(",") + ")");
  AGENTS = {}; for (const p of pr) AGENTS[p.user_id] = p.display_name || p.username;
  AGENTS.__ids = ag.map(a => a.user_id);
}
async function loadList() {
  const [cv, last] = await Promise.all([
    rows("support_conversations", "select=id,status,assignee,last_inbound_at,created_at,closed_at,support_contacts(wa_id,wa_name)&order=created_at.desc&limit=300"),
    rows("support_messages", "select=conversation_id,direction,body,created_at&conversation_id=not.is.null&order=created_at.desc&limit=600")]);
  CONVS = cv; LAST = {};
  for (const m of last) if (!LAST[m.conversation_id]) LAST[m.conversation_id] = m;
  CONVS.sort((a, b) => new Date(LAST[b.id]?.created_at || b.created_at) - new Date(LAST[a.id]?.created_at || a.created_at));
  drawList();
}
async function loadThread() {
  if (!SEL) return;
  MSGS = await rows("support_messages", "select=id,direction,sender,agent_id,body,template,status,error,created_at&conversation_id=eq." + SEL + "&order=created_at.asc&limit=500");
  drawThread();
}
async function poll() { if (document.hidden) return; try { await loadList(); if (SEL) await loadThread() } catch { } }

// ---------- list ----------
function drawList() {
  const q = $("#q").value.trim().toLowerCase().replace(/[\s+-]/g, "");
  const count = s => CONVS.filter(c => c.status === s).length;
  $("#cOpen").textContent = count("open") || ""; $("#cAssigned").textContent = count("assigned") || "";
  const list = CONVS.filter(c => c.status === TAB).filter(c => !q ||
    String(c.support_contacts?.wa_name || "").toLowerCase().includes(q) || String(c.support_contacts?.wa_id || "").includes(q.replace(/^0/, "972")));
  $("#rows").innerHTML = list.map(c => {
    const l = LAST[c.id], unread = l && l.direction === "in" && c.status !== "closed";
    const handler = c.status === "assigned" ? (c.assignee ? agentName(c.assignee) : "בתור") : STATUS_HE[c.status];
    return `<li><button class="row" type="button" data-id="${c.id}" aria-current="${c.id === SEL}">
      <span class="ini" aria-hidden="true">${esc(initial(c.support_contacts?.wa_name))}</span>
      <span class="nm" ${c.support_contacts?.wa_name ? "" : 'dir="ltr" style="text-align:right"'}>${esc(contactName(c))}</span>
      <span class="tm">${unread ? '<i class="dot" aria-label="הודעה חדשה"></i>' : ""}${esc(fmtTime(l?.created_at || c.created_at))}</span>
      <span class="pv">${esc(l?.body || "")}</span>
      <span class="hd chip">${esc(handler)}</span></button></li>`;
  }).join("");
  $("#listEmpty").hidden = list.length > 0;
}
$("#rows").addEventListener("click", e => { const b = e.target.closest(".row"); if (b) openConv(b.dataset.id) });
$("#q").addEventListener("input", drawList);
$("#tabs").addEventListener("click", e => {
  const b = e.target.closest("[data-tab]"); if (!b) return; TAB = b.dataset.tab;
  for (const x of $("#tabs").querySelectorAll("[data-tab]")) x.setAttribute("aria-selected", String(x === b));
  drawList();
});

// ---------- thread ----------
async function openConv(id) {
  SEL = id; $("#inbox").classList.add("show-thread"); $("#sendMsg").textContent = "";
  history.replaceState(null, "", "?c=" + id); drawList(); drawHead(); MSGS = []; drawThread();
  try { await loadThread() } catch (e) { $("#sendMsg").textContent = errText(e) }
}
$("#btnBack").addEventListener("click", () => { $("#inbox").classList.remove("show-thread"); SEL = null; history.replaceState(null, "", location.pathname); drawList() });
const conv = () => CONVS.find(c => c.id === SEL);
function drawHead() {
  const c = conv(); $("#threadNone").hidden = !!c; $("#threadIn").hidden = !c; if (!c) return;
  $("#thName").textContent = c.support_contacts?.wa_name || fmtPhone(c.support_contacts?.wa_id);
  $("#thName").dir = c.support_contacts?.wa_name ? "auto" : "ltr"; // a bare number reads left to right
  $("#thNum").textContent = c.support_contacts?.wa_name ? fmtPhone(c.support_contacts?.wa_id) : "";
  const chip = $("#thChip");
  chip.textContent = c.status === "assigned" ? `בטיפול · ${c.assignee ? agentName(c.assignee) : "בתור"}` : STATUS_HE[c.status];
  chip.className = "chip" + (c.status === "assigned" ? " blue" : "");
  $("#btnClose").textContent = c.status === "closed" ? "פתיחה מחדש" : "סגירת פנייה";
  const left = c.last_inbound_at ? WINDOW_MS - (Date.now() - new Date(c.last_inbound_at)) : -1;
  const open = left > 0 && c.status !== "closed";
  $("#composer").hidden = !open; $("#winClosed").hidden = open || c.status === "closed";
  if (open) $("#winText").textContent = `חלון 24 השעות פתוח עוד ${Math.max(1, Math.ceil(left / 3600e3))} שעות`;
}
function ticks(m) {
  if (m.direction !== "out") return "";
  if (m.status === "failed") return "";
  return m.status === "read" ? '<span class="ticks read" aria-label="נקראה">✓✓</span>'
    : m.status === "delivered" ? '<span class="ticks" aria-label="נמסרה">✓✓</span>'
    : m.status === "sent" ? '<span class="ticks" aria-label="נשלחה">✓</span>' : '<span class="ticks" aria-label="בשליחה">⏱</span>';
}
function drawThread() {
  drawHead();
  const el = $("#msgs"), atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  el.innerHTML = MSGS.map(m => {
    const cls = m.direction === "in" ? "in" : m.sender === "bot" ? "out bot" : "out";
    const label = m.direction === "in" ? "" : m.sender === "bot" ? "בוט" : m.sender === "system" ? "מערכת" : agentName(m.agent_id);
    const failed = m.status === "failed";
    return `<li class="b ${cls}">${label ? `<span class="who-l">${esc(label)}</span>` : ""}${m.template ? `<span class="tpl">הודעה מוכנה: ${esc(m.template)}</span>` : ""}<span class="tx">${esc(m.body)}</span><span class="meta">${failed ? '<span class="fail">⚠ לא נשלחה</span>' : ""}${ticks(m)}<span>${clock(m.created_at)}</span></span>
      ${failed && !m.template && !String(m.body || "").startsWith("📎") ? `<button class="resend" type="button" data-id="${m.id}">שליחה שוב</button>` : ""}</li>`;
  }).join("");
  if (atEnd || !el.dataset.sel || el.dataset.sel !== SEL) el.scrollTop = el.scrollHeight;
  el.dataset.sel = SEL || "";
}
$("#msgs").addEventListener("click", async e => {
  const b = e.target.closest(".resend"); if (!b) return; b.disabled = true;
  try { await withAal(() => waSend({ action: "resend", message: b.dataset.id })); await loadThread() }
  catch (err) { $("#sendMsg").textContent = errText(err); b.disabled = false }
});

// composer: Enter sends, Shift+Enter is a new line
const reply = $("#reply");
reply.addEventListener("input", () => { reply.style.height = "auto"; reply.style.height = Math.min(reply.scrollHeight, 160) + "px" });
reply.addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("#composer").requestSubmit() } });
$("#composer").addEventListener("submit", async e => {
  e.preventDefault(); const body = reply.value.trim(); if (!body || !SEL) return;
  const m = $("#sendMsg"); m.textContent = ""; $("#btnSend").disabled = true;
  try { await withAal(() => waSend({ action: "reply", conversation: SEL, body })); reply.value = ""; reply.style.height = ""; await poll() }
  catch (err) { m.textContent = errText(err) } finally { $("#btnSend").disabled = false; reply.focus() }
});
$("#file").addEventListener("change", async e => {
  const f = e.target.files[0]; e.target.value = ""; if (!f || !SEL) return;
  const m = $("#sendMsg"); m.className = "msg"; m.textContent = `שולח את ${f.name}…`;
  const fd = new FormData(); fd.append("action", "file"); fd.append("conversation", SEL); fd.append("file", f, f.name);
  try { await withAal(() => waSend(fd, true)); m.textContent = ""; await poll() }
  catch (err) { m.className = "msg err"; m.textContent = errText(err) }
});

// header actions
function toggleMenu(btn, menu, open) {
  const show = open ?? menu.hidden; menu.hidden = !show; btn.setAttribute("aria-expanded", String(show));
  if (show) menu.querySelector("button")?.focus();
}
document.addEventListener("click", e => {
  for (const [b, m] of [["#btnAssign", "#assignMenu"], ["#btnMore", "#moreMenu"]]) if (!e.target.closest(b) && !e.target.closest(m)) toggleMenu($(b), $(m), false);
});
document.addEventListener("keydown", e => { if (e.key === "Escape") { toggleMenu($("#btnAssign"), $("#assignMenu"), false); toggleMenu($("#btnMore"), $("#moreMenu"), false) } });
$("#btnAssign").addEventListener("click", () => {
  const c = conv(); if (!c) return;
  $("#assignMenu").innerHTML = [`<li><button role="menuitemradio" type="button" data-u="" aria-checked="${!c.assignee}">בתור (ללא נציג)</button></li>`]
    .concat(AGENTS.__ids.map(id => `<li><button role="menuitemradio" type="button" data-u="${id}" aria-checked="${c.assignee === id}">${esc(agentName(id))}${id === ME.id ? " (אני)" : ""}</button></li>`)).join("");
  toggleMenu($("#btnAssign"), $("#assignMenu"));
});
$("#assignMenu").addEventListener("click", async e => {
  const b = e.target.closest("[data-u]"); if (!b) return; toggleMenu($("#btnAssign"), $("#assignMenu"), false);
  await setStatus("assigned", b.dataset.u || null);
});
$("#btnClose").addEventListener("click", () => { const c = conv(); if (c) setStatus(c.status === "closed" ? "open" : "closed", c.status === "closed" ? null : c.assignee) });
$("#btnMore").addEventListener("click", () => toggleMenu($("#btnMore"), $("#moreMenu")));
$("#miRefresh").addEventListener("click", () => { toggleMenu($("#btnMore"), $("#moreMenu"), false); poll() });
async function setStatus(status, assignee) {
  try { await withAal(() => rpc("support_set_status", { p_conv: SEL, p_status: status, p_assignee: assignee })); await loadList(); drawHead() }
  catch (e) { $("#sendMsg").textContent = errText(e) }
}

// ---------- settings (platform admin) ----------
$("#btnSettings").addEventListener("click", openSettings);
$("#setX").addEventListener("click", () => $("#dlgSettings").close());
async function openSettings() {
  const m = $("#setMsg"); m.textContent = "";
  try {
    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const [st, sp, an] = await Promise.all([rows("support_settings", "select=*&id=eq.1"), rows("support_spend", "select=kind,amount_ils&created_at=gte." + monthStart.toISOString()), rows("support_answers", "select=key,body&order=key")]);
    SETTINGS = st[0]; ANSWERS = an;
    const sum = k => sp.filter(x => !k || x.kind === k).reduce((a, x) => a + +x.amount_ils, 0);
    const tot = sum(), cap = +SETTINGS.monthly_cap_ils, pct = cap ? Math.min(100, Math.round(tot / cap * 100)) : 0;
    $("#spNow").textContent = `₪${tot.toFixed(2)}`; $("#spCap").textContent = `₪${cap}`; $("#spPct").textContent = pct + "%";
    const bar = $("#spBar"); bar.querySelector("i").style.width = pct + "%"; bar.className = "bar" + (pct >= 100 ? " over" : pct >= 80 ? " warn" : "");
    bar.setAttribute("aria-valuenow", pct); bar.setAttribute("aria-valuemin", 0); bar.setAttribute("aria-valuemax", 100);
    $("#spSplit").textContent = `וואטסאפ ₪${sum("meta").toFixed(2)} · בוט חכם ₪${sum("ai").toFixed(2)}`;
    $("#sCap").value = cap;
    for (const r of document.querySelectorAll('[name=chan]')) r.checked = r.value === SETTINGS.alert_channel;
    $("#chanNote").hidden = SETTINGS.alert_channel !== "email";
    $("#sTo").value = SETTINGS.alert_to ? "0" + String(SETTINGS.alert_to).replace(/^972/, "") : "";
    $("#sFrom").value = SETTINGS.hours?.from || "08:00"; $("#sTo2").value = SETTINGS.hours?.to || "17:00";
    const TITLES = { "1": "1 – בעיה בכניסה", "2": "2 – שאלה על הכלי", hours_off: "מחוץ לשעות הפעילות" };
    $("#answers").innerHTML = an.map(a => `<details><summary>${esc(TITLES[a.key] || a.key)} <span aria-hidden="true">✎</span></summary>
      <label class="sr" for="ans-${esc(a.key)}">${esc(TITLES[a.key] || a.key)}</label>
      <textarea id="ans-${esc(a.key)}" data-key="${esc(a.key)}" maxlength="1000">${esc(a.body)}</textarea></details>`).join("");
    $("#dlgSettings").showModal();
  } catch (e) { alertMsg(errText(e)) }
}
function alertMsg(t) { $("#sendMsg").textContent = t }
document.querySelectorAll("[name=chan]").forEach(r => r.addEventListener("change", () => { $("#chanNote").hidden = r.value !== "email" || !r.checked }));
$("#setForm").addEventListener("submit", async e => {
  e.preventDefault(); const m = $("#setMsg"); m.className = "msg"; m.textContent = "שומר…"; $("#setSave").disabled = true;
  try {
    const raw = $("#sTo").value.replace(/\D/g, ""), to = raw ? (raw.startsWith("0") ? "972" + raw.slice(1) : raw) : "";
    if (to && !/^\d{10,15}$/.test(to)) throw new Error("bad_input");
    const chan = document.querySelector("[name=chan]:checked")?.value || SETTINGS.alert_channel;
    await withAal(() => rpc("support_save_settings", { p: { monthly_cap_ils: +$("#sCap").value || 0, alert_channel: chan, alert_to: to,
      hours: { ...(SETTINGS.hours || {}), days: SETTINGS.hours?.days || [0, 1, 2, 3, 4], from: $("#sFrom").value || "08:00", to: $("#sTo2").value || "17:00" } } }));
    for (const t of document.querySelectorAll("#answers textarea")) {
      const old = ANSWERS.find(a => a.key === t.dataset.key)?.body; const v = t.value.trim();
      if (v && v !== old) await withAal(() => rpc("support_save_answer", { p_key: t.dataset.key, p_body: v }));
    }
    m.className = "msg ok"; m.textContent = "נשמר";
  } catch (err) { m.className = "msg err"; m.textContent = errText(err) } finally { $("#setSave").disabled = false }
});

boot();
