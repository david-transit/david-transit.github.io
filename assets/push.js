// yalla-sa portal: "turn on alerts" in the user menu, for support agents only (PRD-email M20, ה־12).
// The device subscribes with the server's public key (support_push {action:"key"}); the server sends a short text with
// no name or content. Uses sb() and token() from portal.js. pushView is pure (tested in Node: tests/push.test.js).
"use strict";

function pushView(e) {
  if (!e.supported) return e.ios && !e.standalone
    ? { act: null, label: "התראות על פניות", note: "כדי לקבל התראות באייפון: שתף ← הוסף למסך הבית, ופתחו את יאללה־סע משם" }
    : { act: null, label: "התראות על פניות", note: "הדפדפן הזה לא תומך בהתראות" };
  if (e.permission === "denied") return { act: null, label: "התראות על פניות", note: "ההתראות חסומות בהגדרות הדפדפן" };
  if (e.subscribed) return { act: "off", label: "כבה התראות במכשיר הזה", note: "התראות על פניות פועלות במכשיר הזה" };
  return { act: "on", label: "הפעל התראות על פניות", note: "" };
}
function deviceLabel(ua) {
  return /iPhone|iPad/.test(ua) ? "iPhone" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Mac/.test(ua) ? "Mac" : "דפדפן";
}
function keyBytes(b64) {
  const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

if (typeof module !== "undefined") module.exports = { pushView, deviceLabel, keyBytes };
else {
  const PFN = (b) => sb("/functions/v1/support_push", { method: "POST", body: JSON.stringify(b) });
  const env = async () => {
    const supported = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
    const ios = /iPhone|iPad/.test(navigator.userAgent);
    const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    let sub = null;
    if (supported) { const reg = await navigator.serviceWorker.getRegistration("/"); sub = reg ? await reg.pushManager.getSubscription() : null; }
    return { supported, ios, standalone, permission: supported ? Notification.permission : "default", subscribed: !!sub, sub };
  };
  const send = (sub) => PFN({ action: "subscribe", endpoint: sub.endpoint, keys: sub.toJSON().keys, label: deviceLabel(navigator.userAgent) });

  async function draw() {
    const e = await env(), v = pushView(e), btn = document.getElementById("pushItem"), note = document.getElementById("pushNote");
    btn.textContent = v.label; btn.disabled = !v.act; btn.dataset.pact = v.act || ""; note.textContent = v.note; note.hidden = !v.note;
    return e;
  }
  async function turnOn() {
    // permission first: iPhone allows the prompt only directly from the tap
    if (await Notification.requestPermission() !== "granted") return;
    const reg = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
    const { key } = await PFN({ action: "key" });
    // a subscription made with an earlier key cannot be reused: drop it first (the server key may have been replaced)
    const old = await reg.pushManager.getSubscription();
    if (old) { await PFN({ action: "unsubscribe", endpoint: old.endpoint }).catch(() => {}); await old.unsubscribe(); }
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) });
    await send(sub);
    await PFN({ action: "test" });
  }
  async function turnOff() {
    const reg = await navigator.serviceWorker.getRegistration("/"), sub = reg && await reg.pushManager.getSubscription();
    if (!sub) return;
    await PFN({ action: "unsubscribe", endpoint: sub.endpoint }).catch(() => {});
    await sub.unsubscribe();
  }
  // called by showPortal (portal.js): show the item to support agents only; keep the server in step with this device
  window.pushSetup = async () => {
    try {
      if (!(await sb("/rest/v1/rpc/support_is_agent", { method: "POST", body: "{}" }))) return;
      document.getElementById("supportItem").hidden = false; // link to the support inbox (/support/)
      document.getElementById("pushItem").hidden = false;
      const e = await draw();
      if (e.sub && e.permission === "granted") send(e.sub).catch(() => {});
    } catch (err) { console.warn("push", err); }
  };
  document.getElementById("pushItem").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, act = btn.dataset.pact, note = document.getElementById("pushNote");
    if (!act) return;
    btn.disabled = true; note.hidden = false; note.textContent = act === "on" ? "מפעיל…" : "מכבה…";
    try { act === "on" ? await turnOn() : await turnOff(); await draw(); }
    catch (err) { console.warn("push", err); note.textContent = "לא הצלחנו להפעיל התראות. נסה שוב"; btn.disabled = false; }
  });
}
