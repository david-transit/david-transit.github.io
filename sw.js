// yalla-sa service worker: push alerts to support agents only (PRD-email M20). No caching, no fetch handler,
// so the site behaves exactly as without it. The payload carries a short text without names or content.
"use strict";
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(d.title || "יאללה־סע", {
    body: d.body || "נכנסה פנייה חדשה לטיפול",
    icon: "/assets/app/icon-192.png",
    badge: "/assets/app/icon-192.png",
    lang: "he", dir: "rtl", tag: "support", renotify: true,
    data: { url: typeof d.url === "string" && d.url.startsWith("/") ? d.url : "/support/" },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL(e.notification.data && e.notification.data.url || "/support/", self.location.origin).href;
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const same = all.find((c) => c.url.startsWith(url));
    if (same) return same.focus();
    return self.clients.openWindow(url);
  })());
});
