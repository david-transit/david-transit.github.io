// yalla-sa sign-in settings: the ONE place to change them. Loaded by the portal (yalla-sa.app/) and by every tool on
// this site (e.g. /deadhead-dashboard/ loads /assets/auth-settings.js); both fall back to the same defaults if it is missing.
"use strict";
window.YS_AUTH = Object.freeze({
  // "personal device" ticked at sign-in: the device stays signed in this many hours, with no idle sign-out.
  // David 18.11.2026: 30 days (720), after the device list with remote disconnect went live. The server caps it at 720
  // (public.device_trust). Cancelled by sign-out, in the control panel, or by a remote disconnect.
  trustHours: 720,
  // every other device: sign-out after this many minutes without a click, key or scroll
  idleMinutes: 30,
  // single gate (David 18.11.2026, stage A): app.yalla-sa.app sits behind Cloudflare Access, whose only login method is
  // this portal (Supabase OAuth server -> /oauth/consent -> portal sign-in). The portal approves ONLY this client and
  // ONLY this callback; empty client id = the bridge is off (nothing is approved).
  accessClientId: "",
  accessCallback: "https://snowy-brook-bd72.cloudflareaccess.com/cdn-cgi/access/callback",
  // portal sign-out also ends the Access session (same site as yalla-sa.app, so its cookie is sent)
  accessLogout: "https://app.yalla-sa.app/cdn-cgi/access/logout",
});
