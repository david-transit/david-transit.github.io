// yalla-sa sign-in settings: the ONE place to change them. Loaded by the portal (yalla-sa.app/) and by every tool on
// this site (e.g. /deadhead-dashboard/ loads /assets/auth-settings.js); both fall back to the same defaults if it is missing.
"use strict";
window.YS_AUTH = Object.freeze({
  // "personal device" ticked at sign-in: the device stays signed in this many hours, with no idle sign-out
  // (David 18.11.2026: 12 hours; considering 30 days = 720). Cancelled by sign-out or in the control panel.
  trustHours: 12,
  // every other device: sign-out after this many minutes without a click, key or scroll
  idleMinutes: 30,
});
