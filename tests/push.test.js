// node --test tests/  (PRD-email M20: the menu item's states)
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { pushView, deviceLabel, keyBytes } = require("../assets/push.js");
const base = { supported: true, ios: false, standalone: false, permission: "default", subscribed: false };

test("iPhone outside the home-screen app: explains how to add it, no action", () => {
  const v = pushView({ ...base, supported: false, ios: true });
  assert.equal(v.act, null); assert.match(v.note, /הוסף למסך הבית/);
});
test("unsupported browser: no action", () => {
  const v = pushView({ ...base, supported: false });
  assert.equal(v.act, null); assert.match(v.note, /לא תומך/);
});
test("blocked in the browser: no action, says so", () => {
  const v = pushView({ ...base, permission: "denied" });
  assert.equal(v.act, null); assert.match(v.note, /חסומות/);
});
test("off -> turn on; on -> turn off", () => {
  assert.equal(pushView(base).act, "on");
  assert.equal(pushView(base).label, "הפעל התראות על פניות");
  assert.equal(pushView({ ...base, permission: "granted", subscribed: true }).act, "off");
  assert.equal(pushView({ ...base, ios: true, standalone: true }).act, "on");
});
test("device label and key decoding", () => {
  assert.equal(deviceLabel("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"), "iPhone");
  assert.equal(deviceLabel("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "Windows");
  assert.deepEqual([...keyBytes("AQID_-8")], [1, 2, 3, 255, 239]);
});
