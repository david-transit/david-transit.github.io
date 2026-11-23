// /oauth/consent -> the portal's sign-in, carrying only a well-formed authorization_id
"use strict";
(() => {
  const id = new URLSearchParams(location.search).get("authorization_id") || "";
  location.replace(/^[A-Za-z0-9_-]{8,128}$/.test(id) ? "/?authorization_id=" + id : "/");
})();
