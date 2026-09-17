#!/usr/bin/env node
/**
 * Example agent client: requests a browser login fill and polls status.
 * Secrets never appear in these responses.
 */
const base = (process.env.SAFE_CONNECT_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const url = process.env.LOGIN_URL ?? `${base}/example/login.html`;

const request = await fetch(`${base}/v1/request_browser_login`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    purpose: "demo agent login",
    url,
    grade: process.env.GRADE ?? "L1",
  }),
});
const pending = await request.json();
console.log("request:", pending);

for (let i = 0; i < 40; i++) {
  await new Promise((r) => setTimeout(r, 250));
  const st = await fetch(`${base}/v1/requests/${pending.request_id}`);
  const body = await st.json();
  console.log("status:", body);
  if (body.status && body.status !== "pending") break;
}
