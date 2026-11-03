import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.js";

const env = { BOOTSTRAP_TOKEN: "test-token", UPSTREAM_BASES: "https://relay.example/bootstrap/" };

test("rejects requests outside the secret path", async () => {
  const response = await worker.fetch(new Request("https://example.test/reg", { method: "POST" }), env);
  assert.equal(response.status, 404);
});

test("rejects unsupported methods and oversized bodies", async () => {
  const get = await worker.fetch(new Request("https://example.test/test-token/reg"), env);
  assert.equal(get.status, 405);
  const oversized = await worker.fetch(new Request("https://example.test/test-token/reg", {
    method: "POST",
    headers: { "Content-Length": "8193" },
  }), env);
  assert.equal(oversized.status, 413);
});

test("proxies only registration fields", async () => {
  const originalFetch = globalThis.fetch;
  let forwarded;
  globalThis.fetch = async (url, init) => {
    forwarded = { url: url.toString(), init };
    return new Response('{"result":{}}', {
      status: 200,
      headers: { "Content-Type": "application/json", "Set-Cookie": "ignored=true" },
    });
  };
  try {
    const response = await worker.fetch(new Request("https://example.test/test-token/reg/id", {
      method: "PATCH",
      headers: { Authorization: "Bearer token", "X-Untrusted": "value" },
      body: "{}",
    }), env);
    assert.equal(response.status, 200);
    assert.equal(forwarded.url, "https://relay.example/bootstrap/reg/id");
    assert.equal(forwarded.init.headers.get("Authorization"), "Bearer token");
    assert.equal(forwarded.init.headers.has("X-Untrusted"), false);
    assert.equal(response.headers.has("Set-Cookie"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("uses the next relay after an upstream failure", async () => {
  const originalFetch = globalThis.fetch;
  const forwarded = [];
  globalThis.fetch = async (url) => {
    forwarded.push(url.toString());
    return new Response(null, { status: forwarded.length === 1 ? 502 : 400 });
  };
  try {
    const response = await worker.fetch(new Request("https://example.test/test-token/reg", {
      method: "POST",
      body: "{}",
    }), {
      BOOTSTRAP_TOKEN: "test-token",
      UPSTREAM_BASES: "https://first.example/bootstrap/|https://second.example/bootstrap/",
    });
    assert.equal(response.status, 400);
    assert.deepEqual(forwarded, [
      "https://first.example/bootstrap/reg",
      "https://second.example/bootstrap/reg",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
