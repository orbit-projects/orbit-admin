import assert from "node:assert/strict";
import test from "node:test";

import { AdminClientError, createAdminClient } from "../dist/assets/admin-client.js";

test("client requests only fixed Core paths with same-origin credentials and no cache", async () => {
  let actualUrl;
  let actualOptions;
  const client = createAdminClient(async (url, options) => {
    actualUrl = url;
    actualOptions = options;
    return Response.json({ state: "running" }, { headers: { "cache-control": "no-store" } });
  });

  const result = await client.read("state");

  assert.deepEqual(result, { state: "running" });
  assert.equal(actualUrl, "/admin/state");
  assert.equal(actualOptions.credentials, "same-origin");
  assert.equal(actualOptions.cache, "no-store");
  assert.equal(actualOptions.redirect, "error");
  assert.equal(actualOptions.mode, "same-origin");
});

test("remote error text and credentials are not copied into client errors", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ code: "security.forbidden", message: "password=do-not-show" }),
    { status: 403, headers: { "content-type": "application/json" } },
  ));

  await assert.rejects(client.read("config"), (error) => {
    assert.ok(error instanceof AdminClientError);
    assert.equal(error.status, 403);
    assert.equal(error.code, "security.forbidden");
    assert.equal(error.message, "Your account cannot view this section.");
    assert.equal(error.message.includes("do-not-show"), false);
    return true;
  });
});

test("401 uses a safe status and ignores an invalid remote error code", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ code: "<script>alert(1)</script>" }),
    { status: 401, headers: { "content-type": "application/json" } },
  ));

  await assert.rejects(client.read("state"), (error) => {
    assert.ok(error instanceof AdminClientError);
    assert.equal(error.status, 401);
    assert.equal(error.code, "admin.request-failed");
    return true;
  });
});

test("redirected and non-JSON responses fail closed", async () => {
  const redirected = createAdminClient(async () => new Response("login", {
    headers: { "content-type": "text/html" },
  }));
  await assert.rejects(redirected.read("state"), { code: "admin.invalid-response" });

  const redirectedFlag = createAdminClient(async () => {
    const response = Response.json({ state: "running" });
    Object.defineProperty(response, "redirected", { value: true });
    return response;
  });
  await assert.rejects(redirectedFlag.read("state"), { code: "admin.invalid-response" });
});

test("response bytes are bounded from the stream, even without Content-Length", async () => {
  const client = createAdminClient(async () => new Response(
    JSON.stringify({ data: "x".repeat(300) }),
    { headers: { "content-type": "application/json" } },
  ), "/admin", 128);

  await assert.rejects(client.read("diagnostics"), { code: "admin.response-too-large" });
});

test("API path and byte limit cannot point to another origin or exceed the fixed ceiling", () => {
  assert.throws(() => createAdminClient(fetch, "https://example.invalid/admin"), TypeError);
  assert.throws(() => createAdminClient(fetch, "//example.invalid/admin"), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin/../outside"), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin%2f.."), TypeError);
  assert.throws(() => createAdminClient(fetch, "/admin", 16_777_217), RangeError);
});
