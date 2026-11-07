import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createGateway } from "./gateway.mjs";

const issuer = "https://mcp.example.test/";
const resource = issuer + "mcp";
const redirect = "https://chatgpt.com/connector_platform_oauth_redirect";
const password = randomBytes(32).toString("base64url");
const verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const body = (value) => new URLSearchParams(value);

test("OAuth protects the complete MCP proxy flow", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "xhs-oauth-test-"));
  const upstream = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      res.setHeader("mcp-session-id", "upstream-session");
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          path: req.url,
          method: req.method,
          authorization: req.headers.authorization,
          cookie: req.headers.cookie,
          session: req.headers["mcp-session-id"],
          body: Buffer.concat(chunks).toString(),
        }),
      );
    });
  }).listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const options = {
    publicUrl: issuer,
    upstreamUrl: `http://127.0.0.1:${upstream.address().port}/mcp`,
    password,
    stateFile: join(dir, "state.json"),
  };
  const gateway = createGateway(options);
  const server = gateway.app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.close();
    upstream.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const send = (path, opts = {}) =>
    fetch(base + path, { ...opts, redirect: "manual" });
  const post = (path, value, headers = {}) =>
    send(path, { method: "POST", body: body(value), headers });
  const register = () =>
    send("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "<ChatGPT>",
        redirect_uris: [redirect],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "xiaohongshu",
      }),
    });
  const tokenRequest = (code, extra = {}) =>
    post("/token", {
      grant_type: "authorization_code",
      client_id: client.client_id,
      code,
      code_verifier: verifier,
      redirect_uri: redirect,
      resource,
      ...extra,
    });
  const unauthorized = await send("/mcp");
  assert.equal(unauthorized.status, 401);
  assert.match(
    unauthorized.headers.get("www-authenticate"),
    /oauth-protected-resource\/mcp/,
  );
  const prm = await (
    await send("/.well-known/oauth-protected-resource/mcp")
  ).json();
  assert.equal(prm.resource, resource);
  assert.deepEqual(prm.authorization_servers, [issuer]);
  const metadata = await (
    await send("/.well-known/oauth-authorization-server")
  ).json();
  assert.equal(metadata.issuer, issuer);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.equal((await send("/api/v1/login/qrcode")).status, 404);
  assert.equal(
    (await send("/mcp", { headers: { Origin: "https://evil.test" } })).status,
    403,
  );
  assert.equal(
    (
      await send("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://evil.test/callback"] }),
      })
    ).status,
    400,
  );
  const registration = await register();
  assert.equal(registration.status, 201);
  const client = await registration.json();
  assert.equal(statSync(options.stateFile).mode & 0o777, 0o600);
  const authQuery = {
    client_id: client.client_id,
    response_type: "code",
    redirect_uri: redirect,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource,
    scope: "xiaohongshu",
    state: "state-to-echo",
  };
  for (const extra of [
    { resource: "https://wrong.test/mcp" },
    { scope: "admin" },
  ]) {
    const rejected = await send(
      "/authorize?" + body({ ...authQuery, ...extra }),
    );
    assert.equal(rejected.status, 302);
    const location = new URL(rejected.headers.get("location"));
    assert.ok(location.searchParams.has("error"));
    assert.equal(location.searchParams.get("iss"), issuer);
  }
  const consent = await send("/authorize?" + body(authQuery));
  assert.equal(consent.status, 200);
  const html = await consent.text();
  assert.ok(html.includes("&lt;ChatGPT&gt;"));
  const requestId = html.match(/name="request" value="([^"]+)"/)[1];
  const cookie = consent.headers.get("set-cookie").split(";")[0];
  assert.equal(
    (await post("/approve", { request: requestId, password })).status,
    400,
  );
  assert.equal(
    (
      await post(
        "/approve",
        { request: requestId, password: "wrong" },
        { Cookie: cookie },
      )
    ).status,
    403,
  );
  const approved = await post(
    "/approve",
    { request: requestId, password },
    { Cookie: cookie, Origin: new URL(issuer).origin },
  );
  assert.equal(approved.status, 303);
  const callback = new URL(approved.headers.get("location"));
  assert.equal(callback.searchParams.get("state"), "state-to-echo");
  assert.equal(callback.searchParams.get("iss"), issuer);
  const code = callback.searchParams.get("code");
  assert.equal(
    (
      await post(
        "/approve",
        { request: requestId, password },
        { Cookie: cookie },
      )
    ).status,
    400,
  );
  assert.equal(
    (await tokenRequest(code, { code_verifier: "wrong" })).status,
    400,
  );
  assert.equal(
    (await tokenRequest(code, { redirect_uri: "https://evil.test/" })).status,
    400,
  );
  assert.equal(
    (await tokenRequest(code, { resource: "https://wrong.test/mcp" })).status,
    400,
  );
  const exchange = await tokenRequest(code);
  assert.equal(exchange.status, 200);
  const tokens = await exchange.json();
  assert.equal((await tokenRequest(code)).status, 400);
  const headers = {
    Authorization: `Bearer ${tokens.access_token}`,
    "Content-Type": "application/json",
    "mcp-session-id": "client-session",
    Cookie: "secret=hidden",
  };
  const result = await send("/mcp", {
    method: "POST",
    headers,
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
  });
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("mcp-session-id"), "upstream-session");
  const proxied = await result.json();
  assert.equal(proxied.path, "/mcp");
  assert.equal(proxied.session, "client-session");
  assert.equal(proxied.authorization, undefined);
  assert.equal(proxied.cookie, undefined);
  assert.equal(JSON.parse(proxied.body).method, "tools/list");
  // Persist registered clients and tokens across restarts.
  const restarted = createGateway(options);
  assert.equal(
    (await restarted.provider.clientsStore.getClient(client.client_id))
      .client_id,
    client.client_id,
  );
  assert.equal(
    (await restarted.provider.verifyAccessToken(tokens.access_token)).resource
      .href,
    resource,
  );
  const otherClient = await (await register()).json();
  assert.equal(
    (
      await post("/token", {
        grant_type: "refresh_token",
        client_id: otherClient.client_id,
        refresh_token: tokens.refresh_token,
        resource,
      })
    ).status,
    400,
  );
  const refreshed = await post("/token", {
    grant_type: "refresh_token",
    client_id: client.client_id,
    refresh_token: tokens.refresh_token,
    resource,
  });
  assert.equal(refreshed.status, 200);
  const newTokens = await refreshed.json();
  assert.notEqual(newTokens.access_token, tokens.access_token);
  assert.equal(
    (
      await post("/token", {
        grant_type: "refresh_token",
        client_id: client.client_id,
        refresh_token: tokens.refresh_token,
        resource,
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await post("/revoke", {
        client_id: client.client_id,
        token: newTokens.refresh_token,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await send("/mcp", {
        headers: { Authorization: `Bearer ${newTokens.access_token}` },
      })
    ).status,
    401,
  );
  assert.equal(
    (
      await send("/mcp", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })
    ).status,
    401,
  );
});

test("configuration rejects public upstreams and weak owner passwords", () => {
  const args = {
    publicUrl: issuer,
    upstreamUrl: "http://127.0.0.1:18060/mcp",
    password,
    stateFile: "/unused",
  };
  assert.throws(() =>
    createGateway({ ...args, upstreamUrl: "http://example.com/mcp" }),
  );
  assert.throws(() =>
    createGateway({ ...args, publicUrl: "http://example.com" }),
  );
  assert.throws(() => createGateway({ ...args, password: "weak" }));
});
