import https from "node:https";
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes, createHash } from "node:crypto";
import assert from "node:assert/strict";
const origin = new URL(process.env.PUBLIC_URL).origin;
const relayIp = process.env.FUNNEL_RELAY_IP;
if (!process.env.OWNER_PASSWORD_FILE)
  throw new Error("OWNER_PASSWORD_FILE is required");
const resource = origin + "/mcp";
const report = {
  endpoint: origin + "/mcp",
  relayIp: relayIp ?? null,
  checks: [],
};
function send(path, { method = "GET", headers = {}, data } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      origin + path,
      {
        method,
        headers,
        ...(relayIp
          ? {
              lookup: (_host, options, cb) =>
                options.all
                  ? cb(null, [{ address: relayIp, family: 4 }])
                  : cb(null, relayIp, 4),
            }
          : {}),
      },
      (res) => {
        const parts = [];
        res.on("data", (d) => parts.push(d));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(parts).toString(),
          }),
        );
      },
    );
    req.on("error", reject);
    req.setTimeout(150000, () => req.destroy(new Error("timeout")));
    req.end(data);
  });
}
const json = (path, value, headers = {}) =>
  send(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    data: JSON.stringify(value),
  });
const post = (path, value, headers = {}) =>
  send(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    data: new URLSearchParams(value).toString(),
  });
function passed(check) {
  report.checks.push(check);
  console.log("PASS:", check);
}
assert.equal((await send("/health")).status, 200);
passed("Public HTTPS health");
assert.equal((await send("/mcp")).status, 401);
passed("Anonymous MCP blocked");
const prm = JSON.parse(
  (await send("/.well-known/oauth-protected-resource/mcp")).body,
);
assert.equal(prm.resource, resource);
passed("OAuth resource discovery");
const client = JSON.parse(
  (
    await json("/register", {
      client_name: "Setup verification",
      redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
    })
  ).body,
);
assert.ok(client.client_id);
const verifier = randomBytes(32).toString("base64url");
const authorize = await send(
  "/authorize?" +
    new URLSearchParams({
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      response_type: "code",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
      resource,
      scope: "xiaohongshu",
      state: "verification",
    }),
);
assert.equal(authorize.status, 200);
const id = authorize.body.match(/name="request" value="([^"]+)"/)[1];
const approved = await post(
  "/approve",
  {
    request: id,
    password: readFileSync(process.env.OWNER_PASSWORD_FILE, "utf8").trim(),
  },
  { Cookie: authorize.headers["set-cookie"][0].split(";")[0], Origin: origin },
);
assert.equal(approved.status, 303);
const callback = new URL(approved.headers.location);
assert.equal(callback.searchParams.get("iss"), origin + "/");
const exchange = await post("/token", {
  grant_type: "authorization_code",
  client_id: client.client_id,
  client_secret: client.client_secret,
  code: callback.searchParams.get("code"),
  code_verifier: verifier,
  redirect_uri: client.redirect_uris[0],
  resource,
});
assert.equal(exchange.status, 200);
const tokens = JSON.parse(exchange.body);
passed("Owner consent + DCR + PKCE token exchange");
try {
  let headers = {
    Authorization: `Bearer ${tokens.access_token}`,
    Accept: "application/json, text/event-stream",
  };
  const init = await json(
    "/mcp",
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "funnel-setup-check", version: "1.0" },
      },
    },
    headers,
  );
  assert.equal(init.status, 200);
  assert.ok(JSON.parse(init.body).result.serverInfo);
  headers["Mcp-Session-Id"] = init.headers["mcp-session-id"];
  passed("Authenticated MCP initialization");
  const list = await json(
    "/mcp",
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    headers,
  );
  assert.equal(list.status, 200);
  const tools = JSON.parse(list.body).result.tools;
  assert.ok(tools.length > 0);
  report.tools = tools.map((t) => t.name);
  passed(`${tools.length} Xiaohongshu tools discovered`);
  const login = await json(
    "/mcp",
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "check_login_status", arguments: {} },
    },
    headers,
  );
  report.login = {
    httpStatus: login.status,
    result: JSON.parse(login.body).result,
  };
  console.log("Login check:", JSON.stringify(report.login));
} finally {
  const revoke = await post("/revoke", {
    client_id: client.client_id,
    client_secret: client.client_secret,
    token: tokens.refresh_token,
  });
  assert.equal(revoke.status, 200);
  assert.equal(
    (
      await send("/mcp", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })
    ).status,
    401,
  );
  passed("Verification tokens revoked");
  if (process.env.VERIFICATION_REPORT_FILE)
    writeFileSync(
      process.env.VERIFICATION_REPORT_FILE,
      JSON.stringify(report, null, 2) + "\n",
    );
}
