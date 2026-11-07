import express from "express";
import { rateLimit } from "express-rate-limit";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { request } from "node:http";
import { pathToFileURL } from "node:url";
import {
  createOAuthMetadata,
  mcpAuthRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";

const random = () => randomBytes(32).toString("base64url");
const hash = (value) => createHash("sha256").update(value).digest("hex");
const now = () => Math.floor(Date.now() / 1000);
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const scope = "xiaohongshu";

// Single-owner authorization gateway. The Go server remains bound to loopback.
export function createGateway({
  publicUrl,
  upstreamUrl,
  password,
  stateFile,
  redirectUris = ["https://chatgpt.com/connector_platform_oauth_redirect"],
}) {
  const issuer = new URL(publicUrl);
  const upstream = new URL(upstreamUrl);
  if (
    issuer.protocol !== "https:" ||
    issuer.pathname !== "/" ||
    issuer.search ||
    issuer.hash ||
    issuer.username ||
    issuer.password
  )
    throw new Error("PUBLIC_URL must be an HTTPS origin");
  if (
    upstream.protocol !== "http:" ||
    upstream.hostname !== "127.0.0.1" ||
    upstream.pathname !== "/mcp" ||
    upstream.search ||
    upstream.hash
  )
    throw new Error("UPSTREAM_URL must be http://127.0.0.1:<port>/mcp");
  if (typeof password !== "string" || password.length < 32)
    throw new Error("Use an owner password of at least 32 characters");
  const resource = new URL("/mcp", issuer).href;
  const issuerId = issuer.href;
  const passwordHash = Buffer.from(hash(password), "hex");
  let state = { clients: {}, access: {}, refresh: {} };
  try {
    state = JSON.parse(readFileSync(stateFile, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const pending = new Map();
  const codes = new Map();
  function save() {
    for (const type of ["access", "refresh"])
      for (const [key, value] of Object.entries(state[type]))
        if (value.expiresAt <= now()) delete state[type][key];
    mkdirSync(dirname(stateFile), { recursive: true, mode: 0o700 });
    writeFileSync(`${stateFile}.tmp`, JSON.stringify(state), { mode: 0o600 });
    renameSync(`${stateFile}.tmp`, stateFile);
  }
  function validateResource(value) {
    if (value && value.href !== resource)
      throw new InvalidTargetError("Resource must match the MCP URL");
  }
  function validateScopes(scopes = [scope]) {
    if (scopes.some((s) => s !== scope))
      throw new InvalidScopeError("Unsupported scope");
    return scopes.length ? scopes : [scope];
  }
  function getCode(client, code) {
    const value = codes.get(hash(code));
    if (
      !value ||
      value.clientId !== client.client_id ||
      value.expiresAt <= now()
    )
      throw new InvalidGrantError("Invalid or expired authorization code");
    return value;
  }
  function issue(clientId, scopes, family = random()) {
    const accessToken = random();
    const refreshToken = random();
    state.access[hash(accessToken)] = {
      clientId,
      scopes,
      resource,
      family,
      expiresAt: now() + 3600,
    };
    state.refresh[hash(refreshToken)] = {
      clientId,
      scopes,
      resource,
      family,
      expiresAt: now() + 30 * 86400,
    };
    save();
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }
  const provider = {
    clientsStore: {
      getClient: (id) =>
        Object.hasOwn(state.clients, id) ? state.clients[id] : undefined,
      registerClient(client) {
        if (
          !client.redirect_uris?.length ||
          client.redirect_uris.some((uri) => !redirectUris.includes(uri))
        )
          throw new InvalidClientMetadataError("Redirect URI is not allowed");
        if (
          !["none", "client_secret_post", "client_secret_basic"].includes(
            client.token_endpoint_auth_method ?? "client_secret_post",
          )
        )
          throw new InvalidClientMetadataError(
            "Unsupported client authentication",
          );
        validateScopes(client.scope?.split(" "));
        const record = {
          ...client,
          client_id: random(),
          client_id_issued_at: now(),
          client_secret_expires_at: 0,
        };
        state.clients[record.client_id] = record;
        save();
        return record;
      },
    },
    async authorize(client, params, res) {
      validateResource(params.resource);
      const scopes = validateScopes(params.scopes);
      const id = random();
      // Keep only short-lived consent requests and codes in memory.
      for (const map of [pending, codes])
        for (const [key, value] of map)
          if (value.expiresAt <= now()) map.delete(key);
      if (pending.size > 100)
        throw new InvalidGrantError("Too many pending consent requests");
      pending.set(id, {
        clientId: client.client_id,
        ...params,
        scopes,
        expiresAt: now() + 300,
      });
      res.cookie("__Host-xhs-consent", id, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 300000,
      });
      res
        .type("html")
        .send(
          `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect Xiaohongshu</title><main><h1>Connect Xiaohongshu</h1><p>Allow <strong>${escape(client.client_name || "MCP client")}</strong> to use your Xiaohongshu account?</p><p>This grants access to account data and actions including publishing, commenting, likes, and favorites.</p><p>Return address: <code>${escape(params.redirectUri)}</code></p><form method="post" action="/approve"><input type="hidden" name="request" value="${id}"><label>Local owner password <input type="password" name="password" required autocomplete="current-password" autofocus></label><p><button type="submit">Allow access</button></p></form><p>Close this page to cancel.</p></main></html>`,
        );
    },
    async challengeForAuthorizationCode(client, code) {
      return getCode(client, code).codeChallenge;
    },
    async exchangeAuthorizationCode(
      client,
      code,
      _verifier,
      redirectUri,
      requestedResource,
    ) {
      const value = getCode(client, code);
      validateResource(requestedResource);
      if (redirectUri !== value.redirectUri)
        throw new InvalidGrantError("Redirect URI mismatch");
      codes.delete(hash(code));
      return issue(client.client_id, value.scopes);
    },
    async exchangeRefreshToken(client, token, scopes, requestedResource) {
      validateResource(requestedResource);
      const value = state.refresh[hash(token)];
      if (
        !value ||
        value.clientId !== client.client_id ||
        value.expiresAt <= now() ||
        value.resource !== resource
      )
        throw new InvalidGrantError("Invalid or expired refresh token");
      const requestedScopes = scopes ? validateScopes(scopes) : value.scopes;
      if (requestedScopes.some((s) => !value.scopes.includes(s)))
        throw new InvalidScopeError("Cannot increase scopes");
      delete state.refresh[hash(token)];
      return issue(client.client_id, requestedScopes, value.family);
    },
    async verifyAccessToken(token) {
      const value = state.access[hash(token)];
      if (
        !value ||
        value.expiresAt <= now() ||
        value.resource !== resource ||
        !value.scopes.includes(scope)
      )
        throw new InvalidTokenError("Invalid or expired access token");
      return { ...value, token, resource: new URL(value.resource) };
    },
    async revokeToken(client, { token }) {
      const key = hash(token);
      const value = state.access[key] ?? state.refresh[key];
      if (!value || value.clientId !== client.client_id) return;
      for (const type of ["access", "refresh"])
        for (const [id, record] of Object.entries(state[type]))
          if (record.family === value.family) delete state[type][id];
      save();
    },
  };
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.set({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    });
    // Funnel is the only public proxy. Never trust client-supplied forwarding headers.
    if (req.headers.origin && req.headers.origin !== issuer.origin)
      return res.status(403).json({ error: "Untrusted origin" });
    next();
  });
  const authOptions = {
    provider,
    issuerUrl: issuer,
    resourceServerUrl: new URL(resource),
    scopesSupported: [scope],
    resourceName: "Xiaohongshu MCP",
    clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
  };
  const metadata = {
    ...createOAuthMetadata(authOptions),
    authorization_response_iss_parameter_supported: true,
  };
  app.get("/.well-known/oauth-authorization-server", (_req, res) =>
    res.json(metadata),
  );
  // The SDK generates OAuth error redirects too. Add RFC 9207 issuer identity
  // to those responses as well as successful owner approvals.
  app.use("/authorize", (_req, res, next) => {
    const redirect = res.redirect.bind(res);
    res.redirect = (statusOrUrl, target) => {
      const url = new URL(target ?? statusOrUrl);
      if (redirectUris.includes(url.origin + url.pathname))
        url.searchParams.set("iss", issuerId);
      return redirect(
        typeof statusOrUrl === "number" ? statusOrUrl : 302,
        url.href,
      );
    };
    next();
  });
  app.use(mcpAuthRouter(authOptions));
  app.post(
    "/approve",
    rateLimit({
      windowMs: 60000,
      limit: 10,
      standardHeaders: "draft-8",
      legacyHeaders: false,
    }),
    express.urlencoded({ extended: false, limit: "4kb" }),
    (req, res) => {
      const id = req.body.request;
      const consentCookie = req.headers.cookie
        ?.split("; ")
        .find((c) => c.startsWith("__Host-xhs-consent="))
        ?.slice("__Host-xhs-consent=".length);
      const value = pending.get(id);
      if (!value || value.expiresAt <= now() || consentCookie !== id)
        return res
          .status(400)
          .send("Consent expired or invalid. Restart the connection.");
      if (
        typeof req.body.password !== "string" ||
        !timingSafeEqual(
          Buffer.from(hash(req.body.password), "hex"),
          passwordHash,
        )
      )
        return res
          .status(403)
          .send("Incorrect owner password. Go back to retry.");
      pending.delete(id);
      const code = random();
      codes.set(hash(code), { ...value, expiresAt: now() + 60 });
      const callback = new URL(value.redirectUri);
      callback.searchParams.set("code", code);
      callback.searchParams.set("iss", issuerId);
      if (value.state) callback.searchParams.set("state", value.state);
      res.clearCookie("__Host-xhs-consent", {
        path: "/",
        secure: true,
        httpOnly: true,
        sameSite: "lax",
      });
      res.redirect(303, callback.href);
    },
  );
  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.all(
    "/mcp",
    requireBearerAuth({
      verifier: provider,
      requiredScopes: [scope],
      resourceMetadataUrl: new URL(
        "/.well-known/oauth-protected-resource/mcp",
        issuer,
      ).href,
    }),
    (req, res) => {
      // Forward only MCP, never the Go REST API, cookies, or the OAuth bearer token.
      const headers = {
        accept: req.headers.accept || "application/json, text/event-stream",
      };
      for (const key of [
        "content-type",
        "mcp-session-id",
        "mcp-protocol-version",
        "last-event-id",
      ])
        if (req.headers[key]) headers[key] = req.headers[key];
      const proxy = request(
        upstream,
        { method: req.method, headers, timeout: 180000 },
        (response) => {
          res.status(response.statusCode || 502);
          for (const key of [
            "content-type",
            "mcp-session-id",
            "mcp-protocol-version",
            "cache-control",
          ])
            if (response.headers[key])
              res.setHeader(key, response.headers[key]);
          response.pipe(res);
          response.on("error", () => res.destroy());
        },
      );
      proxy.on("timeout", () => proxy.destroy(new Error("Upstream timeout")));
      proxy.on("error", () => {
        if (!res.headersSent)
          res.status(502).json({ error: "Local MCP unavailable" });
        else res.destroy();
      });
      res.on("close", () => proxy.destroy());
      req.pipe(proxy);
    },
  );
  app.use((_req, res) => res.status(404).json({ error: "Not found" }));
  app.use((error, _req, res, _next) => {
    if (!res.headersSent)
      res
        .status(error.status === 413 ? 413 : 500)
        .json({ error: "Request failed" });
  });
  return { app, provider, metadata, resource };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const { app } = createGateway({
    publicUrl: process.env.PUBLIC_URL,
    upstreamUrl: process.env.UPSTREAM_URL || "http://127.0.0.1:18060/mcp",
    password: readFileSync(process.env.OWNER_PASSWORD_FILE, "utf8").trim(),
    stateFile: process.env.OAUTH_STATE_FILE,
  });
  const port = Number(process.env.PORT || 18061);
  app.listen(port, "127.0.0.1", () =>
    console.log(`OAuth MCP gateway listening on 127.0.0.1:${port}`),
  );
}
