# Local OAuth gateway for Xiaohongshu MCP

This optional single-owner gateway exposes only `/mcp` from a loopback Xiaohongshu server. It adds an owner consent page, OAuth discovery, dynamic registration, authorization code with PKCE S256, refresh rotation, and token revocation. Clients and token hashes persist in a file with mode 0600. The owner password is separate from Xiaohongshu login credentials; never enter your Xiaohongshu password here.

Requires Node.js 22+, Python 3, the official Xiaohongshu server binary, and a connected Tailscale client with Funnel permission. The Go MCP server must listen on `127.0.0.1:18060`. The gateway listens on `127.0.0.1:18061`. The backend's REST API and cookies are never proxied. Client bearer tokens are verified here and never forwarded upstream.

## Install on macOS

Run from this directory in a persistent feature worktree:

```sh
npm ci --cache /private/tmp/explore-npm-cache
npm test
python3 install.py --runtime /absolute/path/to/runtime --public-url https://your-device.your-tailnet.ts.net:10000
```

The runtime must contain `bin/xiaohongshu-mcp`. The installer creates two user launch agents in `~/Library/LaunchAgents/`, starts both processes, and restarts them on failure and at user login. Stop any manually started server on port 18060 first. The generated owner password is in `RUNTIME/oauth/owner-password.txt`; OAuth state and client secrets are in `RUNTIME/oauth/state.json`. Keep this directory outside Git. Reinstallation preserves passwords and OAuth registrations. Retain the worktree while the service is installed.

Inspect existing routes before enabling the dedicated Funnel port. Do not change a port used by another service:

```sh
tailscale funnel status
tailscale funnel --bg --https=10000 http://127.0.0.1:18061
tailscale funnel status
```

Funnel makes the gateway public. Every MCP request requires a valid OAuth token. Only public health/discovery, client registration, and the consent page are unauthenticated. The default redirect allowlist is exactly `https://chatgpt.com/connector_platform_oauth_redirect`. The authorization server advertises RFC 9207 issuer identification and returns `iss` on success and error redirects, enabling ChatGPT's stable callback. Dynamic clients remain registered across restarts; refresh tokens expire after 30 days, and access tokens after one hour. Revoking a token invalidates its complete token family.

This is a personal, single-owner gateway. It does not isolate multiple Xiaohongshu accounts or offer organization identity management. Use a managed identity provider for a shared deployment.

## Add the custom server

In ChatGPT's **Add custom MCP server** form:

- Name: `Xiaohongshu`
- Connection: **Server URL**
- URL: `https://your-device.your-tailnet.ts.net:10000/mcp`
- Authentication: **OAuth**
- Advanced OAuth: use discovered endpoints and dynamic client registration (DCR); leave client ID and secret blank; scope `xiaohongshu`.

Create and install the plugin. When prompted, enter the owner password from the local file and approve access. The form's **Tunnel** option accepts an OpenAI Secure MCP Tunnel ID, not a Tailscale URL.

Xiaohongshu login is independent. Use the official login executable from the same runtime directory, or the MCP login QR tool, then verify `check_login_status`. Start with a read-only call before using publishing tools.

## Verify and stop

```sh
curl -i https://your-device.your-tailnet.ts.net:10000/mcp
# Expected: 401 with WWW-Authenticate and resource metadata URL.
curl https://your-device.your-tailnet.ts.net:10000/.well-known/oauth-protected-resource/mcp
curl https://your-device.your-tailnet.ts.net:10000/.well-known/oauth-authorization-server
launchctl print gui/$(id -u)/com.owlinlight.explore.xiaohongshu-mcp
launchctl print gui/$(id -u)/com.owlinlight.explore.xiaohongshu-oauth
```

Tests exercise consent, CSRF rejection, password rejection, redirect restrictions, wrong resource/scope, PKCE failure, code replay, refresh client binding and rotation, persistent state, revocation, and proxy header/session handling. They use a local mock upstream and do not contact Xiaohongshu or perform account actions.

For an authenticated public smoke check, run from this directory:

```sh
PUBLIC_URL=https://your-device.your-tailnet.ts.net:10000 \
OWNER_PASSWORD_FILE=/absolute/path/to/runtime/oauth/owner-password.txt \
npm run verify-public
```

This registers a verification client, completes owner consent and PKCE, initializes MCP, lists tools, checks login status, and revokes its test tokens. It performs no content writes. To force traffic through a public Funnel relay instead of tailnet DNS, set `FUNNEL_RELAY_IP` to an IPv4 address returned by `dig @1.1.1.1 +short your-device.your-tailnet.ts.net A`. Set `VERIFICATION_REPORT_FILE` to save a JSON report without OAuth credentials. The report may contain the account name if already logged in; review it before sharing.

Remove only this Funnel port and these two services:

```sh
tailscale funnel --https=10000 off
launchctl bootout gui/$(id -u)/com.owlinlight.explore.xiaohongshu-oauth
launchctl bootout gui/$(id -u)/com.owlinlight.explore.xiaohongshu-mcp
rm ~/Library/LaunchAgents/com.owlinlight.explore.xiaohongshu-oauth.plist
rm ~/Library/LaunchAgents/com.owlinlight.explore.xiaohongshu-mcp.plist
```

Deleting `RUNTIME/oauth/state.json` while the gateway is stopped revokes all clients and tokens; recreate the ChatGPT connection afterward. Rotating only the owner password does not revoke previously granted tokens. Keep cookies and passwords out of logs, commits, screenshots, and PRs.
