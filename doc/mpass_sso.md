# mPass SSO (oauth2-proxy ForwardAuth)

How this fork authenticates on the Moneta FOSS platform, and what a deployment has to
guarantee for it to be safe.

Activated by `AUTH_TYPE=SSO`. Unset, every path below is inert and Chatwoot behaves
exactly like upstream — local login, signup and password reset all work as shipped.

## What it replaces

Chatwoot never talks to the identity provider. Traefik asks oauth2-proxy whether each
request carries a valid session; if it doesn't, the browser goes through the mPass QR
login and comes back. Requests that reach Chatwoot carry the user's identity in
`X-Auth-Request-*` headers, and this integration logs that user in.

The app's native OIDC/SAML support is deliberately **not** used. The platform relies on
the header contract only.

```text
browser ──> traefik ──(ForwardAuth)──> oauth2-proxy ──> mpass-auth-proxy ──> Cognito
               │                            │
               │                            └─ no session: 302 to the mPass QR page
               │
               └─ valid session: request + X-Auth-Request-* headers ──> chatwoot
```

## Configuration

| Variable | Meaning |
|---|---|
| `AUTH_TYPE` | `SSO` turns the integration on. Anything else leaves upstream behaviour untouched |
| `DEFAULT_EMAIL_DOMAIN` | Domain used to synthesise an address from a bare mPass id. Required: unset, every bare-id login is refused. **Must be identical on every app in the bundle**, or the same Cognito principal becomes a different user row per app |
| `FRONTEND_URL` | The https origin the browser sees. The handoff builds its redirect from it |
| `LOGOUT_REDIRECT_URL` | Where the app's Sign out navigates: the platform portal. Must be an absolute `http(s)` URL; missing or invalid, Sign out logs an error and does nothing. Not upstream's `LOGOUT_REDIRECT_LINK`, which is read from the database only and also drives the 401 re-auth path |
| `SESSION_COOKIE_MAX_AGE_SECONDS` | devise_token_auth token lifespan, so Chatwoot expires with the rest of the bundle. Unset or not a positive integer: upstream's 2-month default (`config/initializers/devise_token_auth.rb`) |
| `SMB_CORPORATE_ID` | Optional. When set, only principals of that corporate are admitted; see [Corporate-tenant gate](#corporate-tenant-gate) |
| `CHATWOOT_SMB_DEFAULT_ACCOUNT_ID` | Optional. The account every SSO user joins as `agent`. Unset: the oldest active account. Set to an id that doesn't exist: nobody is joined |
| `ENABLE_ACCOUNT_SIGNUP` | Keep `false`. `POST /api/v1/accounts` is 404 under SSO anyway |
| `GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` | Leave unset. The callbacks are 404 under SSO; unset is defence in depth |

## Why trusting the headers is safe

`lib/mpass/proxy_identity.rb` reads `X-Auth-Request-Email` without verifying it. That is
only sound while all three of these hold:

1. Chatwoot's port is never published — traffic can arrive only through Traefik.
2. Traefik's `strip-auth-headers` middleware deletes any client-supplied
   `X-Auth-Request-*` header **before** `mpass-auth` re-adds the verified values.
3. oauth2-proxy validates the upstream OIDC session on every ForwardAuth call.

If any one stops holding, every reader of these headers becomes a spoofing vector. The
`AUTH_TYPE` gate is the last line of defence: with it unset, the handoff controller
answers `404` no matter what headers arrive.

Deployment requirements that follow from this:

- No `ports:` on the Chatwoot service.
- Every protected router carries `strip-auth-headers`, then `security-headers`, then
  `mpass-auth` — in that order.
- Bypass routers (no `mpass-auth`) still carry `strip-auth-headers`, so a request that
  skips authentication can never assert an identity either. The list is
  [below](#forwardauth-bypass-list).

## ForwardAuth bypass list

This is the source of truth for the `chatwoot-bypass` routers;
`docker/mpass/docker-compose.devkit.yml` implements it. Everything not listed stays on
the protected router, including all of `/api/v1/accounts/*` (the agent-facing webhook
CRUD at `/api/v1/accounts/:id/webhooks` among it) and `/audio/dashboard/`.

Chatwoot is the only bundle app that serves people who have no mPass account: website
visitors using the chat widget, and customers opening help-center or survey links. Behind
`mpass-auth` they would get a QR page they cannot scan, so those surfaces bypass it.

**Bypassed, any method:**

| Path | Why |
|---|---|
| `Path(/health)` | Container health probe |
| `PathPrefix(/packs/)`, `/vite/`, `/assets/` | Precompiled assets, fetched without a session (the widget loads them too) |
| `PathPrefix(/widget)` | The widget iframe on customer websites. Its router drops `security-headers@docker`, whose `X-Frame-Options: SAMEORIGIN` would stop it loading; the rest of the header set is re-added. The help-center plain layout needs the same treatment; see the GET/HEAD table |
| `PathPrefix(/api/v1/widget)` | The widget's API. Authenticated by the widget's own website token and contact JWT, never by a user session |
| `PathPrefix(/public/api/)` | Public inbox API and the CSAT survey's data, authenticated by per-inbox/per-conversation identifiers |
| `Path(/cable)` | ActionCable. The widget's live updates use it, so behind `mpass-auth` agent replies never reach the bubble. **Trade-off:** the endpoint is shared with the dashboard, so an agent's WebSocket handshake is no longer checked against SSO. Each subscription still needs the user's secret `pubsub_token` (`RoomChannel`), which is upstream's only guard, so a leaked agent token would stream that account's events without an SSO session. ForwardAuth only ever checked the handshake, so an open socket already outlived "Log out of all apps" before this |

**Bypassed, `GET`/`HEAD` only:**

| Path | Why |
|---|---|
| `PathPrefix(/audio/widget/)` | The widget's new-message sound (static mp3) |
| `PathPrefix(/hc/)` | Public help center; the widget also fetches its articles. Every route is a read |
| `PathPrefix(/hc/)` + `Query(show_plain_layout, true)` | Help-center articles the widget opens in an iframe on customer sites (`ArticleContainer.vue`). Chatwoot drops `X-Frame-Options` only for this layout (`Public::Api::V1::Portals::BaseController#allow_iframe_requests`), so this router uses the widget's header set without `security-headers` and Traefik does not put it back. Its priority sits above the `/hc/` router; every other `/hc/` page keeps `SAMEORIGIN` |
| `PathPrefix(/survey/responses/)` | CSAT page emailed to customers; a page shell whose data comes from `/public/api/` |

**Channel inbound callbacks: not bypassed by default.** A provider cannot hold an mPass
session, so a channel's inbound path must be bypassed for that channel to work. Bypass only
the channels a deployment enables, each with an exact `Path`/`PathRegexp` and method, and
only where Chatwoot verifies the caller:

| Route | Caller verification in Chatwoot | Bypass when enabled? |
|---|---|---|
| `POST /webhooks/whatsapp/:phone_number`, `GET` (verify) | Meta `X-Hub-Signature-256`, always required | Yes |
| `POST /webhooks/instagram`, `GET` (verify) | Meta signature, always required | Yes |
| `/bot` (Facebook Messenger) | Messenger signature against the page's app secret or `FB_APP_SECRET` | Yes, with `FB_APP_SECRET` set |
| `POST /webhooks/tiktok` | `Tiktok-Signature` HMAC | Yes |
| `POST /webhooks/shopify` | `X-Shopify-Hmac-SHA256`; 401 without `SHOPIFY_CLIENT_SECRET` | Yes |
| `POST /webhooks/line/:line_channel_id` | `x-line-signature`, checked in `Webhooks::LineEventsJob` (the request itself is accepted and queued) | Yes, accepting that unsigned requests still enqueue a job |
| `POST /api/v1/integrations/webhooks` (Slack) | Slack signature, **skipped when `SLACK_SIGNING_SECRET` is blank** | Only with `SLACK_SIGNING_SECRET` set |
| `GET`/`POST /webhooks/twitter` | CRC only on `GET`; events are not signature-checked | No |
| `POST /webhooks/sms/:phone_number` | None | No, unless the risk is accepted in writing |
| `POST /webhooks/telegram/:bot_token` | Only the secret in the path | No, unless the risk is accepted in writing |
| `/twilio/callback`, `/twilio/delivery_status`, EE `/twilio/voice/*` | None (no `X-Twilio-Signature` check) | No, unless the risk is accepted in writing |
| `POST /rails/action_mailbox/:service/inbound_emails` (email inboxes) | Action Mailbox ingress: HTTP basic auth with `RAILS_INBOUND_EMAIL_PASSWORD` (relay), or the provider's signing key (Mailgun, Mandrill, …) | Yes for the configured ingress only, with its password or key set |
| `/enterprise/webhooks/stripe`, `/enterprise/webhooks/firecrawl` (EE) | Provider signatures | Only if the feature is used; exact `Path` |

Never bypass a `/webhooks` prefix: it would also expose the channels that verify nothing.

**Still gated, known breakage:** `/rails/active_storage/*`, so agent avatars and
attachments don't load in the widget. Bypassing it matches stock Chatwoot, but blob links
don't expire by default, so a leaked link to an agent-only attachment would work without a
login. Decide it with link expiry, not by path.

## Login

Chatwoot's credential is a devise_token_auth triple that the SPA persists into the
JS-readable `cw_d_session_info` cookie and replays as request headers. The server cannot
mint it in-band, so login is a redirect handoff rather than a server-side session write.

1. A browser reaches any dashboard document with an asserted identity and no session.
   `DashboardController#reconcile_mpass_identity` redirects to `/auth/sso/proxy-login`.
   Without this step first login dead-ends: the user would be served Chatwoot's own
   login form, which under SSO accepts nothing.
2. `Sso::ProxyLoginController#create` resolves or provisions the user, mints the same
   5-minute single-use `sso_auth_token` the SAML and impersonation paths use
   (`SsoAuthenticatable`), and redirects to `/app/login?email=…&sso_auth_token=…`.
3. The existing SPA login route consumes it: `v3/helpers/RouteHelper.js` clears any
   previous user's session cookie, `v3/views/login/Index.vue` auto-submits, and
   `DeviseOverrides::SessionsController` issues the devise_token_auth headers.

No new credential machinery, and no new client code for the happy path.

Two loop guards on step 1, both load-bearing: the handoff's landing page carries
`sso_auth_token` and its failure landing carries `error`, and re-entering the handoff on
either would bounce the browser until it gave up.

## Corporate-tenant gate

ForwardAuth admits every principal in the Cognito pool. When `SMB_CORPORATE_ID` is set,
`Mpass::ProxyIdentity.corporate_claims_ok?` decodes `X-Auth-Request-Access-Token` (second
JWT segment, base64url, no signature check: it rides the same trust chain as the identity
header) and requires both `custom:is_corporate == "true"` and
`custom:corporate_id == SMB_CORPORATE_ID`. A missing or undecodable token fails the check.
Unset, the check is skipped.

- **Handoff:** `Sso::ProxyLoginController` answers `403` before the user builder runs, so
  a refused principal leaves no user row, and it clears the SPA cookie.
- **Every request after it:** a session whose principal now fails the check is treated as
  a mismatch and flushed on both reconciliation paths (below), and the handoff then refuses
  it. So a revoked corporate membership is enforced on the next request, not only at the
  next login.

This matters more on Chatwoot than elsewhere: an auto-provisioned `agent` can read
end-customer conversations.

## Identity and provisioning

`lib/mpass/proxy_identity.rb`:

- `X-Auth-Request-Email` is the only identity source. `X-Auth-Request-User` (the Cognito
  `sub`) is never used as a fallback. The value is stripped and downcased, and the same normalisation is applied to the DB lookup.
- A value with an `@` (not first) followed at least one character later by a `.` is used
  as is; anything else, including `a@b`, is a bare value and becomes
  `<value>@${DEFAULT_EMAIL_DOMAIN}`. Moneta's Cognito pool returns the literal
  placeholder `cognito:default_val` for the email claim, so identity usually arrives as
  a bare numeric `cognito:username`.
- Email-shape detection is `indexOf`-based, never a regex — the canonical email pattern
  backtracks polynomially on adversarial input (CodeQL `js/polynomial-redos`).
- Display name prefers `X-Auth-Request-Preferred-Username` when the local part is a bare
  number, and never persists a `sub` UUID.

`app/builders/mpass_user_builder.rb` resolves or creates the user (`User.from_email`,
exact match — never `LIKE`). On **every** login, not only at creation, a user with no
account membership at all is joined at role `agent` to `CHATWOOT_SMB_DEFAULT_ACCOUNT_ID`,
or to the oldest active account when that's unset. No account yet: nobody is joined.

A user who already belongs to any account is left alone, so an admin removing an agent
from one account is not undone while they keep another. **Removing an agent's last
membership is undone on their next login**: with no rows left they are joined again. To
revoke access, remove the user in mPass (or exclude them with `SMB_CORPORATE_ID`), not the
membership.

Two deliberate differences from `SamlUserBuilder`:

- **No multi-account rejection.** A user legitimately spans accounts.
- **No role mapping.** mPass asserts identity only; elevation is an in-app action.
  `agent` also keeps SSO users out of the administrator-only onboarding wizard — the
  coupling is invisible from the Ruby side, so it is pinned by
  `spec/requests/sso/onboarding_interlock_spec.rb`.

Concurrent first-request races rescue both `RecordNotUnique` and `RecordInvalid` and fall
back to a plain read, re-raising if the row is still absent.

## Session-identity reconciliation

When the browser holds a session for user A but the proxy asserts user B, the stale
session must be flushed before anything else happens. `MpassSessionReconciliation`
defines "mismatch" once, and two paths act on it, because the credential is client-held:

| Path | Where | How |
|---|---|---|
| Document requests | `DashboardController` | Redirect through the handoff, which re-mints for B. The SPA clears the previous cookie on arrival |
| XHR | `Api::BaseController` | Cannot be redirected: evict this client's token, set `X-Mpass-Session-Flushed`, answer 401. `dashboard/helper/APIHelper.js` hard-navigates on that header |

Two properties worth keeping:

- **Header absence is never a mismatch.** Sidekiq, health probes and direct container
  hits legitimately carry no header and must not be logged out.
- **The SPA keys on the flush header, not the bare 401.** Chatwoot answers 401 for
  ordinary permission denials too, and reacting to those would log an agent out for
  opening an admin-only screen.

The XHR flush never fires for requests authenticated by an `api_access_token`: platform
and bot integrations have no user session to flush, and evicting their credential because
a browser elsewhere switched users would break unrelated integrations.

## Local-credential surfaces under SSO

Cognito owns identity, so every path that creates or changes a local credential is closed
server-side. Hiding the UI is not a control — these endpoints answer curl regardless of
what the SPA renders, and `DISABLE_USER_PROFILE_UPDATE` is honoured only by the frontend.

| Endpoint | Under `AUTH_TYPE=SSO` |
|---|---|
| `POST /auth/sign_in` without an `sso_auth_token` (password or MFA) | `404` |
| `POST`/`PUT` `/auth/password` | `404` — the `PUT` also returned a live session, a complete credential path around mPass |
| `GET`/`POST /auth/confirmation`, `POST /resend_confirmation` | `404` |
| `POST /api/v1/accounts` (self-registration) | `404` |
| `PUT /api/v1/profile` password change | rejected |
| `PUT /api/v1/profile` `email` | dropped from the permitted params — changing it breaks the header lookup and locks the user out |
| `POST`/`PUT`/`PATCH`/`DELETE /auth` (devise_token_auth registrations) | `404` — `PUT` set a password without the current one, `POST` signed up, `DELETE` deleted the account |
| `/auth/:provider/callback`, `/omniauth/:provider/callback`, `/auth/failure`, `/omniauth/failure` (Google OAuth, SAML) | `404` — a second identity path |
| `POST /api/v1/auth/saml_login` (EE) | `404` |
| `/super_admin/*`, `/monitoring/sidekiq` | **not routed** — the super-admin password login and the Devise defaults mounted beside it (password reset, sign-up, confirmation) |

`404` rather than `403`: under SSO these endpoints do not conceptually exist, and a `403`
would confirm the route is there to probe further. The gate lives in
`MpassLocalAuthGuard`; `reject_local_login_under_sso` is the login-specific variant that
lets the handoff's own POST through. The super-admin console is removed with a route
constraint instead, checked per request.
`spec/requests/sso/local_auth_route_inventory_spec.rb` fails CI when a controller behind an
auth route lacks the guard.

**No super-admin console under SSO.** It had its own password login outside mPass.
Operators use `rails console` for what it did (see [Operations](#operations)).

Client side, `v3/helpers/ssoRouteGuard.js` hard-redirects the signup, password-reset and
confirmation routes, the login page renders "Continue with mPass" instead of the local
form, and the profile screen hides the email field, the password section and MFA
enrolment.

## Logout

Per-app Sign out is **navigation-only**: it clears local client state and navigates to
`LOGOUT_REDIRECT_URL`. If that is missing or not an absolute `http(s)` URL it logs an error
and does nothing: falling back to `/` would re-enter the handoff and sign the user straight
back in. It does not call `DELETE /auth/sign_out` and does not end the SSO
session — the next request would re-establish one from the identity header anyway, so the
call only added a failure mode. Ending the session is the portal's "Log out of all apps",
which clears the shared oauth2-proxy cookie.

Stock Chatwoot still issues the sign-out request: without SSO the devise token *is* the
session, and skipping it would leave it valid for its full lifespan.

## Tests

```bash
bundle exec rspec spec/lib/mpass spec/builders/mpass_user_builder_spec.rb spec/requests/sso
pnpm vitest run app/javascript/v3/helpers/specs/ssoRouteGuard.spec.js \
                app/javascript/dashboard/routes/index.spec.js
```

`spec/requests/sso/` carries the platform's six mandatory reconciliation tests plus the
app-specific guards: the `AUTH_TYPE≠SSO` 404, SQL-wildcard literals, the creation race,
hostile `cw_d_session_info` payloads, and the local-credential endpoint gates in both
directions (gated under SSO, untouched without it).

## Known deviations and open items

- **`cw_d_session_info` cannot be `httpOnly`.** The SPA has to read it to build its
  request headers. `secure` is derived from the page's scheme and `sameSite: Lax` is set
  globally; the cookie carries a token whose lifetime is `SESSION_COOKIE_MAX_AGE_SECONDS`. This is
  architectural, not fixable here, and is recorded as a written tradeoff rather than a
  silent gap.
- **Platform API login links** (`/platform/api/v1/users/:id/login`) stay open: machine to
  machine, and a Platform app can already read the user's access token.

## Operations

What the bundle needs to run this fork.

**Image.** Built from `docker/Dockerfile` for the bundle's hosts:

```bash
docker buildx build --platform linux/amd64 -f docker/Dockerfile -t <registry>/chatwoot:<tag> --push .
```

Assets are precompiled into the image, so every frontend change needs a rebuild.

**Processes.** One image, two services with the same environment:

| Service | Command | Network |
|---|---|---|
| web | `bundle exec rails s -p 3000 -b 0.0.0.0` | frontend and backend; Traefik routes to port 3000; never publish the port |
| worker | `bundle exec sidekiq -C config/sidekiq.yml` | backend only; no Traefik router |

**Health check:** `GET /health` (on the bypass list).

**Dependencies.**

- PostgreSQL 16 with the `pgvector` extension (`enable_extension "vector"` in
  `db/schema.rb`); the devkit uses `pgvector/pgvector:pg16`. `POSTGRES_HOST`, `_PORT`,
  `_DATABASE`, `_USERNAME`, `_PASSWORD`.
- Redis (`REDIS_URL`), for Sidekiq, ActionCable and the handoff's one-time tokens. In the
  bundle, use a Valkey DB number the edge doesn't use (8 and 10 are taken).
- `SECRET_KEY_BASE`, `FRONTEND_URL` (the https origin), `FORCE_SSL=false` (TLS ends at
  Traefik), `RAILS_ENV=production`, `INSTALLATION_ENV=docker`.

**First-run bootstrap.** Chatwoot's first-visitor onboarding form is `404` under SSO (it
would make the first mPass visitor a super admin with a local password), so bootstrap is a
deployment step. Run it before the web process starts; it is idempotent:

```bash
bundle exec rails db:chatwoot_prepare
bundle exec rails runner 'Account.exists? || Account.create!(name: "<SMB name>"); Redis::Alfred.delete(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING)'
```

Set `CHATWOOT_SMB_DEFAULT_ACCOUNT_ID` to that account's id to pin auto-join to it.

**Promote an administrator.** Auto-join only ever grants `agent`. The user must have
logged in once through mPass:

```bash
bundle exec rails runner '
  user = User.from_email("<email>") or abort "log in through mPass first"
  AccountUser.find_by!(user: user, account_id: <account id>).administrator!'
```

`agent!` demotes. The super-admin console isn't available under SSO; use `rails console`
for installation config, accounts and users.

**Smoke test:** [`docs/chatwoot-smoke-test.md`](../docs/chatwoot-smoke-test.md).
