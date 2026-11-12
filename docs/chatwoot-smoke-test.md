# Chatwoot smoke test (mPass SSO)

> **Draft.** Built from the mpass-sso-devkit README "Test your app" list and the
> sso-rules-moneta devkit e2e checks. Replace the table with the onboarding guide §8.4 table
> once it is available.

Run after every deploy, and after any change to the SSO code. `HOST` is Chatwoot's host,
`PORTAL` the platform portal. Use a private window, and keep
`https://whoami.<platform domain>` open to see the raw headers the edge sends.

Setup: `AUTH_TYPE=SSO`, `DEFAULT_EMAIL_DOMAIN` set, `MPASS_EDGE_SECRET` set (at least 32 characters, the
same value the `chatwoot-edge-secret` Traefik middleware injects), `LOGOUT_REDIRECT_URL=https://PORTAL`,
bootstrap done (one account, onboarding flag cleared; see `doc/mpass_sso.md` §Operations).

## With a browser

| # | Step | Pass |
|---|---|---|
| 1 | Open `https://HOST` directly | QR page; after scanning, the dashboard as your mPass identity. No login form, setup wizard or admin-creation form |
| 2 | Check the new user (`rails runner 'u = User.from_email("<email>"); p u.name, u.account_users.map { [_1.account_id, _1.role] }'`) | One row, in `CHATWOOT_SMB_DEFAULT_ACCOUNT_ID` (or the oldest account), role `agent`. The name is not a UUID |
| 3 | Open `https://HOST` again in a new tab | Dashboard, no login page |
| 4 | Profile settings | No email field, password section or MFA enrolment |
| 5 | Sign out from the avatar menu | Lands on `https://PORTAL`; no `DELETE /auth/sign_out` in the web logs. Opening `HOST` again logs you straight back in |
| 6 | Portal "Log out of all apps", then reload `HOST` | QR page |
| 7 | Log in as user A, "Log out of all apps", log in as user B, reload the open Chatwoot tab | Served as B, never A. Repeat with a conversation open (XHR path) |
| 8 | Log in again as the same user, then re-run step 2 | Still one user row and one membership |
| 9 | Open the widget on a test page (or `https://HOST/widget?website_token=<token>`) without an mPass session; send a message and reply from the dashboard. The replying agent must be a member of the website inbox: an agent only sees an inbox's conversations once added to it | Widget loads, the reply arrives live, the sound plays |

## With curl

`$C` is the `_oauth2_proxy` cookie from the browser's developer tools.

| # | Request | Pass |
|---|---|---|
| 10 | `curl -skI https://HOST/app` (no cookie) | `302` to the mPass login |
| 11 | `curl -skI -H 'X-Auth-Request-Email: someone-else@example.com' https://HOST/app` | `302` to the mPass login, not a session |
| 12 | `curl -sk -b "_oauth2_proxy=$C" -H 'X-Auth-Request-Email: someone-else@example.com' https://whoami.<domain>/ \| grep X-Auth-Request-Email` | Your own identity, not the spoofed one |
| 13 | `curl -sko /dev/null -w '%{http_code}\n' https://HOST/health` | `200` without a session |
| 14 | Each bypassed path in `doc/mpass_sso.md` §ForwardAuth bypass list, without a cookie | Reaches Chatwoot (no redirect to mPass); the `GET`-only ones refuse `POST` with a redirect to mPass |
| 15 | `curl -skI https://HOST/api/v1/accounts/1/webhooks` and `https://HOST/audio/dashboard/` without a cookie | `302` to the mPass login (not bypassed) |
| 16 | With `-b "_oauth2_proxy=$C"`: `POST /auth/sign_in` with an email and password; `POST`/`PUT /auth/password`; `PUT`/`POST`/`DELETE /auth`; `POST /resend_confirmation`; `POST /api/v1/accounts`; `GET /omniauth/google_oauth2/callback`; `POST /api/v1/auth/saml_login`; `POST /installation/onboarding` | `404` for every one, except `GET /omniauth/google_oauth2/callback`: no session, as `302` to `/auth/sign_in` or `404` (the OmniAuth middleware fails before the callback controller runs) |
| 17 | With `-b "_oauth2_proxy=$C"`: `GET /super_admin/sign_in`, `GET /monitoring/sidekiq` | `404` |
| 18 | `curl -skI https://HOST/app` with the cookie | `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` present |

## Configuration failures

| # | Change, then `docker compose up -d` the web service | Pass |
|---|---|---|
| 19 | Unset `DEFAULT_EMAIL_DOMAIN` (the devkit sends a bare mPass id) and open `HOST` | Login refused (`/app/login?error=sso_failed`); no user row with a made-up address |
| 20 | Set `SMB_CORPORATE_ID` to a value your account doesn't have (on the app only, not in the edge's `.env`), with `MPASS_COGNITO_ISSUER_URL` and `MPASS_OIDC_CLIENT_ID` set | `403` at `/auth/sso/proxy-login`, no new user row, and `reason=wrong_organization` (or `not_corporate`) in the web log: the token's signature, issuer and audience passed. An already-open dashboard is flushed on its next request |
| 21 | Set `SMB_CORPORATE_ID` to your account's corporate id | Login works |
| 22 | Unset `LOGOUT_REDIRECT_URL`, then Sign out. The devkit compose always sets it, so override it to empty for the `chatwoot` service (e.g. `LOGOUT_REDIRECT_URL: ''` in an extra `-f` override file); empty counts as unset | Nothing happens and the browser console logs an error; you are not signed back in through `/` |

| 23 | Set `MPASS_EDGE_SECRET` shorter than 32 characters | Boot logs an error naming `MPASS_EDGE_SECRET`; opening `HOST` ends at `/app/login?error=sso_failed` |

## Edge trust (from a container on the backend network)

Chatwoot's port is reachable from every container on the backend network; only requests carrying the edge
secret may assert an identity. Run from a sibling container, e.g.
`docker run --rm --network <backend network> curlimages/curl ...`, with
`-H 'Host: HOST' -H 'X-Forwarded-Proto: https'`.

| # | Request to `http://chatwoot:3000` | Pass |
|---|---|---|
| 24 | `GET /auth/sso/proxy-login` with `X-Auth-Request-Email: someone@example.com` and no `X-Mpass-Edge-Secret`, then again with a wrong one | `302` to `/app/login?error=sso_failed`, no user row; the web log shows `mPass identity headers ignored ... mpass_id=... path=... remote_addr=...` with no email in it |
| 25 | `GET /api/v1/accounts/<id>/conversations` with `api_access_token` and a forged `X-Auth-Request-Email` | `200`; the token is unaffected |
| 26 | With `SMB_CORPORATE_ID` set and the right edge secret: an `alg: none` or HS256 token carrying the right corporate claims in `X-Auth-Request-Access-Token` | `403`, `reason=wrong_algorithm` in the log |

Put every setting back afterwards.
