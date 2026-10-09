// audit row 15 — under SSO, Cognito owns identity. Each route below offers a way to
// create or change a LOCAL credential, which desynchronises the user from the
// identity X-Auth-Request-Email asserts and locks them out on the next request.
//
// Hard-redirect rather than hide: a merely hidden route is still reachable by URL,
// and the contract requires each surface to "hide or hard-redirect".
//
// `login` is deliberately absent. The ForwardAuth handoff lands on it carrying
// email + sso_auth_token, and RouteHelper's validateSSOLoginParams() must keep
// seeing it to clear the previous user's cookie (design.md §2). Blocking it would
// break login entirely — the regression guard lives in specs/ssoRouteGuard.spec.js
// and in the upstream RouteHelper.spec.js case at :21.
import { isSSOMode } from 'shared/helpers/ssoMode';

export const SSO_BLOCKED_ROUTE_NAMES = [
  'auth_signup',
  'auth_reset_password',
  'auth_password_edit',
  'auth_confirmation',
  'auth_verify_email',
];

export const isSSOBlockedRoute = to =>
  isSSOMode() && SSO_BLOCKED_ROUTE_NAMES.includes(to?.name);
