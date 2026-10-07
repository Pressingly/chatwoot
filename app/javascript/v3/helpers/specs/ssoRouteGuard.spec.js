import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { isSSOBlockedRoute, SSO_BLOCKED_ROUTE_NAMES } from '../ssoRouteGuard';

describe('#isSSOBlockedRoute', () => {
  const original = window.globalConfig;
  beforeEach(() => {
    window.globalConfig = { AUTH_TYPE: 'SSO' };
  });
  afterEach(() => {
    window.globalConfig = original;
  });

  it.each(SSO_BLOCKED_ROUTE_NAMES)(
    'blocks the local-credential route %s under SSO',
    name => {
      expect(isSSOBlockedRoute({ name })).toBe(true);
    }
  );

  // Load-bearing: the ForwardAuth handoff lands on `login` carrying
  // email + sso_auth_token. Blocking it would break login entirely.
  it('NEVER blocks the login route', () => {
    expect(isSSOBlockedRoute({ name: 'login' })).toBe(false);
  });

  it('leaves ordinary routes alone', () => {
    expect(isSSOBlockedRoute({ name: 'home' })).toBe(false);
  });

  it('blocks nothing when AUTH_TYPE is not SSO', () => {
    window.globalConfig = { AUTH_TYPE: '' };
    SSO_BLOCKED_ROUTE_NAMES.forEach(name => {
      expect(isSSOBlockedRoute({ name })).toBe(false);
    });
  });

  it('blocks nothing when globalConfig is absent', () => {
    window.globalConfig = undefined;
    expect(isSSOBlockedRoute({ name: 'auth_signup' })).toBe(false);
  });

  it('tolerates an undefined route', () => {
    expect(isSSOBlockedRoute(undefined)).toBe(false);
  });
});
