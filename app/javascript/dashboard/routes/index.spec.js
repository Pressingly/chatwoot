import { validateAuthenticateRoutePermission } from './index';
import store from '../store'; // This import will be mocked
import { vi } from 'vitest';

// Mock the store module
vi.mock('../store', () => ({
  default: {
    getters: {
      isLoggedIn: false,
      getCurrentUser: {
        account_id: null,
        id: null,
        accounts: [],
      },
      'accounts/getAccount': () => ({}),
    },
    dispatch: vi.fn(() => Promise.resolve()),
  },
}));

describe('#validateAuthenticateRoutePermission', () => {
  let next;

  beforeEach(() => {
    next = vi.fn(); // Mock the next function
  });

  describe('when user is not logged in', () => {
    it('should redirect to login', () => {
      const to = { name: 'some-protected-route', params: { accountId: 1 } };

      // Mock the store to simulate user not logged in
      store.getters.isLoggedIn = false;

      // Mock window.location.assign
      const mockAssign = vi.fn();
      delete window.location;
      window.location = { assign: mockAssign };

      validateAuthenticateRoutePermission(to, next);

      expect(mockAssign).toHaveBeenCalledWith('/app/login');
    });
  });

  describe('when user is logged in', () => {
    beforeEach(() => {
      // Mock the store's getter for a logged-in user
      store.getters.isLoggedIn = true;
      store.getters.getCurrentUser = {
        account_id: 1,
        id: 1,
        accounts: [
          {
            id: 1,
            role: 'agent',
            permissions: ['agent'],
            status: 'active',
          },
        ],
      };
    });

    describe('when route is not accessible to current user', () => {
      it('should redirect to dashboard', async () => {
        const to = {
          name: 'general_settings_index',
          params: { accountId: 1 },
          meta: { permissions: ['administrator'] },
        };

        await validateAuthenticateRoutePermission(to, next);

        expect(next).toHaveBeenCalledWith('/app/accounts/1/dashboard');
      });
    });

    describe('when route is accessible to current user', () => {
      beforeEach(() => {
        // Adjust store getters to reflect the user has admin permissions
        store.getters.getCurrentUser = {
          account_id: 1,
          id: 1,
          accounts: [
            {
              id: 1,
              role: 'administrator',
              permissions: ['administrator'],
              status: 'active',
            },
          ],
        };
      });

      it('should go to the intended route', async () => {
        const to = {
          name: 'general_settings_index',
          params: { accountId: 1 },
          meta: { permissions: ['administrator'] },
        };

        await validateAuthenticateRoutePermission(to, next);

        expect(next).toHaveBeenCalledWith();
      });
    });
  });
});

// workspace-auto-join/spec.md "auto-join SHALL mark onboarding complete on the user
// profile" has no direct analogue in Chatwoot — `User` carries no onboarding state.
// Its PURPOSE still applies: an SSO-provisioned user must land in the app, not be
// trapped in a setup wizard.
//
// It is satisfied structurally by a sibling requirement. The onboarding redirect in
// ./index.js fires only when role === 'administrator', and auto-join assigns
// `agent` because the spec's regular-member rule demands it. So the wizard cannot
// capture an mPass user.
//
// Pinned here because that coupling is INVISIBLE from the Ruby side that assigns
// the role. A reasonable-sounding "make SSO users administrators" change would
// silently reintroduce the trap, and the symptom — every SSO user bounced into
// account setup — reads as a broken SSO integration rather than a role change.
// Ruby half: spec/requests/sso/onboarding_interlock_spec.rb
describe('mPass auto-join vs the onboarding redirect', () => {
  let next;
  const midOnboarding = {
    id: 1,
    status: 'active',
    permissions: ['agent'],
    custom_attributes: {},
    onboarding_step: 'account_details',
  };

  beforeEach(() => {
    next = vi.fn();
    store.getters.isLoggedIn = true;
  });

  it('does NOT redirect an auto-joined agent into onboarding', () => {
    store.getters.getCurrentUser = {
      account_id: 1,
      id: 1,
      accounts: [{ ...midOnboarding, role: 'agent' }],
    };

    validateAuthenticateRoutePermission(
      { name: 'home', params: { accountId: 1 } },
      next
    );

    const target = next.mock.calls[0]?.[0];
    expect(String(target ?? '')).not.toContain('onboarding');
  });

  // Documents the trap the interlock avoids. If this ever stops passing, auto-join
  // has been changed to assign administrator — read the comment above first.
  it('WOULD redirect the same user if auto-join assigned administrator', () => {
    store.getters.getCurrentUser = {
      account_id: 1,
      id: 1,
      accounts: [{ ...midOnboarding, role: 'administrator' }],
    };

    validateAuthenticateRoutePermission(
      { name: 'home', params: { accountId: 1 } },
      next
    );

    const target = next.mock.calls[0]?.[0];
    expect(String(target ?? '')).toContain('onboarding');
  });
});
