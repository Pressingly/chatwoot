import { shallowMount } from '@vue/test-utils';
import Login from './Index.vue';
import routes from '../routes';
import Spinner from 'shared/components/Spinner.vue';
import { getLoginRedirectURL } from '../../helpers/AuthHelper';
import { login } from '../../api/auth';

// Never settles: the token exchange stays in flight for the assertions.
vi.mock('../../api/auth', () => ({
  login: vi.fn(() => new Promise(() => {})),
}));

vi.mock('shared/composables/useBranding', () => ({
  useBranding: () => ({ replaceInstallationName: text => text }),
}));

const getWrapper = (props = {}) =>
  shallowMount(Login, {
    props,
    global: {
      stubs: { 'router-link': true },
      mocks: {
        $t: key => key,
        $route: { query: {} },
        $router: { replace: vi.fn(), push: vi.fn() },
        $store: { getters: { 'globalConfig/get': {} } },
      },
    },
  });

describe('Login page', () => {
  beforeEach(() => {
    window.chatwootConfig = {
      allowedLoginMethods: ['email', 'google_oauth'],
      googleOAuthClientId: 'client-id',
    };
  });

  const realLocation = window.location;
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      value: { ...realLocation, assign: vi.fn() },
      writable: true,
    });
  });

  afterEach(() => {
    window.globalConfig = undefined;
    window.chatwootConfig = {};
    Object.defineProperty(window, 'location', {
      value: realLocation,
      writable: true,
    });
    vi.clearAllMocks();
  });

  it('renders the stock login form when AUTH_TYPE is unset', () => {
    window.globalConfig = { AUTH_TYPE: '' };
    const wrapper = getWrapper();

    expect(window.location.assign).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="email_input"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="password_input"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="submit_button"]').exists()).toBe(true);
    expect(wrapper.findComponent({ name: 'GoogleOAuthButton' }).exists()).toBe(
      true
    );
    expect(wrapper.find('[data-testid="mpass_login_link"]').exists()).toBe(
      false
    );
  });

  it('starts the handoff under SSO instead of showing a login page', () => {
    window.globalConfig = { AUTH_TYPE: 'SSO' };
    const wrapper = getWrapper();

    expect(window.location.assign).toHaveBeenCalledWith(
      '/auth/sso/proxy-login'
    );
    expect(wrapper.findComponent(Spinner).exists()).toBe(true);
    expect(wrapper.find('h2').exists()).toBe(false);
    expect(wrapper.find('[data-testid="email_input"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="mpass_login_link"]').exists()).toBe(
      false
    );
  });

  it('shows only a spinner while the handoff token is exchanged', () => {
    window.globalConfig = { AUTH_TYPE: 'SSO' };
    const wrapper = getWrapper({ email: 'a@askii.ai', ssoAuthToken: 'token' });

    expect(login).toHaveBeenCalled();
    expect(wrapper.findComponent(Spinner).exists()).toBe(true);
    expect(wrapper.find('h2').exists()).toBe(false);
  });

  // The one place the button remains: restarting a failed handoff automatically
  // would loop.
  it('offers the mPass entry after a failed handoff, without retrying', () => {
    window.globalConfig = { AUTH_TYPE: 'SSO' };
    const wrapper = getWrapper({ authError: 'sso_failed' });

    expect(window.location.assign).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="email_input"]').exists()).toBe(false);
    expect(
      wrapper.find('[data-testid="mpass_login_link"]').attributes('href')
    ).toBe('/auth/sso/proxy-login');
  });
});

describe('login retries', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('preserves the Shopify pricing redirect after resolving a session limit', async () => {
    login.mockResolvedValue(null);
    const context = {
      email: '',
      credentials: {
        email: 'john@example.com',
        password: 'Password1!',
      },
      ssoAuthToken: '',
      ssoAccountId: '',
      ssoConversationId: '',
      redirectUrl:
        'settings/billing?plan_handle=growth&shop=store.myshopify.com',
      sessionsLimitReached: true,
      limitedSessions: [{ id: 1 }],
      loginApi: { showLoading: false, hasErrored: false },
      handleImpersonation: vi.fn(),
      showAlertMessage: vi.fn(),
      $t: key => key,
    };

    Login.methods.retryLoginWithParams.call(context, {
      revoke_session_id: 1,
    });
    await Promise.resolve();

    expect(login).toHaveBeenCalledWith(
      expect.objectContaining({
        redirectUrl:
          'settings/billing?plan_handle=growth&shop=store.myshopify.com',
        revoke_session_id: 1,
      })
    );
  });
});

describe('SAML login', () => {
  it('carries the pending Shopify install redirect to the SSO route', () => {
    const redirectUrl = `settings/integrations/shopify?shopify_pending_install=${'a'.repeat(32)}`;

    expect(Login.computed.samlLoginRoute.call({ redirectUrl })).toEqual({
      name: 'sso_login',
      query: { redirect_url: redirectUrl },
    });
  });
});

describe('Shopify signup and password recovery', () => {
  it('shows signup for a pending Shopify installation when public signup is disabled', () => {
    window.chatwootConfig = { signupEnabled: 'false' };

    expect(
      Login.computed.showSignupLink.call({
        signupRoute: {
          name: 'auth_signup',
          query: { shopify_pending_install: 'pending-token' },
        },
      })
    ).toBe(true);
  });

  it('carries the Shopify billing redirect to password recovery', () => {
    const planRedirect = 'settings/billing?plan_handle=growth';
    const route = Login.computed.resetPasswordRoute.call({
      redirectUrl: planRedirect,
      ssoAccountId: '42',
    });
    expect(route).toEqual({
      name: 'auth_reset_password',
      query: { redirect_url: planRedirect, sso_account_id: '42' },
    });
    const resetRoute = routes.find(item => item.name === 'auth_reset_password');
    const props = resetRoute.props(route);
    expect(props).toEqual({ redirectUrl: planRedirect, ssoAccountId: '42' });
    expect(
      getLoginRedirectURL({
        ...props,
        user: { account_id: 1, accounts: [{ id: 1 }, { id: 42 }] },
      })
    ).toBe('/app/accounts/42/settings/billing?plan_handle=growth');
  });

  it('carries a pending install redirect to email verification', async () => {
    const pendingInstallRedirect = `settings/integrations/shopify?shopify_pending_install=${'a'.repeat(32)}`;
    const router = { push: vi.fn() };
    const context = {
      email: '',
      credentials: {
        email: 'john@example.com',
        password: 'Password1!',
      },
      ssoAuthToken: '',
      ssoAccountId: '',
      ssoConversationId: '',
      redirectUrl: pendingInstallRedirect,
      loginApi: { showLoading: false, hasErrored: false },
      $router: router,
      handleImpersonation: vi.fn(),
      showAlertMessage: vi.fn(),
      $t: key => key,
    };
    login.mockRejectedValueOnce({ errorCode: 'user_not_confirmed' });

    Login.methods.submitLogin.call(context);
    await Promise.resolve();
    await Promise.resolve();

    expect(router.push).toHaveBeenCalledWith({
      name: 'auth_verify_email',
      state: {
        email: 'john@example.com',
        redirectUrl: pendingInstallRedirect,
      },
    });
  });
});
