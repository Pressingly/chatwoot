import { shallowMount } from '@vue/test-utils';
import Login from './Index.vue';
import Spinner from 'shared/components/Spinner.vue';
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
