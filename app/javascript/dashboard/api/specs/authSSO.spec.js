import Auth from '../auth';
import {
  clearCookiesOnLogout,
  deleteIndexedDBOnLogout,
} from '../../store/utils/api';

vi.mock('../../store/utils/api', () => ({
  clearCookiesOnLogout: vi.fn(),
  deleteIndexedDBOnLogout: vi.fn(),
}));

// logout-flow: per-app logout under SSO is navigation-only, to the portal.
describe('Auth.logout', () => {
  beforeEach(() => {
    window.axios = { delete: vi.fn(() => Promise.resolve({})) };
  });
  afterEach(() => {
    window.globalConfig = undefined;
    vi.clearAllMocks();
  });

  it('makes no sign-out call under SSO and navigates to the portal', async () => {
    window.globalConfig = {
      AUTH_TYPE: 'SSO',
      LOGOUT_REDIRECT_URL: 'https://foss.local.dev',
    };
    await Auth.logout();
    expect(window.axios.delete).not.toHaveBeenCalled();
    expect(clearCookiesOnLogout).toHaveBeenCalledWith('https://foss.local.dev');
  });

  // Falling back to '/' would re-enter the handoff and sign the user back in.
  it.each([undefined, '', '/', 'foss.local.dev', 'ftp://foss.local.dev'])(
    'logs and does nothing under SSO when the portal URL is %s',
    async url => {
      const error = vi.spyOn(console, 'error').mockImplementation(() => {});
      window.globalConfig = { AUTH_TYPE: 'SSO', LOGOUT_REDIRECT_URL: url };
      await Auth.logout();
      expect(clearCookiesOnLogout).not.toHaveBeenCalled();
      expect(deleteIndexedDBOnLogout).not.toHaveBeenCalled();
      expect(window.axios.delete).not.toHaveBeenCalled();
      expect(error).toHaveBeenCalled();
      error.mockRestore();
    }
  );

  it('keeps the stock sign-out call without SSO', async () => {
    window.globalConfig = { AUTH_TYPE: '' };
    await Auth.logout();
    expect(window.axios.delete).toHaveBeenCalled();
  });
});
