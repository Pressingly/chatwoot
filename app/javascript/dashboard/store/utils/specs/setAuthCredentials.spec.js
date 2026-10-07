import Cookies from 'js-cookie';
import { setAuthCredentials } from '../api';

vi.mock('js-cookie', () => ({
  default: { set: vi.fn(), get: vi.fn(), remove: vi.fn() },
}));

// The bundle's TTL is 8h. Whole-day expiry rounds that to 0, the browser drops the
// cookie on arrival, and every page load loops through the handoff.
describe('setAuthCredentials cookie expiry', () => {
  const eightHoursFromNow = () => Math.floor(Date.now() / 1000) + 8 * 3600;
  const response = expiry => ({
    headers: { expiry: String(expiry), uid: 'a@askii.ai' },
    data: { data: { id: 1 } },
  });
  const sessionCookieCall = () =>
    Cookies.set.mock.calls.find(([name]) => name === 'cw_d_session_info');

  afterEach(() => {
    window.globalConfig = undefined;
    vi.clearAllMocks();
  });

  it('keeps a sub-day session alive under SSO', () => {
    window.globalConfig = { AUTH_TYPE: 'SSO' };
    const expiry = eightHoursFromNow();
    setAuthCredentials(response(expiry));

    const { expires } = sessionCookieCall()[2];
    expect(expires).toBeInstanceOf(Date);
    expect(expires.getTime()).toBe(expiry * 1000);
  });

  it('keeps the stock whole-day expiry without SSO', () => {
    window.globalConfig = { AUTH_TYPE: '' };
    setAuthCredentials(response(eightHoursFromNow()));

    expect(sessionCookieCall()[2].expires).toBe(0);
  });
});
