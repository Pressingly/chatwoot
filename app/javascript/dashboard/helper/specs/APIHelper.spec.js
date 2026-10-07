import { handleUnauthorized } from '../APIHelper';
import { clearBrowserSessionCookies } from '../../store/utils/api';

vi.mock('../../store/utils/api', () => ({
  clearBrowserSessionCookies: vi.fn(),
}));

// The client half of Rule 2's XHR flush: server-side eviction alone is invisible
// to an SPA that never reacts to it (delta spec, "server-side invalidation
// without a client handler is a violation").
describe('handleUnauthorized', () => {
  const realLocation = window.location;
  beforeEach(() => {
    Object.defineProperty(window, 'location', {
      value: { ...realLocation, href: 'https://chat.example/app/accounts/1' },
      writable: true,
    });
  });
  afterEach(() => {
    Object.defineProperty(window, 'location', {
      value: realLocation,
      writable: true,
    });
    vi.clearAllMocks();
  });

  it('clears the cookie and fully navigates into the handoff on a flush', async () => {
    const error = {
      response: { status: 401, headers: { 'x-mpass-session-flushed': 'true' } },
    };
    await expect(handleUnauthorized(error)).rejects.toBe(error);
    expect(clearBrowserSessionCookies).toHaveBeenCalled();
    expect(window.location.href).toBe('/auth/sso/proxy-login');
  });

  it('leaves an ordinary 401 alone (permission denials must not log out)', async () => {
    const error = { response: { status: 401, headers: {} } };
    await expect(handleUnauthorized(error)).rejects.toBe(error);
    expect(clearBrowserSessionCookies).not.toHaveBeenCalled();
    expect(window.location.href).toBe('https://chat.example/app/accounts/1');
  });
});
