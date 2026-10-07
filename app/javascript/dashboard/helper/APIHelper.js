import Auth from '../api/auth';
import { clearBrowserSessionCookies } from '../store/utils/api';
import { SSO_FLUSH_HEADER, SSO_HANDOFF_PATH } from 'shared/helpers/ssoMode';

const parseErrorCode = error => Promise.reject(error);

// audit row 20 — makes Rule 2's XHR flush observable.
//
// Auth headers are bound ONCE at instance creation (below), read from the cookie
// at that moment. After the server evicts the token, this instance keeps replaying
// the dead credential until a full page load — so this must hard-navigate rather
// than soft-route, and must clear the cookie first or the login route's guard sees
// a cookie matching no live token.
//
// Keyed on the flush header, NOT on the 401 alone: 401 is not exclusively "session
// is dead" in Chatwoot. Pundit::NotAuthorizedError renders 401
// (request_exception_handler.rb:24-26) and endpoints such as
// reports_controller.rb:55 answer `head :unauthorized` for a non-administrator.
// Reacting to every 401 would log an agent out for opening an admin-only screen.
// Only Api::BaseController sets this header: on a Rule 2 flush
// (flush_stale_mpass_session) and on a dead token while the proxy still asserts an
// identity (render_authenticate_error). Both mean "re-enter the handoff".
export const handleUnauthorized = error => {
  if (error?.response?.headers?.[SSO_FLUSH_HEADER]) {
    // Cookie-only clear, not clearCookiesOnLogout() — that one navigates to the
    // portal (LOGOUT_REDIRECT_LINK). A Rule 2 flush is not a logout: the user is
    // still authenticated upstream. Go to the handoff rather than /app/login,
    // which under SSO offers no way back in — the handoff mints a token for the
    // incoming identity and returns the user straight to the app.
    clearBrowserSessionCookies();
    window.location.href = SSO_HANDOFF_PATH;
  }
  return Promise.reject(error);
};

export default axios => {
  const { apiHost = '' } = window.chatwootConfig || {};
  const wootApi = axios.create({ baseURL: `${apiHost}/` });
  // Add Auth Headers to requests if logged in
  if (Auth.hasAuthCookie()) {
    const {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    } = Auth.getAuthData();
    Object.assign(wootApi.defaults.headers.common, {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    });
  }
  // Response parsing interceptor
  wootApi.interceptors.response.use(
    response => response,
    error => handleUnauthorized(error).catch(parseErrorCode)
  );
  return wootApi;
};
