import fromUnixTime from 'date-fns/fromUnixTime';
import differenceInDays from 'date-fns/differenceInDays';
import Cookies from 'js-cookie';
import { LOCAL_STORAGE_KEYS } from 'dashboard/constants/localStorage';
import { SESSION_STORAGE_KEYS } from 'dashboard/constants/sessionStorage';
import { LocalStorage } from 'shared/helpers/localStorage';
import SessionStorage from 'shared/helpers/sessionStorage';
import { emitter } from 'shared/helpers/mitt';
import { isSSOMode } from 'shared/helpers/ssoMode';
import {
  ANALYTICS_IDENTITY,
  ANALYTICS_RESET,
  CHATWOOT_RESET,
  CHATWOOT_SET_USER,
} from '../../constants/appEvents';

Cookies.defaults = { sameSite: 'Lax' };

export const getLoadingStatus = state => state.fetchAPIloadingStatus;
export const setLoadingStatus = (state, status) => {
  state.fetchAPIloadingStatus = status;
};

export const setUser = user => {
  emitter.emit(CHATWOOT_SET_USER, { user });
  emitter.emit(ANALYTICS_IDENTITY, { user });
};

export const getHeaderExpiry = response =>
  fromUnixTime(response.headers.expiry);

export const setAuthCredentials = response => {
  const expiryDate = getHeaderExpiry(response);
  // audit row 12 — `secure` is DERIVED, never hardcoded: hardcoding true breaks
  // local http dev, hardcoding false ships an insecure cookie to production.
  // `sameSite: 'Lax'` is already set globally (Cookies.defaults, :16).
  // `httpOnly` is impossible here by design — the SPA must read this cookie to
  // build its request headers. That tradeoff is recorded in
  // sso-rules-moneta/apps/chatwoot/security.md rather than left as a silent gap.
  Cookies.set('cw_d_session_info', JSON.stringify(response.headers), {
    // Under SSO the TTL can be under a day (8h in the bundle); whole days would
    // round it to 0 and the browser would drop the cookie on arrival.
    expires: isSSOMode()
      ? expiryDate
      : differenceInDays(expiryDate, new Date()),
    // SSO-only, like every fork change: stock Chatwoot keeps upstream's cookie.
    secure: isSSOMode() && window.location.protocol === 'https:',
  });
  setUser(response.data.data, expiryDate);
};

export const clearBrowserSessionCookies = () => {
  Cookies.remove('cw_d_session_info');
  Cookies.remove('auth_data');
  Cookies.remove('user');
};

export const clearLocalStorageOnLogout = () => {
  LocalStorage.remove(LOCAL_STORAGE_KEYS.DRAFT_MESSAGES);
};

export const clearSessionStorageOnLogout = () => {
  SessionStorage.remove(SESSION_STORAGE_KEYS.IMPERSONATION_USER);
};

export const deleteIndexedDBOnLogout = async () => {
  let dbs = [];
  try {
    dbs = await window.indexedDB.databases();
    dbs = dbs.map(db => db.name);
  } catch (e) {
    dbs = JSON.parse(localStorage.getItem('cw-idb-names') || '[]');
  }

  dbs.forEach(dbName => {
    const deleteRequest = window.indexedDB.deleteDatabase(dbName);

    deleteRequest.onerror = event => {
      // eslint-disable-next-line no-console
      console.error(`Error deleting database ${dbName}.`, event);
    };

    deleteRequest.onsuccess = () => {
      // eslint-disable-next-line no-console
      console.log(`Database ${dbName} deleted successfully.`);
    };
  });

  localStorage.removeItem('cw-idb-names');
};

export const clearCookiesOnLogout = redirectTo => {
  emitter.emit(CHATWOOT_RESET);
  emitter.emit(ANALYTICS_RESET);
  clearBrowserSessionCookies();
  clearLocalStorageOnLogout();
  clearSessionStorageOnLogout();
  const globalConfig = window.globalConfig || {};
  const logoutRedirectLink =
    redirectTo || globalConfig.LOGOUT_REDIRECT_LINK || '/';
  window.location = logoutRedirectLink;
};

export const parseAPIErrorResponse = error => {
  if (error?.response?.data?.message) {
    return error?.response?.data?.message;
  }
  if (error?.response?.data?.error) {
    return error?.response?.data?.error;
  }
  if (error?.response?.data?.errors) {
    return error?.response?.data?.errors[0];
  }
  return error;
};

export const throwErrorMessage = error => {
  const errorMessage = parseAPIErrorResponse(error);
  throw new Error(errorMessage);
};

export const parseLinearAPIErrorResponse = (error, defaultMessage) => {
  const errorData = error.response.data;
  const errorMessage = errorData?.error?.errors?.[0]?.message || defaultMessage;
  return errorMessage;
};
