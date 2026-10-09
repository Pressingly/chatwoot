/* global axios */

import Cookies from 'js-cookie';
import endPoints from './endPoints';
import {
  clearCookiesOnLogout,
  deleteIndexedDBOnLogout,
} from '../store/utils/api';
import { isSSOMode } from 'shared/helpers/ssoMode';

export default {
  validityCheck() {
    const urlData = endPoints('validityCheck');
    return axios.get(urlData.url);
  },
  logout() {
    // audit row 14 — under SSO, per-app logout is NAVIGATION-ONLY.
    //
    // DELETE /auth/sign_out is skipped only in SSO mode: it cleared the Rails-side
    // token, but the next request would immediately re-establish a session from
    // X-Auth-Request-Email, so the user-visible result was identical while the
    // request added a failure mode. Real sign-out is the portal's "logout all",
    // which clears the shared _oauth2_proxy cookie.
    //
    // Stock Chatwoot still calls it: without SSO the devise token is the whole
    // session, and skipping the request would leave it valid for its full lifespan
    // after the user believes they have logged out.
    //
    // The portal URL is deployer-supplied: LOGOUT_REDIRECT_URL, passed to
    // clearCookiesOnLogout(), not LOGOUT_REDIRECT_LINK (DB-only, and it also drives
    // the 401 re-auth path). Never derive the host by rewriting the hostname, and
    // never point at /oauth2/sign_out.
    //
    // Missing or not an absolute http(s) URL: log and do nothing. Falling back to
    // '/' would re-enter the handoff and sign the user straight back in, so Sign
    // out would look broken instead of failing loudly.
    if (isSSOMode()) {
      const portalUrl = window.globalConfig?.LOGOUT_REDIRECT_URL;
      if (!/^https?:\/\/[^/]/i.test(portalUrl || '')) {
        // eslint-disable-next-line no-console
        console.error(
          'SSO Sign out: LOGOUT_REDIRECT_URL is missing or not an absolute http(s) URL.'
        );
        return Promise.resolve();
      }
      deleteIndexedDBOnLogout();
      clearCookiesOnLogout(portalUrl);
      return Promise.resolve();
    }

    const urlData = endPoints('logout');
    const fetchPromise = new Promise((resolve, reject) => {
      axios
        .delete(urlData.url)
        .then(response => {
          deleteIndexedDBOnLogout();
          clearCookiesOnLogout();
          resolve(response);
        })
        .catch(error => {
          reject(error);
        });
    });
    return fetchPromise;
  },
  hasAuthCookie() {
    return !!Cookies.get('cw_d_session_info');
  },
  getAuthData() {
    if (this.hasAuthCookie()) {
      const savedAuthInfo = Cookies.get('cw_d_session_info');
      return JSON.parse(savedAuthInfo || '{}');
    }
    return false;
  },
  profileUpdate({ displayName, avatar, ...profileAttributes }) {
    const formData = new FormData();
    Object.keys(profileAttributes).forEach(key => {
      const hasValue = profileAttributes[key] === undefined;
      if (!hasValue) {
        formData.append(`profile[${key}]`, profileAttributes[key]);
      }
    });
    formData.append('profile[display_name]', displayName || '');
    if (avatar) {
      formData.append('profile[avatar]', avatar);
    }
    return axios.put(endPoints('profileUpdate').url, formData);
  },

  profilePasswordUpdate({ currentPassword, password, passwordConfirmation }) {
    return axios.put(endPoints('profileUpdate').url, {
      profile: {
        current_password: currentPassword,
        password,
        password_confirmation: passwordConfirmation,
      },
    });
  },

  updateUISettings({ uiSettings }) {
    return axios.put(endPoints('profileUpdate').url, {
      profile: { ui_settings: uiSettings },
    });
  },

  updateAvailability(availabilityData) {
    return axios.post(endPoints('availabilityUpdate').url, {
      profile: { ...availabilityData },
    });
  },

  updateAutoOffline(accountId, autoOffline = false) {
    return axios.post(endPoints('autoOffline').url, {
      profile: { account_id: accountId, auto_offline: autoOffline },
    });
  },

  deleteAvatar() {
    return axios.delete(endPoints('deleteAvatar').url);
  },

  resetPassword({ email }) {
    const urlData = endPoints('resetPassword');
    return axios.post(urlData.url, { email });
  },

  setActiveAccount({ accountId }) {
    const urlData = endPoints('setActiveAccount');
    return axios.put(urlData.url, {
      profile: {
        account_id: accountId,
      },
    });
  },
  resendConfirmation() {
    const urlData = endPoints('resendConfirmation');
    return axios.post(urlData.url);
  },
  resetAccessToken() {
    const urlData = endPoints('resetAccessToken');
    return axios.post(urlData.url);
  },
  getSessions() {
    return axios.get('/api/v1/profile/sessions');
  },
  revokeSession(id) {
    return axios.delete(`/api/v1/profile/sessions/${id}`);
  },
};
