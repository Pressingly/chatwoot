// Single definition of the mPass SSO surface shared by both bundles.
//
// AUTH_TYPE is read from window.globalConfig rather than the Vuex globalConfig
// module because the earliest callers (the axios interceptor, the v3 router guard)
// run before the store exists. DashboardController#app_config injects it per
// request, so it is never baked into a build.
export const isSSOMode = () => window.globalConfig?.AUTH_TYPE === 'SSO';

// Set only by Api::BaseController (a Rule 2 flush, or a dead token while an identity
// is asserted), so the SPA can tell "re-enter the handoff" apart from an ordinary
// permission 401.
// Lowercase: axios normalises response header names.
export const SSO_FLUSH_HEADER = 'x-mpass-session-flushed';

// The ForwardAuth handoff (config/routes.rb). A full navigation, never a soft route.
export const SSO_HANDOFF_PATH = '/auth/sso/proxy-login';
