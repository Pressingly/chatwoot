# frozen_string_literal: true

# Rule 2 — session-identity reconciliation (audit row 20).
#
# When the browser holds a session for user A but oauth2-proxy asserts user B, the
# stale session MUST be flushed before anything else happens. Chatwoot's credential
# is client-held (a devise_token_auth triple the SPA persists into the JS-readable
# cw_d_session_info cookie), so the server cannot clear it directly — hence two
# paths, both defined here so "mismatch" has exactly one definition:
#
#   Path A (DashboardController) — document requests, resolved by redirecting
#     through the handoff, which re-mints for B. RouteHelper.js:23-27 already clears
#     the previous cookie whenever the login route carries email + sso_auth_token.
#   Path B (Api::BaseController) — XHR, which cannot be redirected. Evict the
#     request's token and answer 401; the SPA's 401 handler hard-navigates.
#
# Header ABSENCE is never a mismatch. Internal traffic (Sidekiq, health probes,
# direct container hits) carries no header and must not be logged out.
#
# The same two signals answer the entry question — see mpass_handoff_required?.
# "Which user does this document belong to" is one decision, so mismatch and
# first-entry are decided here together rather than in two places that could drift.
module MpassSessionReconciliation
  extend ActiveSupport::Concern

  # Mirrored by SSO_FLUSH_HEADER in shared/helpers/ssoMode.js.
  SSO_FLUSH_HEADER = 'X-Mpass-Session-Flushed'

  private

  def mpass_identity_mismatch?
    return false unless Mpass::ProxyIdentity.sso_mode?

    return false unless Mpass::ProxyIdentity.asserted?(request)

    current = mpass_session_email
    return false if current.blank?

    # nil here means asserted but unresolvable: flush rather than keep the session.
    # A principal outside SMB_CORPORATE_ID is flushed too, so the corporate gate is
    # enforced on every request, not only at the handoff; the handoff then answers 403.
    current != Mpass::ProxyIdentity.email(request) || !Mpass::ProxyIdentity.corporate_claims_ok?(request)
  end

  # Rule 3, entry path — the proxy asserts an identity and the browser holds no app
  # session at all. Nothing on the client can start the handoff: under SSO the login
  # page offers only local credentials, so a user who has just scanned the QR code
  # would land on a login form with no way in. The server therefore starts it.
  #
  # Distinct from a mismatch, which needs a session to disagree with, and narrower
  # than "no session": without an asserted identity there is nothing to hand off,
  # which is what keeps bypass paths (header-stripped, never re-added) out of it.
  def mpass_handoff_required?
    return false unless Mpass::ProxyIdentity.sso_mode?
    return false if Mpass::ProxyIdentity.email(request).blank?

    mpass_session_email.blank?
  end

  # Resolving "who does the browser think it is" differs by path, because Chatwoot's
  # credential is client-held:
  #
  #   XHR       — the SPA replays the devise_token_auth headers, so SetUserByToken
  #               has already populated current_user.
  #   Document  — a browser navigation sends NO auth headers, only the
  #               cw_d_session_info cookie. DashboardController descends from
  #               ActionController::Base and never includes SetUserByToken. Devise
  #               still gives it a current_user, but that one is Warden's, read
  #               from the httpOnly Rails session the SPA cannot see or clear, so
  #               it must not count: trusting it served the app to a browser whose
  #               SPA then showed a dead-end login page (devkit e2e, 2026-09-24).
  def mpass_session_email
    if self.class.include?(DeviseTokenAuth::Concerns::SetUserByToken) && current_user.present?
      return Mpass::ProxyIdentity.normalise(current_user.email)
    end

    mpass_session_email_from_cookie
  end

  def mpass_session_email_from_cookie
    raw = raw_session_cookie
    return nil if raw.blank?

    # js-cookie writes `+` and `@` unencoded and reads with decodeURIComponent.
    # Rack's `cookies` decodes as form data (`+` → space), which mangles
    # `a+b@corp.com` into a permanent mismatch, so decode the raw value the way
    # js-cookie does.
    payload = JSON.parse(URI.decode_uri_component(raw))
    # Valid JSON is not necessarily an object: `null`, `[1,2]` and `123` all parse
    # cleanly and then raise on []('uid') — NoMethodError, TypeError, TypeError.
    # This cookie is JS-readable by design, so its contents are attacker-reachable
    # via XSS and corruptible by the user; an unguarded crash here would 500 every
    # document request and make the dashboard permanently unreachable.
    return nil unless payload.is_a?(Hash)

    uid = payload['uid']
    return nil unless uid.is_a?(String)

    Mpass::ProxyIdentity.normalise(uid)
  rescue JSON::ParserError, ArgumentError
    # A malformed cookie (bad JSON or bad %-encoding) tells us nothing about
    # identity. Treat it as "no session" rather than as a mismatch: a spurious
    # flush would log out a valid user.
    nil
  end

  # First match wins, as in Rack::Utils.parse_cookies_header.
  def raw_session_cookie
    request.get_header('HTTP_COOKIE').to_s.split(/; */).each do |pair|
      name, value = pair.split('=', 2)
      return value if name == 'cw_d_session_info'
    end
    nil
  end
end
