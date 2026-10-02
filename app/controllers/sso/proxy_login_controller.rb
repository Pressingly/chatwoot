# frozen_string_literal: true

# GET /auth/sso/proxy-login — the ForwardAuth handoff.
#
# Trust chain: Traefik strips any client-supplied X-Auth-Request-* header, then
# oauth2-proxy re-adds verified values only for a valid upstream OIDC session.
# This controller therefore trusts X-Auth-Request-Email without verifying it, which
# is safe ONLY while the three invariants in sso-rules-moneta/openspec/project.md
# hold. The AUTH_TYPE gate below is the last line of defence if they stop holding.
#
# Flow: read proxy identity -> resolve-or-provision -> mint a 5-minute single-use
# sso_auth_token -> 302 to /app/login?email=&sso_auth_token=. The existing SPA login
# route consumes it: RouteHelper.js clears the previous user's session cookie, the
# login page (Index.vue) submits the token behind a spinner, and
# DeviseOverrides::SessionsController issues the devise_token_auth headers only for a
# token it validated. No new credential machinery.
class Sso::ProxyLoginController < ApplicationController
  skip_before_action :set_current_user, raise: false

  before_action :ensure_sso_mode

  def create
    email = Mpass::ProxyIdentity.email(request)
    return redirect_with_error if email.blank?
    # Before the builder, so a refused principal leaves no user row behind.
    return refuse_corporate unless Mpass::ProxyIdentity.corporate_claims_ok?(request)

    user = MpassUserBuilder.new(
      email: email,
      display_name: Mpass::ProxyIdentity.display_name(request, email)
    ).perform

    return redirect_with_error if user.blank? || !user.persisted?

    # Chatwoot's own handoff URL builder (SsoAuthenticatable#generate_sso_link) —
    # same 5-minute single-use token the SAML and OAuth callbacks hand off with.
    redirect_to user.generate_sso_link, allow_other_host: true
  end

  private

  # Audit row 6: the backend must refuse identity headers when it is not deployed
  # behind ForwardAuth. Without this a non-SSO deployment trusts headers from any
  # caller that can reach the port.
  def ensure_sso_mode
    head :not_found unless Mpass::ProxyIdentity.sso_mode?
  end

  # 403, not the error redirect: a principal outside the tenant is not a failed
  # handoff to retry. The SPA cookie goes too, so a session the browser still holds
  # for this principal cannot outlive the refusal.
  def refuse_corporate
    cookies.delete('cw_d_session_info')
    head :forbidden
  end

  def redirect_with_error
    # Expire the SPA credential too: otherwise the failure page sees the old cookie,
    # reloads the dashboard as the previous user, and the flush loops.
    cookies.delete('cw_d_session_info')
    redirect_to "#{frontend_url}/app/login?error=sso_failed", allow_other_host: true
  end

  def frontend_url
    ENV.fetch('FRONTEND_URL', '')
  end
end
