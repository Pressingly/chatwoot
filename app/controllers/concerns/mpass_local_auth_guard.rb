# frozen_string_literal: true

# audit row 15 / Threat 5 — server-side enforcement for local-credential endpoints.
#
# The SPA route guard (v3/helpers/ssoRouteGuard.js) only removes the affordance.
# These Devise endpoints remain reachable by curl regardless of it, and
# `PUT /auth/password` does not merely change a password — it calls
# `send_auth_headers` and returns a live devise_token_auth session. That is a
# complete credential path around mPass.
#
# This is the same defect class as Chatwoot's own DISABLE_USER_PROFILE_UPDATE,
# which is honoured by the frontend and ignored by the API. A flag the UI respects
# and the server does not is not a control.
#
# 404 rather than 403: under SSO these endpoints do not conceptually exist, and a
# 403 would confirm the route is there to probe further.
# Provides the filter but does NOT register it — each controller declares its own
# `before_action :reject_local_auth_under_sso`, with an `only:` scope where the
# controller also serves non-auth actions. Auto-registering here would silently
# 404 every action on any controller that includes it.
module MpassLocalAuthGuard
  extend ActiveSupport::Concern

  private

  def reject_local_auth_under_sso
    head :not_found if Mpass::ProxyIdentity.sso_mode?
  end

  # The login endpoint is the one local-credential surface that cannot be refused
  # outright: the ForwardAuth handoff re-enters POST /auth/sign_in carrying an
  # sso_auth_token, so a blanket gate there would break login itself. Everything
  # else that reaches it — a password, a header-supplied credential pair, an MFA
  # verification — is a second identity path Moneta does not control. Every account
  # created before the integration still has a working local password, and
  # MpassUserBuilder gives provisioned users a real (random) one too.
  #
  # Must run AFTER merge_credential_headers and process_sso_auth_token: only a
  # handoff token that process_sso_auth_token VALIDATED (it sets @resource) opens
  # the door, and never alongside a password or MFA credential. Keying on the
  # parameter's presence let `sso_auth_token=x` plus a password through.
  def reject_local_login_under_sso
    return unless Mpass::ProxyIdentity.sso_mode?

    handoff = @resource.present? && params[:password].blank? && params[:mfa_token].blank?
    head :not_found unless handoff
  end
end
