# devise_token_auth's default registrations, gated under SSO (security.md G7):
# PUT /auth sets a password (and email) without the current one, POST /auth signs
# up, DELETE /auth deletes the account. Stock behaviour is unchanged.
class DeviseOverrides::RegistrationsController < DeviseTokenAuth::RegistrationsController
  include MpassLocalAuthGuard
  # prepend_: the parent's param validations would otherwise answer 422 first,
  # which confirms the route exists.
  prepend_before_action :reject_local_auth_under_sso
end
