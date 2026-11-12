# The middleware stack is built before Zeitwerk can autoload lib/, so the
# namespace and the middleware are loaded by hand; Zeitwerk adopts both later.
module Mpass; end
require Rails.root.join('lib/mpass/edge_trust')

Rails.application.config.middleware.insert_before 0, Mpass::EdgeTrust

Rails.application.config.after_initialize do
  next unless Mpass::ProxyIdentity.sso_mode?

  unless Mpass::EdgeTrust.usable_secret?(Mpass::EdgeTrust.configured_secret)
    Rails.logger.error(
      'MPASS_EDGE_SECRET is unset or shorter than 32 characters: mPass identity headers will be ignored and SSO login is disabled'
    )
  end

  if Mpass::ProxyIdentity.corporate_id.present? && !Mpass::TokenVerifier.from_env.configured?
    Rails.logger.error(
      'SMB_CORPORATE_ID is set but no token issuer or client id is configured ' \
      '(MPASS_COGNITO_ISSUER_URL or COGNITO_AWS_REGION + COGNITO_USER_POOL_ID, MPASS_OIDC_CLIENT_ID): every mPass login will be refused'
    )
  end
end
