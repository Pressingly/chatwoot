module MpassTokenHelpers
  MPASS_EDGE_SECRET = 'spec-edge-secret-0123456789abcdef0123456789'.freeze
  MPASS_ISSUER = 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_spec'.freeze
  MPASS_CLIENT_ID = 'spec-client-id'.freeze
  MPASS_KID = 'spec-kid'.freeze
  MPASS_SIGNING_KEY = OpenSSL::PKey::RSA.generate(2048)

  def mpass_edge_headers(headers = {})
    headers.merge('X-Mpass-Edge-Secret' => MPASS_EDGE_SECRET)
  end

  def mpass_verifier_env
    { MPASS_COGNITO_ISSUER_URL: MPASS_ISSUER, MPASS_OIDC_CLIENT_ID: MPASS_CLIENT_ID }
  end

  def mpass_claims(overrides = {})
    now = Time.now.to_i
    { 'iss' => MPASS_ISSUER, 'token_use' => 'access', 'client_id' => MPASS_CLIENT_ID,
      'iat' => now, 'exp' => now + 3600, 'sub' => 'spec-sub' }.merge(overrides).compact
  end

  def mpass_token(overrides = {}, key = MPASS_SIGNING_KEY, kid = MPASS_KID)
    JWT.encode(mpass_claims(overrides), key, 'RS256', kid: kid)
  end

  def stub_mpass_jwks(issuer = MPASS_ISSUER, key: MPASS_SIGNING_KEY)
    jwks = JWT::JWK::Set.new(JWT::JWK.new(key.public_key, kid: MPASS_KID)).export
    stub_request(:get, "#{issuer}/.well-known/jwks.json")
      .to_return(status: 200, body: jwks.to_json, headers: { 'Content-Type' => 'application/json' })
  end
end

RSpec.configure do |config|
  config.include MpassTokenHelpers
  config.before do
    Mpass::JwksCache.shared.reset!
    Mpass::VerifiedTokenCache.shared.reset!
    Mpass::LogThrottle.shared.reset!
  end
end
