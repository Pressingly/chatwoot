# frozen_string_literal: true

# Verifies the mPass token oauth2-proxy forwards in X-Auth-Request-Access-Token.
#
# A browser session forwards the Cognito access token; a Bearer caller forwards
# its id_token, which mpass-auth-proxy re-signs under its own issuer when email
# capture is on. Both issuers are trusted, each against its own JWKS, and nothing
# else is.
class Mpass::TokenVerifier
  class InvalidToken < StandardError
    attr_reader :reason

    def initialize(reason)
      super
      @reason = reason
    end
  end

  PLACEHOLDER_PREFIX = 'CHANGE_ME_'
  CLOCK_SKEW_LEEWAY_SECONDS = 60
  REQUIRED_CLAIMS = %w[exp iat iss token_use].freeze

  attr_reader :issuers, :client_id

  def self.configured(value)
    text = value.to_s.strip
    text.start_with?(PLACEHOLDER_PREFIX) ? '' : text
  end

  def self.without_trailing_slash(url)
    url.sub(%r{/+\z}, '')
  end

  def self.cognito_issuer(env)
    explicit = without_trailing_slash(configured(env['MPASS_COGNITO_ISSUER_URL']))
    return explicit if explicit.present?

    region = configured(env['COGNITO_AWS_REGION'])
    pool_id = configured(env['COGNITO_USER_POOL_ID'])
    return '' if region.blank? || pool_id.blank?

    "https://cognito-idp.#{region}.amazonaws.com/#{pool_id}"
  end

  def self.from_env(env = ENV, jwks_cache: Mpass::JwksCache.shared, claims_cache: Mpass::VerifiedTokenCache.shared)
    new(
      cognito_issuer: cognito_issuer(env),
      extra_issuers: [without_trailing_slash(configured(env['MPASS_TOKEN_ISSUER_URL']))],
      client_id: configured(env['MPASS_OIDC_CLIENT_ID']),
      jwks_cache: jwks_cache,
      claims_cache: claims_cache
    )
  end

  # Cognito access tokens name the client in client_id; id_tokens in aud.
  def self.audience_matches?(claims, client_id)
    case claims['token_use']
    when 'access' then claims['client_id'] == client_id
    when 'id' then Array.wrap(claims['aud']).include?(client_id)
    else false
    end
  end

  def initialize(cognito_issuer:, client_id:, jwks_cache:, extra_issuers: [], claims_cache: Mpass::VerifiedTokenCache.new)
    @cognito_issuer = cognito_issuer
    @issuers = [cognito_issuer, *extra_issuers].compact_blank.uniq.freeze
    @client_id = client_id
    @jwks_cache = jwks_cache
    @claims_cache = claims_cache
  end

  def configured?
    @cognito_issuer.present? && @client_id.present?
  end

  def verify(token)
    raise InvalidToken, 'verifier_unconfigured' unless configured?

    cache_key = Mpass::VerifiedTokenCache.key_for(token, [*issuers, client_id].join('|'))
    @claims_cache.fetch(cache_key) || @claims_cache.store(cache_key, verify_uncached(token))
  end

  private

  def verify_uncached(token)
    issuer = unverified_issuer(token)
    raise InvalidToken, 'untrusted_issuer' unless issuers.include?(issuer)

    claims = decode(token, issuer)
    raise InvalidToken, 'invalid' unless issued_in_past?(claims)
    raise InvalidToken, 'wrong_audience' unless self.class.audience_matches?(claims, client_id)

    claims
  end

  def unverified_issuer(token)
    claims, = JWT.decode(token, nil, false)
    raise InvalidToken, 'malformed' unless claims.is_a?(Hash)

    claims['iss'].to_s
  rescue JWT::DecodeError
    raise InvalidToken, 'malformed'
  end

  def decode(token, issuer)
    claims, = JWT.decode(
      token, nil, true,
      algorithms: ['RS256'],
      jwks: ->(options) { @jwks_cache.keys_for(issuer, refresh: options[:kid_not_found].present?) },
      iss: issuer, verify_iss: true,
      leeway: CLOCK_SKEW_LEEWAY_SECONDS,
      required_claims: REQUIRED_CLAIMS,
      verify_iat: false
    )
    claims
  rescue Mpass::JwksCache::Unavailable
    raise InvalidToken, 'jwks_unavailable'
  rescue JWT::DecodeError => e
    raise InvalidToken, decode_failure_reason(e)
  end

  # jwt's own iat check allows no clock skew; Cognito's clock may run ahead of ours.
  def issued_in_past?(claims)
    claims['iat'].is_a?(Numeric) && claims['iat'] <= Time.now.to_i + CLOCK_SKEW_LEEWAY_SECONDS
  end

  def decode_failure_reason(error)
    case error
    when JWT::ExpiredSignature then 'expired'
    when JWT::InvalidIssuerError then 'untrusted_issuer'
    when JWT::VerificationError then 'bad_signature'
    when JWT::IncorrectAlgorithm then 'wrong_algorithm'
    when JWT::MissingRequiredClaim then 'missing_claim'
    else error.message.start_with?('Could not find public key') ? 'unknown_signing_key' : 'invalid'
    end
  end
end
