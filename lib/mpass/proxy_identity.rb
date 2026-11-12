# frozen_string_literal: true

# Reads the identity oauth2-proxy asserts on ForwardAuth-protected requests.
#
# Mpass::EdgeTrust has already dropped these headers unless the request carried
# the edge secret only Traefik's chatwoot-secure router injects, so whatever is
# left here came through mPass ForwardAuth. With SMB_CORPORATE_ID set, the
# forwarded token is also verified against the issuers' JWKS before its corporate
# claims count. Do not read these headers outside an AUTH_TYPE=SSO gate.
#
module Mpass::ProxyIdentity
  EMAIL_HEADER = 'HTTP_X_AUTH_REQUEST_EMAIL'
  PREFERRED_USERNAME_HEADER = 'HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME'
  ACCESS_TOKEN_HEADER = 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'

  UUID_SHAPE = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/
  NUMERIC = /\A\d+\z/
  CLAIM_REJECTIONS = %w[not_corporate wrong_organization].freeze

  module_function

  # The single switch for every mPass behaviour in this fork. Everything SSO-only
  # asks this, so the gate cannot drift between call sites.
  def sso_mode?
    ENV.fetch('AUTH_TYPE', nil) == 'SSO'
  end

  # Whether the proxy asserted ANY identity, resolvable or not. A header present but
  # unresolvable (bare username with DEFAULT_EMAIL_DOMAIN unset) is not an absence:
  # proxy-auth-middleware "Mismatch with unresolvable upstream identity also flushes".
  def asserted?(request)
    normalise(request.get_header(EMAIL_HEADER)).present?
  end

  # The normalised email this request asserts, or nil when no identity is present.
  # Absence is NOT a logout signal — internal traffic (Sidekiq, health probes,
  # direct container hits) legitimately carries no header. X-Auth-Request-User is
  # deliberately not a fallback: it is the Cognito `sub`, not the user key.
  def email(request)
    raw = normalise(request.get_header(EMAIL_HEADER))
    return nil if raw.blank?

    email_shaped?(raw) ? raw : synthesise(raw)
  end

  # Applied to BOTH sides of every comparison and to the DB lookup.
  def normalise(value)
    value.to_s.strip.downcase.presence
  end

  # indexOf-based by contract, never a regex. The canonical email-shape pattern
  # backtracks polynomially on adversarial input; CodeQL's js/polynomial-redos
  # flags it. See proxy-auth-middleware/spec.md "email-shape detection": an `@`
  # that isn't first, then a `.` at least one character after it. Matching the
  # canonical check keeps `a@b` resolving to the same user row in every app.
  def email_shaped?(value)
    value = value.to_s
    at = value.index('@')
    return false if at.nil? || at.zero?

    dot = value.index('.', at + 1)
    !dot.nil? && dot > at + 1
  end

  # Corporate-tenant binding (proxy-auth-middleware "corporate-tenant binding SHALL
  # gate admission when configured"). ForwardAuth admits the whole Cognito pool;
  # with SMB_CORPORATE_ID set, only that corporate's principals get in. Unset, the
  # check is skipped and no token is read. Returns why the caller is refused, or
  # nil when it is admitted; a missing or unverifiable token fails closed.
  def corporate_rejection(request, verifier: Mpass::TokenVerifier.from_env)
    expected = corporate_id
    return nil if expected.blank?

    token = request.get_header(ACCESS_TOKEN_HEADER).to_s
    return 'missing_token' if token.blank?

    corporate_claims_rejection(verifier.verify(token), expected)
  rescue Mpass::TokenVerifier::InvalidToken => e
    e.reason
  end

  # The per-request re-check on an existing session. Only a verified token whose
  # claims name another tenant ends the session; a token that cannot be verified
  # right now (expired between refreshes, JWKS unreachable) leaves it alone, so an
  # issuer outage cannot log everyone out. The handoff stays strict.
  def corporate_mismatch?(request)
    reason = corporate_rejection(request)
    return false if reason.nil?
    return true if CLAIM_REJECTIONS.include?(reason)

    Rails.logger.warn(
      "mPass corporate re-check skipped: reason=#{reason} mpass_id=#{Mpass::EdgeTrust.mpass_id_for_logs(request.env)} path=#{request.path}"
    )
    false
  end

  def corporate_id
    Mpass::TokenVerifier.configured(ENV.fetch('SMB_CORPORATE_ID', nil))
  end

  def corporate_claims_rejection(claims, expected)
    return 'not_corporate' unless claims['custom:is_corporate'] == 'true'
    return 'wrong_organization' unless claims['custom:corporate_id'] == expected

    nil
  end

  # Moneta's Cognito pool returns the literal placeholder "cognito:default_val"
  # for the email claim, so identity arrives as cognito:username — a bare number.
  # Fails closed: without DEFAULT_EMAIL_DOMAIN there is no identity, never a guessed one.
  def synthesise(username)
    domain = normalise(ENV.fetch('DEFAULT_EMAIL_DOMAIN', nil))
    return nil if domain.blank?

    "#{username}@#{domain}"
  end

  # Audit row 19: a display name must never be a UUID. Prefer a real name claim
  # when the synthesised local-part is a bare Cognito ID, but reject the claim
  # when it is itself a `sub` UUID.
  def display_name(request, email_value)
    local_part = email_value.to_s.split('@').first
    return local_part unless local_part.match?(NUMERIC)

    claim = request.get_header(PREFERRED_USERNAME_HEADER).to_s.strip
    return local_part if claim.blank? || claim.match?(UUID_SHAPE)

    claim
  end
end
