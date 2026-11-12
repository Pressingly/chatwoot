# frozen_string_literal: true

# Rack middleware: mPass identity headers count only on requests Traefik's
# chatwoot-secure router sent, which carry MPASS_EDGE_SECRET in X-Mpass-Edge-Secret.
# Chatwoot's port is reachable from every container on the backend network, so a
# direct call could otherwise assert any identity. Untrusted X-Auth-Request-*
# headers are dropped here, before any controller reads them, and the secret
# itself never travels past this point, so no log or error report can carry it.
class Mpass::EdgeTrust
  EDGE_SECRET_HEADER = 'HTTP_X_MPASS_EDGE_SECRET'
  IDENTITY_HEADER_PREFIX = 'HTTP_X_AUTH_REQUEST_'
  MPASS_ID_HEADERS = %w[HTTP_X_AUTH_REQUEST_USER HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME HTTP_X_AUTH_REQUEST_EMAIL].freeze
  MIN_SECRET_LENGTH = 32

  def self.configured_secret(env = ENV)
    Mpass::TokenVerifier.configured(env.fetch('MPASS_EDGE_SECRET', ''))
  end

  def self.usable_secret?(secret)
    secret.length >= MIN_SECRET_LENGTH
  end

  def self.from_edge?(rack_env, secret)
    return false unless usable_secret?(secret)

    ActiveSupport::SecurityUtils.secure_compare(secret, rack_env[EDGE_SECRET_HEADER].to_s)
  end

  def self.identity_header?(key)
    key.start_with?(IDENTITY_HEADER_PREFIX)
  end

  def self.carries_identity?(rack_env)
    rack_env.any? { |key, value| identity_header?(key) && value.present? }
  end

  # Logs carry the mPass id, never an email: with email capture on, the asserted
  # value is a real address.
  def self.mpass_id_for_logs(rack_env)
    MPASS_ID_HEADERS.map { |header| rack_env[header].to_s.strip }
                    .find { |value| value.present? && value.exclude?('@') } || '-'
  end

  def self.sanitised(rack_env, trusted:)
    rack_env.reject { |key, _| key == EDGE_SECRET_HEADER || (!trusted && identity_header?(key)) }
  end

  def initialize(app, logger: Rails.logger)
    @app = app
    @logger = logger
  end

  def call(rack_env)
    trusted = self.class.from_edge?(rack_env, self.class.configured_secret)
    warn_untrusted(rack_env) if !trusted && self.class.carries_identity?(rack_env)
    @app.call(self.class.sanitised(rack_env, trusted: trusted))
  end

  private

  def warn_untrusted(rack_env)
    @logger.warn(
      'mPass identity headers ignored: request lacks the edge secret ' \
      "mpass_id=#{self.class.mpass_id_for_logs(rack_env)} path=#{rack_env['PATH_INFO']} " \
      "remote_addr=#{rack_env['REMOTE_ADDR'] || '-'}"
    )
  end
end
