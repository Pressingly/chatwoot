# frozen_string_literal: true

# Process-wide JWKS per issuer. Puma serves requests on several threads, so every
# read and refresh goes through one mutex. After a failed fetch the issuer is not
# retried for FAILURE_BACKOFF_SECONDS, so an issuer outage costs each request a
# cache lookup instead of a 2-second timeout.
class Mpass::JwksCache
  class Unavailable < StandardError; end

  LIFESPAN_SECONDS = 3600
  FETCH_TIMEOUT_SECONDS = 2
  FAILURE_BACKOFF_SECONDS = 30

  def self.shared
    @shared ||= new
  end

  def self.jwks_url(issuer)
    "#{issuer.delete_suffix('/')}/.well-known/jwks.json"
  end

  def self.http_get(url)
    uri = URI.parse(url)
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                                   open_timeout: FETCH_TIMEOUT_SECONDS, read_timeout: FETCH_TIMEOUT_SECONDS) do |http|
      http.get(uri.request_uri)
    end
    raise Unavailable, "JWKS answered #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    response.body
  end

  def self.parse(body)
    document = JSON.parse(body)
    raise Unavailable, 'JWKS has no keys array' unless document.is_a?(Hash) && document['keys'].is_a?(Array)

    JWT::JWK::Set.new(document)
  end

  def initialize(fetcher: self.class.method(:http_get), clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
    @fetcher = fetcher
    @clock = clock
    @mutex = Mutex.new
    @entries = {}
    @failed_at = {}
  end

  # refresh: true is the key-rotation path (the token's kid is not in the cached
  # set). It refetches at most once per backoff window.
  def keys_for(issuer, refresh: false)
    @mutex.synchronize do
      entry = @entries[issuer]
      next entry[:keys] if entry && reusable?(entry, refresh)
      raise Unavailable, 'JWKS fetch backing off' if backing_off?(issuer)

      fetch(issuer)
    end
  end

  def reset!
    @mutex.synchronize do
      @entries.clear
      @failed_at.clear
    end
  end

  private

  def reusable?(entry, refresh)
    max_age = refresh ? FAILURE_BACKOFF_SECONDS : LIFESPAN_SECONDS
    @clock.call - entry[:fetched_at] < max_age
  end

  def backing_off?(issuer)
    failed_at = @failed_at[issuer]
    failed_at.present? && @clock.call - failed_at < FAILURE_BACKOFF_SECONDS
  end

  def fetch(issuer)
    keys = self.class.parse(@fetcher.call(self.class.jwks_url(issuer)))
    @failed_at.delete(issuer)
    @entries[issuer] = { keys: keys, fetched_at: @clock.call }
    keys
  rescue StandardError => e
    @failed_at[issuer] = @clock.call
    raise Unavailable, e.message
  end
end
