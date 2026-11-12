# frozen_string_literal: true

# Process-wide JWKS per issuer, shared by Puma's threads. The mutex guards only the
# bookkeeping; the HTTP fetch runs outside it, one in flight per issuer, so a slow
# issuer never blocks lookups for another. A failed fetch backs the issuer off for
# FAILURE_BACKOFF_SECONDS, and while a previously fetched set is younger than
# STALE_GRACE_SECONDS it keeps being served, so an issuer outage does not turn
# into refused logins.
class Mpass::JwksCache
  class Unavailable < StandardError; end

  LIFESPAN_SECONDS = 3600
  FETCH_TIMEOUT_SECONDS = 2
  FAILURE_BACKOFF_SECONDS = 30
  STALE_GRACE_SECONDS = 24 * 3600

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

  def initialize(fetcher: self.class.method(:http_get), clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                 logger: Rails.logger)
    @fetcher = fetcher
    @clock = clock
    @logger = logger
    @mutex = Mutex.new
    @fetch_finished = ConditionVariable.new
    @entries = {}
    @failed_at = {}
    @in_flight = {}
  end

  # refresh: true is the key-rotation path (the token's kid is not in the cached
  # set). It refetches at most once per backoff window.
  def keys_for(issuer, refresh: false)
    action, keys = @mutex.synchronize { claim_or_wait(issuer, refresh) }
    return keys if action == :use

    fetch(issuer)
  end

  def reset!
    @mutex.synchronize do
      @entries.clear
      @failed_at.clear
      @in_flight.clear
    end
  end

  def parse(body)
    document = JSON.parse(body)
    raise Unavailable, 'JWKS has no keys array' unless document.is_a?(Hash) && document['keys'].is_a?(Array)

    importable = document['keys'].select { |jwk| importable?(jwk) }
    raise Unavailable, 'JWKS has no usable keys' if importable.empty?

    JWT::JWK::Set.new('keys' => importable)
  end

  private

  def claim_or_wait(issuer, refresh)
    loop do
      entry = @entries[issuer]
      return [:use, entry[:keys]] if entry && fresh?(entry, refresh)
      return [:use, serve_stale(issuer, entry)] if backing_off?(issuer) || (@in_flight[issuer] && entry)

      unless @in_flight[issuer]
        @in_flight[issuer] = true
        return [:fetch, nil]
      end
      @fetch_finished.wait(@mutex, FETCH_TIMEOUT_SECONDS * 2)
    end
  end

  def fetch(issuer)
    keys = parse(@fetcher.call(self.class.jwks_url(issuer)))
    @mutex.synchronize { record_success(issuer, keys) }
  rescue StandardError => e
    @mutex.synchronize { record_failure(issuer, e) }
  end

  def record_success(issuer, keys)
    @failed_at.delete(issuer)
    @entries[issuer] = { keys: keys, fetched_at: @clock.call }
    finish(issuer)
    keys
  end

  def record_failure(issuer, error)
    @failed_at[issuer] = @clock.call
    finish(issuer)
    @logger.warn("mPass JWKS fetch failed for #{issuer}: #{error.message}")
    serve_stale(issuer, @entries[issuer])
  end

  def finish(issuer)
    @in_flight.delete(issuer)
    @fetch_finished.broadcast
  end

  def serve_stale(issuer, entry)
    raise Unavailable, "no usable JWKS for #{issuer}" unless entry && age(entry) < STALE_GRACE_SECONDS

    @logger.warn("mPass JWKS for #{issuer} is stale (#{age(entry).round}s old); serving the last good set") unless fresh?(entry, false)
    entry[:keys]
  end

  def fresh?(entry, refresh)
    age(entry) < (refresh ? FAILURE_BACKOFF_SECONDS : LIFESPAN_SECONDS)
  end

  def age(entry)
    @clock.call - entry[:fetched_at]
  end

  def backing_off?(issuer)
    failed_at = @failed_at[issuer]
    failed_at.present? && @clock.call - failed_at < FAILURE_BACKOFF_SECONDS
  end

  def importable?(jwk)
    JWT::JWK.new(jwk)
    true
  rescue StandardError => e
    @logger.warn("mPass JWKS key skipped: kid=#{jwk.is_a?(Hash) ? jwk['kid'] : '-'} (#{e.class})")
    false
  end
end
