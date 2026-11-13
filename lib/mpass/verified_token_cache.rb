# frozen_string_literal: true

# Claims of tokens that already passed verification, keyed by a digest of the
# token and the verifier's configuration, kept until the token's exp. The gate
# re-checks the same token on every request of a session, so without this each
# request would repeat the signature check. Bounded: expired entries go first,
# then the ones expiring soonest.
class Mpass::VerifiedTokenCache
  MAX_ENTRIES = 1000

  def self.shared
    @shared ||= new
  end

  def self.key_for(token, scope)
    Digest::SHA256.hexdigest("#{scope}\0#{token}")
  end

  def initialize(max_entries: MAX_ENTRIES, clock: -> { Time.now.to_i })
    @max_entries = max_entries
    @clock = clock
    @mutex = Mutex.new
    @entries = {}
  end

  def fetch(key)
    @mutex.synchronize do
      entry = @entries[key]
      next nil unless entry
      next entry[:claims] if entry[:expires_at] > @clock.call

      @entries.delete(key)
      nil
    end
  end

  def store(key, claims)
    @mutex.synchronize do
      evict if @entries.size >= @max_entries
      @entries[key] = { claims: claims.freeze, expires_at: claims['exp'].to_i }
    end
    claims
  end

  def size
    @mutex.synchronize { @entries.size }
  end

  def reset!
    @mutex.synchronize { @entries.clear }
  end

  private

  def evict
    now = @clock.call
    @entries.delete_if { |_, entry| entry[:expires_at] <= now }
    return if @entries.size < @max_entries

    soonest = @entries.min_by(@entries.size - @max_entries + 1) { |_, entry| entry[:expires_at] }
    soonest.map(&:first).each { |key| @entries.delete(key) }
  end
end
