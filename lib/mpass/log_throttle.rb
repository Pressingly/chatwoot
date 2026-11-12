# frozen_string_literal: true

# Lets a recurring warning through once per key per interval, so a condition that
# hits every request (an issuer outage, say) logs once a minute, not per request.
class Mpass::LogThrottle
  INTERVAL_SECONDS = 60

  def self.shared
    @shared ||= new
  end

  def initialize(interval: INTERVAL_SECONDS, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
    @interval = interval
    @clock = clock
    @mutex = Mutex.new
    @last_logged_at = {}
  end

  def allow?(key)
    @mutex.synchronize do
      now = @clock.call
      last = @last_logged_at[key]
      next false if last && now - last < @interval

      @last_logged_at[key] = now
      true
    end
  end

  def reset!
    @mutex.synchronize { @last_logged_at.clear }
  end
end
