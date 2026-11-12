require 'rails_helper'

RSpec.describe Mpass::JwksCache do
  let(:issuer) { MpassTokenHelpers::MPASS_ISSUER }
  let(:now) { [1000.0] }
  let(:good_jwk) { JWT::JWK.new(MpassTokenHelpers::MPASS_SIGNING_KEY.public_key, kid: 'k').export }
  let(:jwks_body) { { keys: [good_jwk] }.to_json }
  let(:fetches) { [] }
  let(:responses) { [] }
  let(:logger) { instance_double(ActiveSupport::Logger, warn: nil) }
  let(:fetcher) do
    lambda { |url|
      fetches << url
      response = responses.shift || jwks_body
      raise response if response.is_a?(Exception)

      response
    }
  end
  let(:cache) { described_class.new(clock: -> { now.first }, fetcher: fetcher, logger: logger) }

  def advance(seconds)
    now[0] += seconds
  end

  it 'fetches once and serves from cache within the lifespan' do
    2.times { cache.keys_for(issuer) }
    expect(fetches).to eq(["#{issuer}/.well-known/jwks.json"])
  end

  it 'refetches after the lifespan' do
    cache.keys_for(issuer)
    advance(described_class::LIFESPAN_SECONDS + 1)
    cache.keys_for(issuer)
    expect(fetches.size).to eq(2)
  end

  it 'refreshes for an unknown kid at most once per backoff window' do
    cache.keys_for(issuer)
    cache.keys_for(issuer, refresh: true)
    advance(described_class::FAILURE_BACKOFF_SECONDS)
    cache.keys_for(issuer, refresh: true)
    expect(fetches.size).to eq(2)
  end

  it 'raises Unavailable for an issuer that was never fetched, and backs off for 30 seconds' do
    responses << Net::OpenTimeout.new
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
    advance(described_class::FAILURE_BACKOFF_SECONDS - 1)
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
    expect(fetches.size).to eq(1)
    advance(1)
    expect(cache.keys_for(issuer)).to be_a(JWT::JWK::Set)
  end

  it 'serves the last good set, with a warning, when a refresh fails within the grace period' do
    cache.keys_for(issuer)
    advance(described_class::LIFESPAN_SECONDS + 1)
    responses << Net::OpenTimeout.new
    expect(cache.keys_for(issuer).size).to eq(1)
    expect(cache.keys_for(issuer).size).to eq(1)
    expect(fetches.size).to eq(2)
    expect(logger).to have_received(:warn).with(/is stale/).at_least(:once)
  end

  it 'stops serving the last good set once it is older than the grace period' do
    cache.keys_for(issuer)
    advance(described_class::STALE_GRACE_SECONDS + 1)
    responses << Net::OpenTimeout.new
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
  end

  it 'skips a key that fails to import and logs its kid' do
    responses << { keys: [{ 'kty' => 'RSA', 'kid' => 'broken' }, good_jwk] }.to_json
    expect(cache.keys_for(issuer).map { |key| key[:kid] }).to eq(['k'])
    expect(logger).to have_received(:warn).with(/key skipped: kid=broken/)
  end

  it 'treats a body without usable keys as unavailable' do
    responses << 'not json'
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
  end

  it 'runs one fetch per issuer at a time, outside the lock' do
    started = Queue.new
    release = Queue.new
    slow = lambda { |url|
      fetches << url
      started << true
      release.pop
      jwks_body
    }
    slow_cache = described_class.new(clock: -> { now.first }, fetcher: slow, logger: logger)
    first = Thread.new { slow_cache.keys_for(issuer) }
    started.pop
    other_issuer = Thread.new { slow_cache.keys_for('https://other.example.com') }
    started.pop
    waiters = Array.new(3) { Thread.new { slow_cache.keys_for(issuer) } }
    2.times { release << true }
    [first, other_issuer, *waiters].each(&:join)
    expect(fetches.count("#{issuer}/.well-known/jwks.json")).to eq(1)
    expect(waiters.map(&:value)).to all(be_a(JWT::JWK::Set))
  end
end
