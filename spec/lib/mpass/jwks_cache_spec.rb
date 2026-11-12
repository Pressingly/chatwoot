require 'rails_helper'

RSpec.describe Mpass::JwksCache do
  let(:issuer) { MpassTokenHelpers::MPASS_ISSUER }
  let(:now) { [1000.0] }
  let(:jwks_body) { JWT::JWK::Set.new(JWT::JWK.new(MpassTokenHelpers::MPASS_SIGNING_KEY.public_key, kid: 'k')).export.to_json }
  let(:fetches) { [] }
  let(:responses) { [] }
  let(:cache) do
    described_class.new(clock: -> { now.first }, fetcher: lambda { |url|
      fetches << url
      response = responses.shift || jwks_body
      raise response if response.is_a?(Exception)

      response
    })
  end

  it 'fetches once and serves from cache within the lifespan' do
    2.times { cache.keys_for(issuer) }
    expect(fetches).to eq(["#{issuer}/.well-known/jwks.json"])
  end

  it 'refetches after the lifespan' do
    cache.keys_for(issuer)
    now[0] += described_class::LIFESPAN_SECONDS + 1
    cache.keys_for(issuer)
    expect(fetches.size).to eq(2)
  end

  it 'refreshes for an unknown kid at most once per backoff window' do
    cache.keys_for(issuer)
    cache.keys_for(issuer, refresh: true)
    now[0] += described_class::FAILURE_BACKOFF_SECONDS
    cache.keys_for(issuer, refresh: true)
    expect(fetches.size).to eq(2)
  end

  it 'backs off for 30 seconds after a failed fetch, then retries' do
    responses << Net::OpenTimeout.new
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
    now[0] += described_class::FAILURE_BACKOFF_SECONDS - 1
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
    expect(fetches.size).to eq(1)
    now[0] += 1
    expect(cache.keys_for(issuer)).to be_a(JWT::JWK::Set)
  end

  it 'treats a non-JSON body as unavailable' do
    responses << 'not json'
    expect { cache.keys_for(issuer) }.to raise_error(described_class::Unavailable)
  end
end
