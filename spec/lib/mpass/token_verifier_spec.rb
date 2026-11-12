require 'rails_helper'

RSpec.describe Mpass::TokenVerifier do
  let(:issuer) { MpassTokenHelpers::MPASS_ISSUER }
  let(:proxy_issuer) { 'https://mpass-auth.example.com' }
  let(:verifier) do
    described_class.new(cognito_issuer: issuer, extra_issuers: [proxy_issuer], client_id: MpassTokenHelpers::MPASS_CLIENT_ID,
                        jwks_cache: Mpass::JwksCache.new)
  end

  def reason_for(token)
    verifier.verify(token)
    nil
  rescue described_class::InvalidToken => e
    e.reason
  end

  def unsigned(header, claims)
    "#{[header.to_json, claims.to_json].map { |part| Base64.urlsafe_encode64(part, padding: false) }.join('.')}."
  end

  before { stub_mpass_jwks }

  it 'accepts a Cognito access token for the configured client' do
    expect(verifier.verify(mpass_token)).to include('client_id' => MpassTokenHelpers::MPASS_CLIENT_ID)
  end

  it 'accepts an id_token whose aud names the client' do
    token = mpass_token('token_use' => 'id', 'client_id' => nil, 'aud' => MpassTokenHelpers::MPASS_CLIENT_ID)
    expect(reason_for(token)).to be_nil
  end

  it 'accepts a token from the mpass-auth-proxy issuer against its own JWKS' do
    stub_mpass_jwks(proxy_issuer)
    expect(reason_for(mpass_token('iss' => proxy_issuer, 'token_use' => 'id', 'aud' => [MpassTokenHelpers::MPASS_CLIENT_ID]))).to be_nil
  end

  it 'tolerates 60 seconds of clock skew' do
    expect(reason_for(mpass_token('exp' => Time.now.to_i - 30, 'iat' => Time.now.to_i + 30))).to be_nil
  end

  {
    'a bad signature' => [-> { mpass_token({}, OpenSSL::PKey::RSA.generate(2048)) }, 'bad_signature'],
    'an expired token' => [-> { mpass_token('exp' => Time.now.to_i - 120) }, 'expired'],
    'a token issued in the future' => [-> { mpass_token('iat' => Time.now.to_i + 600) }, 'invalid'],
    'an untrusted issuer' => [-> { mpass_token('iss' => 'https://evil.example.com') }, 'untrusted_issuer'],
    'another client' => [-> { mpass_token('client_id' => 'other-client') }, 'wrong_audience'],
    'an id_token for another audience' => [-> { mpass_token('token_use' => 'id', 'aud' => 'other-client') }, 'wrong_audience'],
    'an unknown token_use' => [-> { mpass_token('token_use' => 'refresh') }, 'wrong_audience'],
    'a token without token_use' => [-> { mpass_token('token_use' => nil) }, 'missing_claim'],
    'an unknown kid' => [-> { mpass_token({}, MpassTokenHelpers::MPASS_SIGNING_KEY, 'rotated-away') }, 'unknown_signing_key'],
    'alg none' => [-> { unsigned({ alg: 'none' }, mpass_claims) }, 'wrong_algorithm'],
    'HS256 keyed with the public key' => [
      -> { JWT.encode(mpass_claims, MpassTokenHelpers::MPASS_SIGNING_KEY.public_key.to_pem, 'HS256', kid: MpassTokenHelpers::MPASS_KID) },
      'wrong_algorithm'
    ],
    'garbage' => [-> { 'not-a-jwt' }, 'malformed']
  }.each do |description, (build, reason)|
    it "refuses #{description} with reason #{reason}" do
      expect(reason_for(instance_exec(&build))).to eq(reason)
    end
  end

  it 'refuses everything when unconfigured' do
    unconfigured = described_class.new(cognito_issuer: '', client_id: '', jwks_cache: Mpass::JwksCache.new)
    expect(unconfigured.configured?).to be false
    expect { unconfigured.verify(mpass_token) }.to raise_error(described_class::InvalidToken, 'verifier_unconfigured')
  end

  it 'reports jwks_unavailable when the JWKS endpoint fails' do
    stub_request(:get, "#{issuer}/.well-known/jwks.json").to_return(status: 503)
    expect(reason_for(mpass_token)).to eq('jwks_unavailable')
  end

  it 'reports jwks_unavailable when the JWKS body is not a key set' do
    stub_request(:get, "#{issuer}/.well-known/jwks.json").to_return(status: 200, body: '{"nope":1}')
    expect(reason_for(mpass_token)).to eq('jwks_unavailable')
  end

  describe '.from_env' do
    it 'strips trailing slashes and treats CHANGE_ME_ placeholders as unset' do
      env = { 'MPASS_COGNITO_ISSUER_URL' => "#{issuer}//", 'MPASS_TOKEN_ISSUER_URL' => 'CHANGE_ME_ISSUER',
              'MPASS_OIDC_CLIENT_ID' => 'client' }
      from_env = described_class.from_env(env)
      expect(from_env.issuers).to eq([issuer])
      expect(from_env).to be_configured
    end

    it 'falls back to the Cognito region and pool id' do
      env = { 'COGNITO_AWS_REGION' => 'eu-west-1', 'COGNITO_USER_POOL_ID' => 'eu-west-1_spec', 'MPASS_OIDC_CLIENT_ID' => 'client' }
      expect(described_class.from_env(env).issuers).to eq([issuer])
    end

    it 'is unconfigured without a Cognito issuer, even with the proxy issuer set' do
      env = { 'MPASS_TOKEN_ISSUER_URL' => proxy_issuer, 'MPASS_OIDC_CLIENT_ID' => 'client' }
      expect(described_class.from_env(env)).not_to be_configured
    end
  end
end
