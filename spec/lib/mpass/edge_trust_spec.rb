require 'rails_helper'

RSpec.describe Mpass::EdgeTrust do
  let(:secret) { MpassTokenHelpers::MPASS_EDGE_SECRET }
  let(:logger) { instance_double(ActiveSupport::Logger, warn: nil) }
  let(:seen) { [] }
  let(:middleware) { described_class.new(->(env) { seen.push(env) && [200, {}, []] }, logger: logger) }
  let(:identity) do
    { 'HTTP_X_AUTH_REQUEST_EMAIL' => 'alice@example.com', 'HTTP_X_AUTH_REQUEST_USER' => 'mpass-123',
      'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'token', 'PATH_INFO' => '/app', 'REMOTE_ADDR' => '172.18.0.9' }
  end

  def call(env)
    middleware.call(env)
    seen.last
  end

  around { |ex| with_modified_env(MPASS_EDGE_SECRET: secret) { ex.run } }

  it 'keeps identity headers on a request carrying the edge secret, and drops the secret' do
    passed = call(identity.merge('HTTP_X_MPASS_EDGE_SECRET' => secret))
    expect(passed).to include('HTTP_X_AUTH_REQUEST_EMAIL' => 'alice@example.com', 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => 'token')
    expect(passed).not_to have_key('HTTP_X_MPASS_EDGE_SECRET')
    expect(logger).not_to have_received(:warn)
  end

  it 'drops every identity header without the secret and logs the mPass id, never the email' do
    passed = call(identity)
    expect(passed.keys.grep(/\AHTTP_X_AUTH_REQUEST_/)).to be_empty
    expect(logger).to have_received(:warn).with(%r{mpass_id=mpass-123 path=/app remote_addr=172\.18\.0\.9})
    expect(logger).not_to have_received(:warn).with(/alice@example\.com/)
  end

  it 'drops identity headers on a wrong secret' do
    expect(call(identity.merge('HTTP_X_MPASS_EDGE_SECRET' => "#{secret}x")).keys.grep(/\AHTTP_X_AUTH_REQUEST_/)).to be_empty
  end

  it 'trusts nothing when the configured secret is empty or short' do
    ['', 'a' * 31].each do |configured|
      with_modified_env(MPASS_EDGE_SECRET: configured) do
        expect(call(identity.merge('HTTP_X_MPASS_EDGE_SECRET' => configured)).keys.grep(/\AHTTP_X_AUTH_REQUEST_/)).to be_empty
      end
    end
  end

  it 'treats a CHANGE_ME_ placeholder of any length as unset' do
    placeholder = 'CHANGE_ME_CHATWOOT_EDGE_SECRET_0123456789abcdef'
    with_modified_env(MPASS_EDGE_SECRET: placeholder) do
      expect(call(identity.merge('HTTP_X_MPASS_EDGE_SECRET' => placeholder)).keys.grep(/\AHTTP_X_AUTH_REQUEST_/)).to be_empty
    end
  end

  it 'strips the incoming env in place so callers see what downstream middleware stores in it' do
    env = identity.merge('HTTP_X_MPASS_EDGE_SECRET' => 'forged')
    expect(call(env)).to equal(env)
    expect(env.keys.grep(/\AHTTP_X_(AUTH_REQUEST|MPASS_EDGE_SECRET)/)).to be_empty
  end

  it 'stays quiet without identity headers' do
    call({ 'PATH_INFO' => '/health', 'HTTP_X_MPASS_EDGE_SECRET' => 'forged' })
    expect(logger).not_to have_received(:warn)
  end
end
