require 'rails_helper'

RSpec.describe 'Proxy login session lifetime', type: :request do
  let(:account) { create(:account) }
  let(:sso_env) do
    { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => account.id.to_s, 'SMB_NAME' => 'chat', 'SESSION_COOKIE_MAX_AGE_SECONDS' => '86400',
      'SSO_TRUSTED_PROXY_CIDRS' => '127.0.0.1/32' }
  end
  let(:proxy) { { 'X-Auth-Request-Email' => 'alice@example.com' } }

  around do |example|
    original = DeviseTokenAuth.token_lifespan
    with_modified_env(sso_env) do
      load Rails.root.join('config/initializers/devise_token_auth.rb')
      example.run
    end
  ensure
    DeviseTokenAuth.token_lifespan = original
  end

  it 'returns an expiry header equal to now plus the configured lifetime' do
    freeze_time do
      post '/proxy_auth/session', headers: proxy
      expect(response.headers['expiry'].to_i).to eq(86_400.seconds.from_now.to_i)
    end
  end

  it 'rejects the token at validate_token after the lifetime even with continuous activity' do
    post '/proxy_auth/session', headers: proxy
    auth = response.headers.slice('access-token', 'client', 'uid', 'token-type')

    2.times do
      travel 8.hours
      get '/auth/validate_token', headers: auth.merge(proxy)
      expect(response).to have_http_status(:success)
    end
    travel 9.hours # 25 hours since login, activity every 8 hours in between

    get '/auth/validate_token', headers: auth.merge(proxy)
    expect(response).to have_http_status(:unauthorized)
  ensure
    travel_back
  end
end
