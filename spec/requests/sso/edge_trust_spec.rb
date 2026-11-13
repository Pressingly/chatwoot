require 'rails_helper'

# A direct call on the backend network bypasses Traefik, so it carries no edge
# secret: whatever identity it names must change nothing, and the paths that never
# relied on mPass (API tokens, the widget) must keep working.
RSpec.describe 'mPass edge trust', type: :request do
  let!(:account) { create(:account) }
  let(:user_a) { create(:user, email: 'a@askii.ai', account: account) }
  let(:sso_env) { { AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com', MPASS_EDGE_SECRET: MpassTokenHelpers::MPASS_EDGE_SECRET } }
  let(:forged) { { 'X-Auth-Request-Email' => 'b@askii.ai', 'X-Mpass-Edge-Secret' => 'forged-secret-that-is-long-enough-to-count' } }

  it 'does not flush a dashboard session over a forged identity' do
    token_a = user_a.create_new_auth_token
    with_modified_env(**sso_env) do
      get "/api/v1/accounts/#{account.id}/conversations", headers: token_a.merge(forged)
      expect(response).to have_http_status(:success)
      expect(response.headers['X-Mpass-Session-Flushed']).to be_nil
      expect(user_a.reload.tokens.keys).to include(token_a['client'])
    end
  end

  it 'does not start the handoff on a document request with a forged identity' do
    with_modified_env(**sso_env) do
      get '/app', headers: forged
      expect(response).to have_http_status(:success)
    end
  end

  it 'serves an api_access_token caller carrying forged headers' do
    with_modified_env(**sso_env) do
      get "/api/v1/accounts/#{account.id}/conversations", headers: forged.merge('api_access_token' => user_a.access_token.token)
      expect(response).to have_http_status(:success)
    end
  end

  it 'serves the public widget config with forged headers' do
    web_widget = create(:channel_widget, account: account)
    with_modified_env(**sso_env) do
      post '/api/v1/widget/config', params: { website_token: web_widget.website_token }, headers: forged, as: :json
      expect(response).to have_http_status(:success)
    end
  end

  it 'still serves the widget with no mPass configuration at all' do
    web_widget = create(:channel_widget, account: account)
    with_modified_env(**sso_env, MPASS_EDGE_SECRET: nil) do
      post '/api/v1/widget/config', params: { website_token: web_widget.website_token }, as: :json
      expect(response).to have_http_status(:success)
    end
  end
end
