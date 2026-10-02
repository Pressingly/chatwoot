require 'rails_helper'

# audit row 15 — the SERVER half. The SPA route guard only removes the affordance;
# these endpoints stay reachable by curl. `PUT /auth/password` is the sharpest: it
# resets the password AND calls send_auth_headers, returning a live session — a
# complete credential path around mPass.
RSpec.describe 'local-credential endpoints under SSO', type: :request do
  let!(:account) { create(:account) }
  let!(:user) { create(:user, email: 'alice@askii.ai', account: account) }

  context 'when AUTH_TYPE=SSO' do
    around { |ex| with_modified_env(AUTH_TYPE: 'SSO') { ex.run } }

    it 'refuses the password-reset request' do
      post '/auth/password', params: { email: user.email }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses the password-reset submission' do
      put '/auth/password', params: { reset_password_token: 'x', password: 'NewPassword1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'does not send a reset email' do
      expect { post '/auth/password', params: { email: user.email } }
        .not_to(change { ActionMailer::Base.deliveries.size })
    end

    it 'refuses self-registration' do
      expect do
        post '/api/v1/accounts', params: {
          account_name: 'Evil Co', user_full_name: 'E', email: 'evil@example.com', password: 'Password1!'
        }
      end.not_to change(User, :count)
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses installation onboarding while the flag is set' do
      Redis::Alfred.set(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING, true)
      post '/installation/onboarding', params: { user: { name: 'x', email: 'x@x.io', password: 'Password1!' } }
      expect(response).to have_http_status(:not_found)
    ensure
      Redis::Alfred.delete(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING)
    end

    it 'refuses confirmation resend' do
      post '/resend_confirmation', params: { email: user.email }
      expect(response).to have_http_status(:not_found)
    end

    # The sharpest of the set for a fork that pre-dates SSO: every account created
    # before the integration still has a working local password, and the form the
    # SPA used to render is only an affordance — this endpoint answers curl.
    it 'refuses a password login' do
      post '/auth/sign_in', params: { email: user.email, password: 'Password1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses a password login sent as credential headers' do
      post '/auth/sign_in', headers: { 'email' => user.email, 'password' => 'Password1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses an MFA verification' do
      post '/auth/sign_in', params: { mfa_token: 'some-token', otp_code: '123456' }
      expect(response).to have_http_status(:not_found)
    end

    # Review finding: the gate once checked only that sso_auth_token was PRESENT, so
    # any value plus a password fell through to DTA's password login.
    it 'refuses a password login carrying a bogus handoff token' do
      post '/auth/sign_in', params: { email: user.email, password: 'Password1!', sso_auth_token: 'x' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses an MFA verification carrying a bogus handoff token' do
      post '/auth/sign_in', params: { mfa_token: 'some-token', otp_code: '123456', sso_auth_token: 'x' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses a valid handoff token sent together with a password' do
      token = user.generate_sso_auth_token
      post '/auth/sign_in', params: { email: user.email, password: 'Password1!', sso_auth_token: token }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses v2 self-registration, which returns a session' do
      post '/api/v2/accounts', params: { user: { email: 'new@example.com', password: 'Password1!' } }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses MFA enrolment' do
      post '/api/v1/profile/mfa', headers: user.create_new_auth_token
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses profile confirmation resend' do
      post '/api/v1/profile/resend_confirmation', headers: user.create_new_auth_token
      expect(response).to have_http_status(:not_found)
    end

    # The gate must be scoped to local credentials only: the handoff re-enters this
    # same action, and a blanket 404 here would break login entirely.
    it 'still accepts the handoff token on the same endpoint' do
      token = user.generate_sso_auth_token
      post '/auth/sign_in', params: { email: user.email, sso_auth_token: token }
      expect(response).to have_http_status(:success)
    end

    # G7: devise_token_auth's default registrations.
    it 'refuses a password change through PUT /auth, in every spelling' do
      before = user.reload.encrypted_password
      %w[/auth /auth.json].each do |path|
        put path, params: { password: 'NewPassword1!', password_confirmation: 'NewPassword1!' },
                  headers: user.create_new_auth_token
        expect(response).to have_http_status(:not_found)
      end
      expect(user.reload.encrypted_password).to eq(before)
    end

    it 'refuses sign-up and self-deletion through /auth' do
      expect { post '/auth', params: { email: 'new@example.com', password: 'Password1!', name: 'N' } }
        .not_to change(User, :count)
      expect(response).to have_http_status(:not_found)

      delete '/auth', headers: user.create_new_auth_token
      expect(response).to have_http_status(:not_found)
    end

    # G10: federated logins are second identity paths.
    # OmniAuth's test mode passes a successful auth hash through, so without the
    # guard these callbacks would sign the user in.
    it 'refuses OmniAuth callbacks that would otherwise sign in' do
      OmniAuth.config.test_mode = true
      OmniAuth.config.mock_auth[:google_oauth2] =
        OmniAuth::AuthHash.new(provider: 'google_oauth2', uid: '1', info: { email: user.email, name: 'A' })

      %w[/omniauth/google_oauth2/callback /auth/google_oauth2/callback /auth/failure /omniauth/failure].each do |path|
        get path
        expect(response).to have_http_status(:not_found), path
      end
    ensure
      OmniAuth.config.mock_auth[:google_oauth2] = nil
      OmniAuth.config.test_mode = false
    end

    it 'refuses the SAML login initiation' do
      post '/api/v1/auth/saml_login', params: { email: user.email }
      expect(response).to have_http_status(:not_found)
    end

    it 'does not route the super-admin console or its Devise defaults' do
      super_admin = create(:super_admin)
      post '/super_admin/sign_in', params: { super_admin: { email: super_admin.email, password: super_admin.password } }
      expect(response).to have_http_status(:not_found)

      [[:get, '/super_admin'], [:post, '/super_admin/password'], [:post, '/super_admin'],
       [:get, '/monitoring/sidekiq']].each do |verb, path|
        public_send(verb, path)
        expect(response).to have_http_status(:not_found), "#{verb} #{path}"
      end
    end

    it 'leaves the SSO handoff itself reachable' do
      with_modified_env(FRONTEND_URL: 'https://support.example.com') do
        get '/auth/sso/proxy-login', headers: { 'X-Auth-Request-Email' => 'alice@askii.ai' }
        expect(response).to have_http_status(:found)
      end
    end
  end

  context 'when AUTH_TYPE is unset (stock Chatwoot)' do
    around { |ex| with_modified_env(AUTH_TYPE: nil) { ex.run } }

    # Upstream's MFA request specs skip without encryption configured, so pin the
    # non-SSO side here: whatever MFA answers, it is not the SSO gate's 404.
    it 'does not gate MFA enrolment' do
      post '/api/v1/profile/mfa', headers: user.create_new_auth_token
      expect(response).not_to have_http_status(:not_found)
    end

    it 'does not gate profile confirmation resend' do
      post '/api/v1/profile/resend_confirmation', headers: user.create_new_auth_token
      expect(response).not_to have_http_status(:not_found)
    end

    # Guards against the gate leaking into non-SSO deployments.
    it 'still serves the password-reset request' do
      post '/auth/password', params: { email: user.email }
      expect(response).not_to have_http_status(:not_found)
    end

    it 'still accepts a password login' do
      post '/auth/sign_in', params: { email: user.email, password: user.password }
      expect(response).to have_http_status(:success)
    end

    it 'still routes PUT /auth' do
      put '/auth', params: { name: 'Renamed' }, headers: user.create_new_auth_token
      expect(response).not_to have_http_status(:not_found)
    end

    it 'still serves the super-admin login' do
      get '/super_admin/sign_in'
      expect(response).to have_http_status(:success)
    end
  end
end
