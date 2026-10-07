require 'rails_helper'

# The six mandatory tests from sso-rules-moneta/proxy-auth-contract.md §Testing,
# adapted to Chatwoot's redirect-handoff shape, plus the app-specific guards.
RSpec.describe 'Sso::ProxyLoginController', type: :request do
  let!(:account) { create(:account) }
  let(:sso_env) { { AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com', DEFAULT_EMAIL_DOMAIN: 'askii.ai' } }

  def get_handoff(headers)
    get '/auth/sso/proxy-login', headers: headers
  end

  describe 'AUTH_TYPE gate (audit row 6)' do
    it 'returns 404 when AUTH_TYPE is not SSO, even with a valid-looking header' do
      with_modified_env AUTH_TYPE: nil do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        expect(response).to have_http_status(:not_found)
      end
    end
  end

  describe 'Rule 3 — auto-provision and hand off' do
    it 'creates the user, joins the oldest account as agent, and redirects with a token' do
      with_modified_env(**sso_env) do
        expect { get_handoff('X-Auth-Request-Email' => 'alice@example.com') }.to change(User, :count).by(1)

        user = User.from_email('alice@example.com')
        expect(user.account_users.first.account).to eq(account)
        expect(user.account_users.first.role).to eq('agent')
        expect(response).to redirect_to(%r{/app/login\?email=alice%40example\.com&sso_auth_token=\w+})
      end
    end

    it 'normalises case and whitespace before the lookup (mandatory test 2)' do
      existing = create(:user, email: 'alice@example.com', account: account)
      with_modified_env(**sso_env) do
        expect { get_handoff('X-Auth-Request-Email' => '  ALICE@EXAMPLE.COM ') }.not_to change(User, :count)
        expect(response.location).to include(ERB::Util.url_encode(existing.email))
      end
    end

    it 'does not match a different user via SQL wildcards' do
      victim = create(:user, email: 'victim@example.com', account: account)
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => 'v%@example.com')
        expect(User.from_email('v%@example.com')).to be_present
        expect(response.location).not_to include(ERB::Util.url_encode(victim.email))
      end
    end

    it 'synthesises an email from a bare Cognito username' do
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => '847392')
        expect(User.from_email('847392@askii.ai')).to be_present
      end
    end

    it 'refuses login when DEFAULT_EMAIL_DOMAIN is unset' do
      with_modified_env(**sso_env, DEFAULT_EMAIL_DOMAIN: nil) do
        expect { get_handoff('X-Auth-Request-Email' => '847392') }.not_to change(User, :count)
        expect(response).to redirect_to(%r{/app/login\?error=sso_failed})
      end
    end

    it 'is idempotent across repeated logins (workspace-auto-join: every login)' do
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        expect { get_handoff('X-Auth-Request-Email' => 'alice@example.com') }.not_to change(AccountUser, :count)
      end
    end
  end

  describe 'header absent' do
    it 'does not provision and redirects with an error (mandatory test 3)' do
      with_modified_env(**sso_env) do
        expect { get_handoff({}) }.not_to change(User, :count)
        expect(response).to redirect_to(%r{/app/login\?error=sso_failed})
      end
    end

    # The failure landing must not find the previous user's SPA cookie, or it reloads
    # the dashboard as that user and an unresolvable identity loops.
    it 'expires the SPA session cookie on the failure redirect' do
      cookies['cw_d_session_info'] = CGI.escape({ uid: 'a@askii.ai' }.to_json)
      with_modified_env(**sso_env) do
        get_handoff({})
        expect(response.headers['Set-Cookie'].to_s).to match(/cw_d_session_info=;.*max-age=0/i)
      end
    end
  end

  describe 'corporate-tenant gate' do
    let(:env) { sso_env.merge(SMB_CORPORATE_ID: 'acme-42') }

    def token(claims)
      "h.#{Base64.urlsafe_encode64(claims.to_json, padding: false)}.s"
    end

    it 'hands off a matching corporate principal' do
      with_modified_env(**env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com',
                    'X-Auth-Request-Access-Token' => token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42'))
        expect(response).to redirect_to(/sso_auth_token/)
      end
    end

    it 'refuses another tenant with 403 and leaves no user row' do
      with_modified_env(**env) do
        expect do
          get_handoff('X-Auth-Request-Email' => 'mallory@example.com',
                      'X-Auth-Request-Access-Token' => token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'))
        end.not_to change(User, :count)
        expect(response).to have_http_status(:forbidden)
      end
    end

    it 'refuses a missing access token with 403' do
      with_modified_env(**env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        expect(response).to have_http_status(:forbidden)
      end
    end
  end

  describe 'workspace auto-join edge cases' do
    it 'skips join entirely when no account exists' do
      Account.destroy_all
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        expect(User.from_email('alice@example.com').account_users).to be_empty
      end
    end

    it 'joins the OLDEST account, not the newest' do
      newer = create(:account)
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        joined = User.from_email('alice@example.com').account_users.first.account
        expect(joined).to eq(account)
        expect(joined).not_to eq(newer)
      end
    end

    it 'does not reject a user who already belongs to another account' do
      other = create(:account)
      user = create(:user, email: 'alice@example.com', account: other)
      with_modified_env(**sso_env) do
        get_handoff('X-Auth-Request-Email' => 'alice@example.com')
        expect(response).to redirect_to(/sso_auth_token/)
        # An existing member is left alone (workspace-auto-join "no DB writes").
        expect(user.reload.accounts).to contain_exactly(other)
      end
    end
  end
end
