require 'rails_helper'

# Rule 2 — mandatory tests 1, 4, 5, 6. audit row 20.
RSpec.describe 'mPass session reconciliation', type: :request do
  let!(:account) { create(:account) }
  let(:user_a) { create(:user, email: 'a@askii.ai', account: account) }
  let(:user_b) { create(:user, email: 'b@askii.ai', account: account) }
  let(:sso_env) { { AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com' } }
  # Minted once: each create_new_auth_token call issues a fresh client id, so the
  # eviction assertion needs the same triple the request was made with.
  let(:token_a) { user_a.create_new_auth_token }

  describe 'Path A — document request (DashboardController)' do
    # A document request carries the cw_d_session_info cookie, not auth headers.
    # Encoded exactly as js-cookie 3 writes it: encodeURIComponent, then these
    # characters put back raw — so `+` and `@` reach the server unencoded.
    # `cookies.merge` sends the value as-is; `cookies[]=` would escape it again.
    def with_session_cookie(email)
      encoded = ERB::Util.url_encode({ uid: email }.to_json)
                         .gsub(/%(2[346BF]|3[AC-F]|40|5[BDE]|60|7[BCD])/) { URI.decode_uri_component(Regexp.last_match(0)) }
      cookies.merge("cw_d_session_info=#{encoded}")
    end

    it 'serves normally when the proxy identity MATCHES the session (mandatory test 1)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'a@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    it 'serves normally when the header is ABSENT (mandatory test 3)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app'
        expect(response).to have_http_status(:success)
      end
    end

    it 'redirects into the handoff on MISMATCH (mandatory test 4)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    # Regression: /app/login is dashboard#index too, so the handoff lands back on a
    # reconciled action while the previous user's cookie is still set — the SPA
    # clears it only once this document has loaded. Reconciling it bounced the
    # browser between /app/login and the handoff until it gave up.
    it 'serves the handoff landing page instead of redirecting into it again' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app/login?email=b%40askii.ai&sso_auth_token=sometoken',
            headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    # The ENTRY path. This previously asserted a 200, which described the dead end
    # rather than a requirement: the user scans the QR code, the edge lets them
    # through, and Chatwoot serves its own login form — which under SSO accepts
    # nothing (sessions_controller 404s a password login) and offers no way to
    # start the handoff. First login could not complete at all.
    it 'enters the handoff when there is no session cookie at all (first visit)' do
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    # Devise gives DashboardController a Warden-backed current_user from the httpOnly
    # Rails session. The SPA never sees it: without cw_d_session_info it renders the
    # login page. Found in the devkit e2e run — the server served the app, the SPA
    # showed "Continue with mPass", and nothing re-entered the handoff.
    it 'enters the handoff when only a Warden session exists, without the SPA cookie' do
      sign_in user_b
      with_modified_env(**sso_env) do
        get '/', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    it 'does not let a bare ?sso_auth_token= skip reconciliation outside /app/login' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app/accounts/1/dashboard?sso_auth_token=x', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    # Required regression test: both sides normalised before comparing.
    it 'treats a case- and whitespace-different identity as a MATCH' do
      with_session_cookie('A@Askii.ai ')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => '  a@ASKII.AI  ' }
        expect(response).to have_http_status(:success)
      end
    end

    # Rack form-decodes cookies (`+` → space); a plus-addressed user must not loop.
    it 'treats a plus-addressed identity as a MATCH' do
      create(:user, email: 'a+b@askii.ai', account: account)
      with_session_cookie('a+b@askii.ai')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'a+b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    # proxy-auth-middleware "Mismatch with unresolvable upstream identity also flushes".
    it 'flushes when the asserted identity cannot be resolved' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env, DEFAULT_EMAIL_DOMAIN: nil) do
        get '/app', headers: { 'X-Auth-Request-Email' => '847392' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    it 'enters the handoff from the site root too' do
      with_modified_env(**sso_env) do
        get '/', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    # Entry is gated on an ASSERTED identity, not on the absence of a session. This
    # is what keeps bypass routers out of it: they strip the identity headers and
    # mpass-auth never re-adds them, so a webhook or health probe sees no redirect.
    it 'does not enter the handoff when no identity is asserted' do
      with_modified_env(**sso_env) do
        get '/app'
        expect(response).to have_http_status(:success)
      end
    end

    it 'does not enter the handoff when AUTH_TYPE is not SSO' do
      with_modified_env AUTH_TYPE: nil do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    # The handoff's own failure landing. It carries an identity and no session —
    # exactly the entry condition — so without the ?error= short-circuit a failing
    # handoff would be retried forever instead of surfacing why it failed.
    it 'does not re-enter the handoff on its own error landing' do
      with_modified_env(**sso_env) do
        get '/app/login?error=sso_failed', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    # A cookie we cannot read is not a session. Serving the SPA instead would strand
    # the browser: hasAuthCookie() is true, so it reloads into the dashboard pack and
    # replays garbage credentials, and the 401s that come back carry no flush header
    # for APIHelper to react to. The handoff re-mints and the SPA clears the cookie.
    it 'enters the handoff on a malformed session cookie rather than flushing' do
      cookies['cw_d_session_info'] = 'not-json'
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    it 'does nothing when AUTH_TYPE is not SSO' do
      with_session_cookie('a@askii.ai')
      with_modified_env AUTH_TYPE: nil do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'Path B — XHR (Api::BaseController)' do
    it 'evicts the token and 401s on MISMATCH' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'b@askii.ai')
        expect(response).to have_http_status(:unauthorized)
        expect(user_a.reload.tokens.keys).not_to include(token_a['client'])
      end
    end

    # The SPA hard-navigates on this header, not on the bare 401 — Chatwoot answers
    # 401 for ordinary permission denials too (Pundit::NotAuthorizedError), and
    # those must not log an agent out.
    it 'marks the flush with a header so the SPA can tell it apart from a permission 401' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'b@askii.ai')
        expect(response.headers['X-Mpass-Session-Flushed']).to eq('true')
      end
    end

    it 'does not mark an ordinary permission 401' do
      with_modified_env(**sso_env) do
        # An agent reaching an administrator-only endpoint.
        get "/api/v2/accounts/#{account.id}/reports/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'a@askii.ai')
        expect(response.headers['X-Mpass-Session-Flushed']).to be_nil
      end
    end

    it 'treats a case- and whitespace-different identity as a MATCH' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => '  A@ASKII.AI  ')
        expect(response).to have_http_status(:success)
        expect(user_a.reload.tokens.keys).to include(token_a['client'])
      end
    end

    it 'flushes when the asserted identity cannot be resolved' do
      with_modified_env(**sso_env, DEFAULT_EMAIL_DOMAIN: nil) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => '847392')
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers['X-Mpass-Session-Flushed']).to eq('true')
        expect(user_a.reload.tokens.keys).not_to include(token_a['client'])
      end
    end

    # session-lifecycle: Layer 2 expiry while Layer 1 is valid must re-establish.
    it 'marks a dead token as a flush while the proxy still asserts an identity' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('access-token' => 'expired', 'X-Auth-Request-Email' => 'a@askii.ai')
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers['X-Mpass-Session-Flushed']).to eq('true')
      end
    end

    it 'does not mark a dead token when no identity is asserted' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations", headers: token_a.merge('access-token' => 'expired')
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers['X-Mpass-Session-Flushed']).to be_nil
      end
    end

    it 'leaves a MATCHING session untouched (mandatory test 1)' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'a@askii.ai')
        expect(response).to have_http_status(:success)
      end
    end

    # The defect this guards: a browser-side identity switch must never evict the
    # credential of a platform or bot integration. sso-implementer Step 4 item 5.
    it 'NEVER fires for requests authenticated by an api_access_token (machine-to-machine)' do
      # user_a's API token standing in for an integration. A browser elsewhere is
      # asserting user B; that must not touch this credential.
      api_token = user_a.access_token.token
      token_a # mint the DTA triple so there is something evictable to assert on

      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: { 'api_access_token' => api_token, 'X-Auth-Request-Email' => 'b@askii.ai' }

        expect(response).to have_http_status(:success)
        expect(user_a.reload.tokens.keys).to include(token_a['client'])
      end
    end
  end

  # The corporate gate is enforced on every request, not only at the handoff: an
  # existing session for a principal outside SMB_CORPORATE_ID is flushed.
  describe 'corporate-tenant gate on an existing session' do
    let(:corp_env) { sso_env.merge(SMB_CORPORATE_ID: 'acme-42') }
    let(:acme) { token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42') }
    let(:globex) { token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7') }

    def token(claims)
      "h.#{Base64.urlsafe_encode64(claims.to_json, padding: false)}.s"
    end

    it 'redirects a document request into the handoff, which then refuses it' do
      cookies.merge("cw_d_session_info=#{ERB::Util.url_encode({ uid: 'a@askii.ai' }.to_json)}")
      with_modified_env(**corp_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'a@askii.ai', 'X-Auth-Request-Access-Token' => globex }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    it 'evicts the token and 401s an XHR' do
      with_modified_env(**corp_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'a@askii.ai', 'X-Auth-Request-Access-Token' => globex)
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers['X-Mpass-Session-Flushed']).to eq('true')
        expect(user_a.reload.tokens.keys).not_to include(token_a['client'])
      end
    end

    it 'leaves a matching corporate principal alone' do
      with_modified_env(**corp_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'a@askii.ai', 'X-Auth-Request-Access-Token' => acme)
        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'identity-managed fields are gated SERVER-side (audit row 15)' do
    it 'refuses a password change under SSO' do
      with_modified_env(**sso_env) do
        put '/api/v1/profile', params: { profile: { password: 'NewPassword1!', current_password: 'Password1!' } },
                               headers: token_a
        expect(response).to have_http_status(:unprocessable_entity)
        expect(user_a.reload.valid_password?('NewPassword1!')).to be(false)
      end
    end

    # The gate must not leak into stock Chatwoot: without SSO a user still changes
    # their own password here, with their current one.
    it 'still lets a user change their password without SSO' do
      with_modified_env(AUTH_TYPE: nil) do
        put '/api/v1/profile', params: { profile: { password: 'NewPassword1!', current_password: 'Password1!' } },
                               headers: token_a
        expect(response).to have_http_status(:success)
        expect(user_a.reload.valid_password?('NewPassword1!')).to be(true)
      end
    end

    it 'silently ignores an email change under SSO' do
      with_modified_env(**sso_env) do
        put '/api/v1/profile', params: { profile: { email: 'hijack@example.com' } }, headers: token_a
        expect(user_a.reload.email).to eq('a@askii.ai')
      end
    end
  end

  # The cw_d_session_info cookie is JS-readable by design (the SPA must build its
  # request headers from it), so its contents are attacker-reachable via XSS and
  # corruptible by the user. Valid JSON that is not an object — null, [1,2], 123 —
  # parses cleanly and then raises on []('uid'). Unguarded that 500s EVERY document
  # request, making the dashboard unreachable until the cookie is cleared by hand.
  describe 'hostile session cookie' do
    hostile_cookies = [
      'null',
      '[1,2]',
      '123',
      '"a-bare-string"',
      'not-json',
      '{"uid":{"nested":1}}',
      '{"uid":[1]}'
    ].freeze

    hostile_cookies.each do |payload|
      it "serves rather than crashing on cw_d_session_info=#{payload}" do
        cookies.merge("cw_d_session_info=#{ERB::Util.url_encode(payload)}")
        with_modified_env(**sso_env) do
          get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
          expect(response.status).to be < 500
        end
      end
    end

    it 'treats an unusable cookie as no session, never as a mismatch' do
      cookies.merge('cw_d_session_info=null')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        # No readable identity => the entry path, which re-mints and lets the SPA
        # replace the cookie. What must NOT happen is a crash, or a mismatch flush
        # decided from a value that never identified anyone.
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end
  end
end
