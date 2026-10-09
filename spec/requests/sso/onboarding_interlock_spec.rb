require 'rails_helper'

# workspace-auto-join/spec.md "auto-join SHALL mark onboarding complete on the user
# profile" has no direct analogue here — Chatwoot's `User` carries no onboarding
# state. Its PURPOSE still applies: an SSO-provisioned user must land in the app,
# not trapped in a setup wizard.
#
# That purpose is satisfied structurally, by a different requirement in the same
# spec. Chatwoot's onboarding redirect (dashboard/routes/index.js:39-42) fires only
# when:
#
#     ONBOARDING_STEPS.includes(userAccount.onboarding_step)
#       && userAccount.role === 'administrator'     <-- the load-bearing clause
#       && userAccount.status === 'active'
#
# Auto-join assigns `agent`, never `administrator`, because the spec's
# "regular-member role" requirement demands it. So the wizard can never capture an
# mPass user — the role requirement closes the onboarding requirement for free.
#
# This test exists because that coupling is INVISIBLE at both call sites. Anyone
# implementing a reasonable-sounding "make SSO users administrators" request would
# silently reintroduce the trap, and the symptom — every SSO user bounced into an
# account-setup wizard — reads as a broken integration, not a role change.
RSpec.describe 'auto-join / onboarding interlock', type: :request do
  let!(:account) { create(:account) }

  it 'provisions at a role the onboarding wizard cannot capture' do
    with_modified_env AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com' do
      get '/auth/sso/proxy-login', headers: { 'X-Auth-Request-Email' => 'alice@askii.ai' }
    end

    account_user = User.from_email('alice@askii.ai').account_users.first

    expect(account_user.role).to eq('agent')
    # The literal guarantee the SPA depends on. If this flips, read the comment above
    # before "fixing" the test.
    expect(account_user.role).not_to eq('administrator')
  end

  it 'still provisions cleanly when the account is mid-onboarding' do
    account.update!(custom_attributes: { 'onboarding_step' => 'account_details' })

    with_modified_env AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com' do
      get '/auth/sso/proxy-login', headers: { 'X-Auth-Request-Email' => 'bob@askii.ai' }
      expect(response).to redirect_to(/sso_auth_token/)
    end

    expect(User.from_email('bob@askii.ai').account_users.first.role).to eq('agent')
  end
end
