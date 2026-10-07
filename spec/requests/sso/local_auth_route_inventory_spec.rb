require 'rails_helper'

# The per-controller guard is opt-in, so this is its choke point: it walks every route
# the auth libraries (and first-run setup) mount under AUTH_TYPE=SSO and fails when a
# controller behind one of them lacks the guard. A new local-credential surface that
# forgets `include MpassLocalAuthGuard` fails here instead of shipping open.
RSpec.describe 'local-credential route inventory under SSO', type: :request do
  let(:guards) { %i[reject_local_auth_under_sso reject_local_login_under_sso] }
  let(:local_auth_controller_pattern) { %r{\A(devise_token_auth|devise_overrides|devise|installation|auth|api/v1/auth\z)} }

  # Reachable under SSO without the guard, each for a stated reason.
  let(:not_local_credentials) do
    %w[
      devise_overrides/token_validations
      sso/proxy_login
    ] # the handoff itself mints the one-time token; header trust is gated on AUTH_TYPE
  end
  let(:known_open) do
    {
      # The super-admin console and the Devise defaults devise_for mounts beside it
      # are not routed under SSO (a route constraint, so these controllers carry no
      # guard); the 404s are pinned in local_auth_endpoints_spec.rb.
      'devise/passwords' => 'super-admin Devise defaults: unrouted under SSO',
      'devise/confirmations' => 'super-admin Devise defaults: unrouted under SSO',
      'devise/registrations' => 'super-admin Devise defaults: unrouted under SSO',
      'devise/omniauth_callbacks' => 'super-admin Devise defaults: unrouted under SSO',
      'super_admin/devise/sessions' => 'super-admin password login: unrouted under SSO',
      'platform/api/v1/users' => 'Platform API mints login links; machine-to-machine, and a Platform app ' \
                                 'can already read the user access token, so it adds no new access'
    }
  end

  around do |example|
    with_modified_env(AUTH_TYPE: 'SSO') do
      Rails.application.reload_routes!
      example.run
    end
  ensure
    Rails.application.reload_routes!
  end

  # A route whose controller is not loaded (CE build: enterprise/ stripped, so
  # auth#saml_login) raises a routing error, so it exposes no surface to guard.
  def local_auth_controllers
    Rails.application.routes.routes
         .filter_map { |route| route.defaults[:controller] }
         .grep(local_auth_controller_pattern).uniq
         .select { |name| "#{name.camelize}Controller".safe_constantize }
  end

  it 'guards every local-credential controller the routes expose' do
    unguarded = (local_auth_controllers - not_local_credentials - known_open.keys).reject do |name|
      filters = "#{name.camelize}Controller".constantize._process_action_callbacks.map(&:filter)
      filters.intersect?(guards)
    end

    expect(unguarded).to be_empty
  end

  # Prefixes miss endpoints like POST /api/v2/accounts, so also find controllers by
  # what they do: anything that issues a devise_token_auth session must be gated.
  it 'guards every controller that issues a session, wherever it is mounted' do
    # Session issuers, handoff-token minters and Warden sign-ins, in CE and EE code.
    issuing = /\b(send_auth_headers|create_new_auth_token|create_token|generate_sso_link|generate_sso_auth_token)\b|\bsign_in\(/
    issuers = Dir[Rails.root.join('{app,enterprise/app}/controllers/**/*_controller.rb')].select do |file|
      File.read(file).match?(issuing)
    end
    # An EE file is a module prepended into the CE controller of the same name.
    names = issuers.map { |file| file[%r{controllers/(.+)_controller\.rb\z}, 1].delete_prefix('enterprise/') }.uniq

    unguarded = (names - not_local_credentials - known_open.keys).reject do |name|
      filters = "#{name.camelize}Controller".constantize._process_action_callbacks.map(&:filter)
      filters.intersect?(guards)
    end

    expect(unguarded).to be_empty
  end
end
