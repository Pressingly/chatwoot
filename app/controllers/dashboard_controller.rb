class DashboardController < ActionController::Base
  include SwitchLocale
  include PortalHomeData
  include MpassSessionReconciliation

  # Rule 2, Path A — must run before the SPA is served, so user B never sees a
  # document rendered under user A's identity. Also the SSO entry point: a browser
  # with no app session is sent into the handoff. audit rows 6, 20
  before_action :reconcile_mpass_identity, only: [:index]

  GLOBAL_CONFIG_KEYS = %w[
    LOGO
    LOGO_DARK
    LOGO_THUMBNAIL
    INSTALLATION_NAME
    WIDGET_BRAND_URL
    TERMS_URL
    BRAND_URL
    BRAND_NAME
    PRIVACY_URL
    DISPLAY_MANIFEST
    CREATE_NEW_ACCOUNT_FROM_DASHBOARD
    CHATWOOT_INBOX_TOKEN
    API_CHANNEL_NAME
    API_CHANNEL_THUMBNAIL
    CLOUD_ANALYTICS_TOKEN
    DIRECT_UPLOADS_ENABLED
    MAXIMUM_FILE_UPLOAD_SIZE
    HCAPTCHA_SITE_KEY
    LOGOUT_REDIRECT_LINK
    DISABLE_USER_PROFILE_UPDATE
    DISABLE_META_INBOX_CREATION
    DISABLE_META_MESSAGE_SENDING
    DEPLOYMENT_ENV
    INSTALLATION_PRICING_PLAN
  ].freeze

  before_action :set_application_pack
  before_action :set_global_config
  before_action :set_dashboard_scripts
  around_action :switch_locale
  before_action :ensure_installation_onboarding, only: [:index]
  before_action :render_hc_if_custom_domain, only: [:index]
  before_action :ensure_html_format
  layout 'vueapp'

  def index; end

  private

  def ensure_html_format
    render json: { error: 'Please use API routes instead of dashboard routes for JSON requests' }, status: :not_acceptable if request.format.json?
  end

  def set_global_config
    @global_config = GlobalConfig.get(*GLOBAL_CONFIG_KEYS).merge(app_config)
  end

  # Rule 2, Path A, and the SSO entry point. Both resolve the same way: enter the
  # handoff, which mints a token for the incoming identity and redirects to
  # /app/login?email=&sso_auth_token= — the SPA's existing RouteHelper.js:23-27
  # clears any previous user's cookie before submitting.
  #
  # Without the entry half, first login dead-ends: the user scans the QR code, the
  # edge lets the request through, and Chatwoot serves its own login form, which
  # under SSO accepts nothing. Nothing on the client can start the handoff.
  def reconcile_mpass_identity
    # The handoff lands back here on /app/login (dashboard#index serves it), still
    # carrying the PREVIOUS user's cookie — the SPA clears it only once this
    # document has loaded. Reconciling that request would bounce it into the
    # handoff again, and again, until the browser gives up.
    # Only on /app/login: a bare ?sso_auth_token= on any other path must not skip
    # reconciliation.
    return if request.path == '/app/login' && params[:sso_auth_token].present?
    # The handoff's own failure landing is /app/login?error=sso_failed, which by
    # definition carries an identity and no session — exactly the entry condition.
    # Re-entering it would retry a failed handoff forever instead of showing why.
    return if request.path == '/app/login' && params[:error].present?

    redirect_to '/auth/sso/proxy-login' if mpass_identity_mismatch? || mpass_handoff_required?
  end

  def set_dashboard_scripts
    @dashboard_scripts = sensitive_path? ? nil : GlobalConfig.get_value('DASHBOARD_SCRIPTS')
  end

  def ensure_installation_onboarding
    return if Mpass::ProxyIdentity.sso_mode? # onboarding is 404 under SSO

    redirect_to '/installation/onboarding' if ::Redis::Alfred.get(::Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING)
  end

  def render_hc_if_custom_domain
    domain = request.host
    return if domain == URI.parse(ENV.fetch('FRONTEND_URL', '')).host

    @portal = Portal.find_by(custom_domain: domain)
    return unless @portal

    @locale = @portal.default_locale
    request.variant = :documentation if @portal.layout == 'documentation'
    load_home_data
    render 'public/api/v1/portals/show', layout: 'portal', portal: @portal and return
  end

  def app_config
    {
      APP_VERSION: Chatwoot.config[:version],
      VAPID_PUBLIC_KEY: VapidService.public_key,
      ENABLE_ACCOUNT_SIGNUP: GlobalConfigService.load('ENABLE_ACCOUNT_SIGNUP', 'false'),
      FB_APP_ID: GlobalConfigService.load('FB_APP_ID', ''),
      INSTAGRAM_APP_ID: GlobalConfigService.load('INSTAGRAM_APP_ID', ''),
      TIKTOK_APP_ID: GlobalConfigService.load('TIKTOK_APP_ID', ''),
      FACEBOOK_API_VERSION: GlobalConfigService.load('FACEBOOK_API_VERSION', 'v18.0'),
      WHATSAPP_APP_ID: GlobalConfigService.load('WHATSAPP_APP_ID', ''),
      WHATSAPP_CONFIGURATION_ID: GlobalConfigService.load('WHATSAPP_CONFIGURATION_ID', ''),
      IS_ENTERPRISE: ChatwootApp.enterprise?,
      AZURE_APP_ID: GlobalConfigService.load('AZURE_APP_ID', ''),
      GIT_SHA: GIT_HASH,
      ALLOWED_LOGIN_METHODS: allowed_login_methods,
      # Read from ENV on every request, never via GlobalConfig: GlobalConfigService
      # persists ENV into InstallationConfig on first read, which would make
      # AUTH_TYPE sticky in the database and survive an env change. audit rows 5, 8
      AUTH_TYPE: ENV.fetch('AUTH_TYPE', ''),
      # SSO Sign out target (logout-flow spec), the bundle's LOGOUT_REDIRECT_URL. Not
      # upstream's LOGOUT_REDIRECT_LINK: that one is DB-only and also drives the 401
      # re-auth path, which must stay inside the app.
      LOGOUT_REDIRECT_URL: ENV.fetch('LOGOUT_REDIRECT_URL', ''),
      ACTIVE_PLATFORM_BANNERS: active_platform_banners
    }
  end

  def active_platform_banners
    return [] unless ChatwootApp.chatwoot_cloud?

    PlatformBanner.active.order(created_at: :desc).as_json(only: %i[id banner_message banner_type updated_at])
  end

  def allowed_login_methods
    # Under SSO the only entry point is the ForwardAuth handoff; offering any local
    # or federated method here is a second identity path Moneta does not control.
    return ['sso'] if Mpass::ProxyIdentity.sso_mode?

    methods = ['email']
    methods << 'google_oauth' if GlobalConfigService.load('ENABLE_GOOGLE_OAUTH_LOGIN', 'true').to_s != 'false'
    methods << 'saml' if ChatwootHub.pricing_plan != 'community' && GlobalConfigService.load('ENABLE_SAML_SSO_LOGIN', 'true').to_s != 'false'
    methods
  end

  def set_application_pack
    @application_pack = if request.path.include?('/auth') || request.path.include?('/login')
                          'v3app'
                        else
                          'dashboard'
                        end
  end

  def sensitive_path?
    # dont load dashboard scripts on sensitive paths like password reset
    sensitive_paths = [edit_user_password_path].freeze

    # remove app prefix
    current_path = request.path.gsub(%r{^/app}, '')

    sensitive_paths.include?(current_path)
  end
end
