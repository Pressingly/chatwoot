# frozen_string_literal: true

# Resolves-or-provisions the user an mPass proxy identity asserts, then joins them
# to the canonical account.
#
# Ported from enterprise/app/builders/saml_user_builder.rb, with two deliberate
# differences:
#
#   1. NO multi-account rejection. SamlUserBuilder raises AuthenticationFailed when
#      the user belongs to another account (:21-24). The workspace-auto-join
#      contract requires join, never reject — a user legitimately spans accounts.
#   2. NO role mappings. mPass asserts identity only; role stays the regular-member
#      role. Elevation is an in-app action.
class MpassUserBuilder
  # Regular-member role. Never `administrator` — auto-provisioning must not be a
  # privilege-escalation path (workspace-auto-join/spec.md).
  DEFAULT_ROLE = 'agent'

  def initialize(email:, display_name: nil)
    @email = email
    @display_name = display_name
  end

  def perform
    @user = find_or_create_user
    auto_join_account if @user&.persisted?
    @user
  end

  private

  def find_or_create_user
    # Exact match, case-folded by User.from_email (app/models/user.rb:173).
    # Never LIKE/ILIKE on a proxy-supplied value.
    existing = User.from_email(@email)
    return adopt(existing) if existing

    create_user
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    # Concurrent first-request race: another request created the row between our
    # lookup and our insert. Fall back to a plain read; re-raise if the row is
    # still absent rather than swallowing (proxy-auth-middleware/spec.md
    # "Concurrent creation races SHALL fall back to read").
    #
    # BOTH exceptions are in scope, and which one fires depends on how narrow the
    # window was. Devise's :validatable adds a uniqueness validation, so if the
    # other request's row became visible before our validation query we get
    # RecordInvalid; if it landed between our validation and our INSERT we get
    # RecordNotUnique from the unique index on (uid, provider) — uid is synced to
    # the email by devise_token_auth. Rescuing only the latter leaves the wider
    # window unhandled.
    #
    # Re-raising when the row is still absent keeps a genuinely invalid record
    # (bad email, failed validation for some other reason) from being silently
    # swallowed as if it were a race.
    User.from_email(@email) || raise
  end

  def adopt(user)
    user.skip_confirmation! unless user.confirmed?
    user.save! if user.changed?
    user
  end

  def create_user
    user = User.new(
      email: @email,
      name: @display_name.presence || @email.split('@').first,
      password: SecureRandom.hex(32),
      provider: 'mpass'
    )
    user.skip_confirmation!
    user.save!
    user
  end

  # Runs on EVERY login, not only on creation — a user may have been created by an
  # earlier request that died before joining, or provisioned out of band
  # (workspace-auto-join/spec.md "auto-join SHALL run on every login").
  # A user who already belongs to ANY account is left alone ("Existing member
  # triggers no DB writes"), so an admin removing an agent from one account while
  # they keep another is not undone on their next login. Removing their LAST
  # membership is: with no rows they are joined again. Revoke access in mPass
  # (or with SMB_CORPORATE_ID), not by removing the membership.
  def auto_join_account
    return if @user.account_users.exists?

    account = target_account
    # No account yet: do nothing and let Chatwoot's own first-run flow create one.
    # Creating it here would race the admin provisioning the canonical account.
    return if account.blank?

    AccountUser.create!(user: @user, account: account, role: DEFAULT_ROLE)
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    # Two concurrent logins for the same new user: the loser trips either the DB
    # unique index or AccountUser's uniqueness validation. Re-raise anything else.
    raise unless @user.account_users.exists?(account_id: account.id)
  end

  # CHATWOOT_SMB_DEFAULT_ACCOUNT_ID names the account, so the provisioner knows
  # exactly which one to create; unset, the oldest active account. A configured id
  # that doesn't exist (or is suspended) joins nothing rather than guessing another.
  def target_account
    id = ENV.fetch('CHATWOOT_SMB_DEFAULT_ACCOUNT_ID', nil).presence
    return Account.active.find_by(id: id) if id

    Account.active.order(created_at: :asc).first
  end
end
