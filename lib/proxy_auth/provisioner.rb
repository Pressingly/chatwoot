# Turns a normalised proxy email into a local User plus an agent AccountUser in the single SSO account.
# Called only by the proxy-login endpoint. Exact lookup (User.from_email), never sets the STI type,
# never creates an administrator and never changes an existing role.
class ProxyAuth::Provisioner
  class AccountUnavailable < StandardError; end
  class LimitExceeded < StandardError; end
  class UserInactive < StandardError; end

  def self.call(email)
    new(email).call
  end

  def initialize(email)
    @email = email
  end

  def call
    account = Account.find_by(id: SsoMode.account_id)
    raise AccountUnavailable, 'SSO account is missing or suspended' unless account&.active?

    user = User.from_email(@email)
    user = onboard(account, user) unless user && member?(account, user)
    ensure_usable(user)
  end

  private

  # Serialise on the account row like AgentBuilder so two logins cannot both slip under the agent limit.
  def onboard(account, user)
    account.with_lock do
      # Re-read: the caller's lookup ran before the lock, so a second request for the same brand-new
      # user can arrive here with a stale nil, after the first request already committed the user and
      # the membership. Without this, the second request would create_user again (a duplicate email)
      # or, once that raced-creation fallback resolved it, still count the just-added membership
      # against the seat limit and raise LimitExceeded for a user who is already a member.
      user ||= User.from_email(@email)
      unless user && member?(account, user)
        raise LimitExceeded, 'Account limit exceeded' unless account.usage_limits[:agents] > account.account_users.count

        user ||= create_user
        ensure_usable(user)
        add_membership(account, user)
      end
      user
    end
  end

  def member?(account, user)
    AccountUser.exists?(account_id: account.id, user_id: user.id)
  end

  def ensure_usable(user)
    user.confirm unless user.confirmed?
    raise UserInactive, 'User is not active for authentication' unless user.active_for_authentication?

    user
  end

  def create_user
    ActiveRecord::Base.transaction(requires_new: true) do
      password = "#{SecureRandom.hex(16)}aA1!"
      User.new(email: @email, name: @email.split('@').first, password: password, password_confirmation: password).tap do |user|
        user.skip_confirmation!
        user.save!
      end
    end
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid => e
    # Lost a creation race: fall back to a plain read; unrelated failures re-raise.
    User.from_email(@email) || raise(e)
  end

  def add_membership(account, user)
    ActiveRecord::Base.transaction(requires_new: true) do
      AccountUser.create!(account_id: account.id, user_id: user.id, role: :agent)
    end
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid => e
    member?(account, user) || raise(e)
  end
end
