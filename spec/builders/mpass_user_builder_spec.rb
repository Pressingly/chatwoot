require 'rails_helper'

RSpec.describe MpassUserBuilder do
  let(:email) { 'mpass.user@askii.ai' }
  let!(:account) { create(:account) }
  let(:builder) { described_class.new(email: email) }

  describe '#perform — resolution' do
    it 'creates an unconfirmed-free user with an unusable random password' do
      user = builder.perform

      expect(user).to be_persisted
      expect(user.email).to eq(email)
      expect(user.provider).to eq('mpass')
      expect(user).to be_confirmed
    end

    it 'reuses an existing user rather than creating a second' do
      existing = create(:user, email: email, account: account)

      expect { builder.perform }.not_to change(User, :count)
      expect(builder.perform).to eq(existing)
    end

    it 'confirms an existing unconfirmed user' do
      create(:user, email: email, account: account, skip_confirmation: false)

      expect(builder.perform.reload).to be_confirmed
    end

    it 'uses the display name when given' do
      user = described_class.new(email: '847392@askii.ai', display_name: 'Alice Okonkwo').perform
      expect(user.name).to eq('Alice Okonkwo')
    end

    it 'falls back to the email local-part when no display name is given' do
      expect(described_class.new(email: '847392@askii.ai').perform.name).to eq('847392')
    end
  end

  # proxy-auth-middleware/spec.md "Concurrent creation races SHALL fall back to read".
  # Only reachable as a unit test — a request spec cannot interleave two inserts.
  #
  # No exception is stubbed: the conflicting row is real, so the failure comes from
  # Chatwoot's own uniqueness validation / the unique index on (uid, provider),
  # which devise_token_auth keeps synced to the email.
  describe '#perform — concurrent creation race' do
    it 'falls back to a read when another request wins the insert' do
      # The row the "other request" committed between our lookup and our insert.
      winner = create(:user, email: email, account: account)

      lookups = 0
      allow(User).to receive(:from_email) do
        lookups += 1
        lookups == 1 ? nil : winner # first lookup misses; the retry finds it
      end

      expect(builder.perform).to eq(winner)
      expect(lookups).to eq(2) # proves the retry ran, rather than the miss being lucky
    end

    it 're-raises when the row still does not exist after the retry' do
      # A conflicting row exists but from_email never sees it, so the retry cannot
      # resolve. The error must surface rather than be swallowed as a race.
      create(:user, email: email, account: account)
      allow(User).to receive(:from_email).and_return(nil)

      expect { builder.perform }
        .to raise_error(an_instance_of(ActiveRecord::RecordInvalid)
                          .or(an_instance_of(ActiveRecord::RecordNotUnique)))
    end
  end

  describe '#perform — workspace auto-join' do
    it 'joins the oldest account as agent, never administrator' do
      newer = create(:account)
      au = builder.perform.account_users.first

      expect(au.account).to eq(account)
      expect(au.account).not_to eq(newer)
      expect(au.role).to eq('agent')
      expect(au.role).not_to eq('administrator')
    end

    it 'is a no-op on the second run' do
      builder.perform
      expect { described_class.new(email: email).perform }.not_to change(AccountUser, :count)
    end

    it 'skips entirely when no account exists' do
      Account.destroy_all
      user = described_class.new(email: 'first@askii.ai').perform

      expect(user).to be_persisted
      expect(user.account_users).to be_empty
    end

    # SamlUserBuilder raises AuthenticationFailed here (saml_user_builder.rb:21-24).
    # The workspace-auto-join contract requires join, not reject — this guards
    # against the rejection being reintroduced during an upstream rebase.
    # The loser of a concurrent first login trips AccountUser's uniqueness
    # validation (RecordInvalid), not only the DB index (RecordNotUnique).
    it 'treats a lost membership race as a no-op' do
      user = create(:user, email: email, account: nil)
      allow(AccountUser).to receive(:create!).and_wrap_original do |original, **attrs|
        original.call(**attrs) # the winner's insert
        original.call(**attrs) # the loser's, which now fails validation
      end

      expect { described_class.new(email: email).perform }.not_to raise_error
      expect(user.account_users.count).to eq(1)
    end

    it 're-raises a validation failure that is not a race' do
      create(:user, email: email, account: nil)
      allow(AccountUser).to receive(:create!).and_raise(ActiveRecord::RecordInvalid.new(AccountUser.new))

      expect { described_class.new(email: email).perform }.to raise_error(ActiveRecord::RecordInvalid)
    end

    it 'does NOT reject a user who already belongs to another account' do
      other = create(:account)
      user = create(:user, email: email, account: other)

      expect { described_class.new(email: email).perform }.not_to raise_error
      # An existing member is left alone, so an admin's removal from one account
      # is not undone while the user keeps another.
      expect(user.reload.accounts).to contain_exactly(other)
    end

    it 'joins CHATWOOT_SMB_DEFAULT_ACCOUNT_ID instead of the oldest account' do
      named = create(:account)
      with_modified_env(CHATWOOT_SMB_DEFAULT_ACCOUNT_ID: named.id.to_s) do
        expect(builder.perform.accounts).to contain_exactly(named)
      end
    end

    it 'joins nothing when CHATWOOT_SMB_DEFAULT_ACCOUNT_ID names no account' do
      with_modified_env(CHATWOOT_SMB_DEFAULT_ACCOUNT_ID: '0') do
        expect(builder.perform.account_users).to be_empty
      end
    end

    it 'skips a suspended oldest account' do
      account.update!(status: :suspended)
      newer = create(:account)
      expect(builder.perform.accounts).to contain_exactly(newer)
    end
  end
end
