require 'rails_helper'

RSpec.describe Mpass::ProxyIdentity do
  def request_with(headers)
    ActionDispatch::TestRequest.create(headers)
  end

  describe '.email' do
    it 'reads X-Auth-Request-Email' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => 'Alice@Example.com')
      expect(described_class.email(req)).to eq('alice@example.com')
    end

    it 'is case- and whitespace-insensitive (mandatory test 2)' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '  ALICE@EXAMPLE.COM  ')
      expect(described_class.email(req)).to eq('alice@example.com')
    end

    it 'ignores X-Auth-Request-User (the Cognito sub) when email is absent' do
      req = request_with('HTTP_X_AUTH_REQUEST_USER' => '3f2504e0-4f89-11d3-9a0c-0305e82c3301')
      expect(described_class.email(req)).to be_nil
    end

    it 'returns nil when both headers are absent (mandatory test 3: absence is not logout)' do
      expect(described_class.email(request_with({}))).to be_nil
    end

    it 'returns nil when the header is whitespace only' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '   ')
      expect(described_class.email(req)).to be_nil
    end

    it 'synthesises a bare Cognito username against DEFAULT_EMAIL_DOMAIN' do
      with_modified_env DEFAULT_EMAIL_DOMAIN: 'askii.ai' do
        req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '847392')
        expect(described_class.email(req)).to eq('847392@askii.ai')
      end
    end

    it 'refuses a bare username when DEFAULT_EMAIL_DOMAIN is unset (fails closed)' do
      with_modified_env DEFAULT_EMAIL_DOMAIN: nil do
        req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '847392')
        expect(described_class.email(req)).to be_nil
      end
    end
  end

  describe '.email_shaped?' do
    # Regression guard for audit row 21: this must stay indexOf-based. A
    # polynomial-backtracking regex would hang on this input instead of returning.
    it 'returns quickly on adversarial input' do
      adversarial = "!@#{'!.' * 5_000}"
      expect { Timeout.timeout(2) { described_class.email_shaped?(adversarial) } }.not_to raise_error
    end

    it 'rejects values with no @' do
      expect(described_class.email_shaped?('847392')).to be false
    end

    it 'rejects a leading or trailing @' do
      expect(described_class.email_shaped?('@example.com')).to be false
      expect(described_class.email_shaped?('alice@')).to be false
    end

    # proxy-auth-middleware "email-shape detection": a `.` at least one character
    # after the `@`, so every bundle app resolves the same value to the same row.
    it 'requires a dot after the @' do
      expect(described_class.email_shaped?('alice@example.com')).to be true
      expect(described_class.email_shaped?('a@b')).to be false
      expect(described_class.email_shaped?('alice@.com')).to be false
    end
  end

  describe '.corporate_rejection' do
    def rejection(access_token)
      headers = access_token ? { 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => access_token } : {}
      described_class.corporate_rejection(request_with(headers))
    end

    let(:acme) { mpass_token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42') }

    it 'skips the check when SMB_CORPORATE_ID is unset, even with no token' do
      with_modified_env(SMB_CORPORATE_ID: nil) { expect(rejection(nil)).to be_nil }
    end

    context 'when SMB_CORPORATE_ID is set' do
      around { |ex| with_modified_env(SMB_CORPORATE_ID: 'acme-42', **mpass_verifier_env) { ex.run } }

      before { stub_mpass_jwks }

      it 'admits a matching corporate principal' do
        expect(rejection(acme)).to be_nil
      end

      it 'refuses another corporate' do
        expect(rejection(mpass_token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'))).to eq('wrong_organization')
      end

      it 'refuses an individual principal carrying the right id' do
        expect(rejection(mpass_token('custom:is_corporate' => 'false', 'custom:corporate_id' => 'acme-42'))).to eq('not_corporate')
        expect(rejection(mpass_token('custom:corporate_id' => 'acme-42'))).to eq('not_corporate')
      end

      it 'refuses a missing token' do
        expect(rejection(nil)).to eq('missing_token')
        expect(rejection('')).to eq('missing_token')
      end

      it 'refuses an undecodable token without raising' do
        ['not-a-jwt', 'a.!!!.c', "a.#{Base64.urlsafe_encode64('not json')}.c",
         "a.#{Base64.urlsafe_encode64('[1]')}.c", "a.#{Base64.urlsafe_encode64("\xff\xfe")}.c"].each do |bad|
          expect(rejection(bad)).to eq('malformed'), bad
        end
      end
    end
  end

  describe '.corporate_id' do
    it 'treats a blank value as unset, so the gate stays off' do
      with_modified_env(SMB_CORPORATE_ID: '  ') do
        expect(described_class.corporate_rejection(request_with({}))).to be_nil
      end
    end

    it 'keeps the gate on for a CHANGE_ME_ placeholder and refuses even a valid token' do
      stub_mpass_jwks
      token = mpass_token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'CHANGE_ME_SMB_CORPORATE_ID')
      with_modified_env(SMB_CORPORATE_ID: ' CHANGE_ME_SMB_CORPORATE_ID ', **mpass_verifier_env) do
        request = request_with('HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => token)
        expect(described_class.corporate_rejection(request)).to eq('placeholder_config')
        expect(described_class.corporate_mismatch?(request)).to be true
      end
    end

    it 'trims the configured id' do
      with_modified_env(SMB_CORPORATE_ID: '  acme-42 ') { expect(described_class.corporate_id).to eq('acme-42') }
    end
  end

  describe '.corporate_mismatch?' do
    around { |ex| with_modified_env(SMB_CORPORATE_ID: 'acme-42', **mpass_verifier_env) { ex.run } }

    def mismatch?(access_token)
      headers = access_token ? { 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => access_token } : {}
      described_class.corporate_mismatch?(request_with(headers))
    end

    let(:acme_claims) { { 'custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42' } }

    before { stub_mpass_jwks }

    it 'is a mismatch only for a verified token naming another tenant' do
      expect(mismatch?(mpass_token(acme_claims.merge('custom:corporate_id' => 'globex-7')))).to be true
      expect(mismatch?(mpass_token(acme_claims.merge('custom:is_corporate' => 'false')))).to be true
      expect(mismatch?(mpass_token(acme_claims))).to be false
    end

    it 'keeps the session, and logs why, when the token cannot be verified right now' do
      allow(Rails.logger).to receive(:warn)
      expect(mismatch?(mpass_token(acme_claims.merge('exp' => Time.now.to_i - 600)))).to be false
      expect(mismatch?(nil)).to be false
      expect(Rails.logger).to have_received(:warn).with(/re-check skipped: reason=expired/)
      expect(Rails.logger).to have_received(:warn).with(/re-check skipped: reason=missing_token/)
    end

    it 'logs a skipped re-check once per reason per minute' do
      allow(Rails.logger).to receive(:warn)
      expired = mpass_token(acme_claims.merge('exp' => Time.now.to_i - 600))
      3.times { mismatch?(expired) }
      expect(Rails.logger).to have_received(:warn).with(/re-check skipped: reason=expired/).once
    end

    it 'does not log an unconfigured verifier per request' do
      allow(Rails.logger).to receive(:warn)
      with_modified_env(MPASS_OIDC_CLIENT_ID: nil) { expect(mismatch?(mpass_token(acme_claims))).to be false }
      expect(Rails.logger).not_to have_received(:warn).with(/verifier_unconfigured/)
    end

    it 'keeps the session when the JWKS is unreachable' do
      stub_request(:get, "#{MpassTokenHelpers::MPASS_ISSUER}/.well-known/jwks.json").to_return(status: 503)
      expect(mismatch?(mpass_token(acme_claims.merge('custom:corporate_id' => 'globex-7')))).to be false
    end
  end

  describe '.display_name' do
    it 'uses the local-part when it is not numeric' do
      req = request_with({})
      expect(described_class.display_name(req, 'alice@example.com')).to eq('alice')
    end

    it 'prefers the preferred-username claim when the local-part is a bare Cognito id' do
      req = request_with('HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME' => 'Alice Smith')
      expect(described_class.display_name(req, '847392@askii.ai')).to eq('Alice Smith')
    end

    # audit row 19 — a sub UUID must never reach a user-visible name field.
    it 'rejects a UUID-shaped preferred-username and falls back to the local-part' do
      req = request_with('HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME' => '3f2504e0-4f89-11d3-9a0c-0305e82c3301')
      expect(described_class.display_name(req, '847392@askii.ai')).to eq('847392')
    end
  end
end
