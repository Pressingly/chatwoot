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

  describe '.corporate_claims_ok?' do
    def token(claims)
      "header.#{Base64.urlsafe_encode64(claims.to_json, padding: false)}.signature"
    end

    def check(access_token)
      headers = access_token ? { 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN' => access_token } : {}
      described_class.corporate_claims_ok?(request_with(headers))
    end

    let(:acme) { token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'acme-42') }

    it 'skips the check when SMB_CORPORATE_ID is unset, even with no token' do
      with_modified_env(SMB_CORPORATE_ID: nil) { expect(check(nil)).to be true }
    end

    context 'when SMB_CORPORATE_ID is set' do
      around { |ex| with_modified_env(SMB_CORPORATE_ID: 'acme-42') { ex.run } }

      it 'admits a matching corporate principal' do
        expect(check(acme)).to be true
      end

      it 'refuses another corporate' do
        expect(check(token('custom:is_corporate' => 'true', 'custom:corporate_id' => 'globex-7'))).to be false
      end

      it 'refuses an individual principal carrying the right id' do
        expect(check(token('custom:is_corporate' => 'false', 'custom:corporate_id' => 'acme-42'))).to be false
        expect(check(token('custom:corporate_id' => 'acme-42'))).to be false
      end

      it 'refuses a missing token' do
        expect(check(nil)).to be false
        expect(check('')).to be false
      end

      it 'refuses an undecodable token without raising' do
        ['not-a-jwt', 'a.!!!.c', "a.#{Base64.urlsafe_encode64('not json')}.c",
         "a.#{Base64.urlsafe_encode64('[1]')}.c", "a.#{Base64.urlsafe_encode64("\xff\xfe")}.c"].each do |bad|
          expect(check(bad)).to be(false), bad
        end
      end
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
