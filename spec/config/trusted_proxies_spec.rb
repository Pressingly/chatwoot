require 'rails_helper'

# rubocop:disable RSpec/DescribeClass
describe 'Trusted proxies configuration' do
  # rubocop:enable RSpec/DescribeClass

  let(:initializer) { Rails.root.join('config/initializers/00_trusted_proxies.rb') }
  let(:gke_cidrs) { '172.32.0.0/14,35.191.0.0/16,130.211.0.0/22,34.49.215.84/32' }
  # client -> Google Front End (appends the client and the load balancer VIP) -> Traefik pod
  # (appends the GFE hop) -> Puma; the leading entry is client-supplied.
  let(:env) do
    Rack::MockRequest.env_for(
      '/',
      'REMOTE_ADDR' => '172.32.0.6',
      'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 203.0.113.9, 34.49.215.84, 35.191.10.20',
      'HTTP_FORWARDED' => 'for=7.7.7.7'
    )
  end
  let(:rack_attack_ip) { Rack::Attack::Request.new(env).ip }
  let(:remote_ip) do
    proxies = Rails.application.config.action_dispatch.trusted_proxies
    ActionDispatch::RemoteIp::GetIp.new(ActionDispatch::Request.new(env), true, proxies).to_s
  end

  around do |example|
    ip_filter = Rack::Request.ip_filter
    forwarded_priority = Rack::Request.forwarded_priority
    trusted_proxies = Rails.application.config.action_dispatch.trusted_proxies
    example.run
  ensure
    Rack::Request.ip_filter = ip_filter
    Rack::Request.forwarded_priority = forwarded_priority
    Rails.application.config.action_dispatch.trusted_proxies = trusted_proxies
  end

  context 'when TRUSTED_PROXY_CIDRS is set' do
    before { with_modified_env(TRUSTED_PROXY_CIDRS: gke_cidrs) { load initializer } }

    it 'resolves the client the front end saw, for Rack::Attack and request.remote_ip alike' do
      expect([rack_attack_ip, remote_ip]).to eq(%w[203.0.113.9 203.0.113.9])
    end

    it 'ignores a client-supplied Forwarded header' do
      env.delete('HTTP_X_FORWARDED_FOR')

      expect(rack_attack_ip).to eq('172.32.0.6')
    end

    it 'treats an unparsable address as untrusted' do
      env['REMOTE_ADDR'] = 'not-an-ip'

      expect(rack_attack_ip).to eq('not-an-ip')
    end
  end

  context 'when TRUSTED_PROXY_CIDRS is unset' do
    before { with_modified_env(TRUSTED_PROXY_CIDRS: nil) { load initializer } }

    it 'keeps the defaults' do
      expect(Rack::Request.forwarded_priority).to eq(%i[forwarded x_forwarded])
      expect(Rails.application.config.action_dispatch.trusted_proxies).to be_nil
    end

    it 'resolves to the untrusted pod address as before' do
      expect(rack_attack_ip).to eq('172.32.0.6')
    end
  end
end
