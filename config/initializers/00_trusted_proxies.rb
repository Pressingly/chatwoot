# frozen_string_literal: true

# TRUSTED_PROXY_CIDRS: comma-separated CIDRs of proxies in front of Puma that sit outside
# the private ranges Rack and Rails already trust, e.g. a Kubernetes pod CIDR beyond
# 172.16.0.0/12 or a cloud load balancer. Without them, request.ip resolves to the proxy and
# Rack::Attack throttles every client in one bucket. Unset leaves both defaults untouched.
trusted_proxy_cidrs = ENV.fetch('TRUSTED_PROXY_CIDRS', '').split(',').map(&:strip).reject(&:empty?).map { |cidr| IPAddr.new(cidr) }

if trusted_proxy_cidrs.any?
  default_ip_filter = Rack::Request.ip_filter
  Rack::Request.ip_filter = lambda do |ip|
    default_ip_filter.call(ip) || trusted_proxy_cidrs.any? { |cidr| cidr.include?(ip) }
  rescue IPAddr::Error
    false
  end

  # Rack reads RFC 7239 Forwarded before X-Forwarded-For, and Traefik passes a client-supplied
  # Forwarded header through untouched, so a client could otherwise choose its own address.
  Rack::Request.forwarded_priority = [:x_forwarded]

  Rails.application.config.action_dispatch.trusted_proxies = ActionDispatch::RemoteIp::TRUSTED_PROXIES + trusted_proxy_cidrs
end
