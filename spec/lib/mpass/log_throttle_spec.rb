require 'rails_helper'

RSpec.describe Mpass::LogThrottle do
  let(:now) { [0] }
  let(:throttle) { described_class.new(clock: -> { now.first }) }

  it 'allows each key once per interval' do
    expect(throttle.allow?('a')).to be true
    expect(throttle.allow?('a')).to be false
    expect(throttle.allow?('b')).to be true
    now[0] = described_class::INTERVAL_SECONDS
    expect(throttle.allow?('a')).to be true
  end
end
