require 'rails_helper'

RSpec.describe Mpass::VerifiedTokenCache do
  let(:now) { [1_000] }
  let(:cache) { described_class.new(max_entries: 2, clock: -> { now.first }) }

  it 'serves stored claims until exp, then forgets them' do
    cache.store('a', { 'exp' => 1_010 })
    expect(cache.fetch('a')).to eq('exp' => 1_010)
    now[0] = 1_010
    expect(cache.fetch('a')).to be_nil
  end

  it 'stays bounded, evicting the entry that expires soonest' do
    cache.store('a', { 'exp' => 1_500 })
    cache.store('b', { 'exp' => 1_100 })
    cache.store('c', { 'exp' => 1_900 })
    expect(cache.size).to eq(2)
    expect(cache.fetch('b')).to be_nil
    expect(cache.fetch('a')).to be_present
  end

  it 'keys on the verifier configuration as well as the token' do
    expect(described_class.key_for('t', 'issuer-a')).not_to eq(described_class.key_for('t', 'issuer-b'))
  end
end
