require 'spec_helper'
require 'puppet/type/ldap'

RSpec.describe 'the ldap type' do
  it 'loads' do
    expect(Puppet::Type.type(:ldap)).not_to be_nil
  end
end
