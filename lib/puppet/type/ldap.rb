require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'ldap',
  docs: <<-EOS,
@summary a ldap type
@example
ldap { 'foo':
  ensure => 'present',
}

This type provides Puppet with the capabilities to manage ...

EOS
  features: [],
  attributes: {
    ensure: {
      type:    'Enum[present, absent]',
      desc:    'Whether this domain membership should be present or absent.',
      default: 'present',
    },
    name: {
      type:      'String',
      desc:      'The name of the domain you want to manage membership of.',
      behaviour: :namevar,
    },
    user: {
      type:      'String',
      desc:      'The username of an account with privileges to join a domain.',
      behaviour: :parameter,
      default:   'user',
    },
    password: {
      type:      'String',
      desc:      'The password for the user joining the computer to the domain.',
      behaviour: :parameter,
      default:   'password',
    },
  },
)
