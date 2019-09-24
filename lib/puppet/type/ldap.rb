Puppet::Type.newtype(:ldap) do
  @doc = <<-PUPPET
    @summary
      Manage a ldap connection.
    PUPPET

  ensurable
  newparam(:domain, namevar: true){}
end
