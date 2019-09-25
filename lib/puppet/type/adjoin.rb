Puppet::Type.newtype(:adjoin) do
  @doc = <<-PUPPET
    @summary
      Join a domain.
    PUPPET

  ensurable
  newparam(:domain, :namevar => true)do
    desc "The name of the domain."
  end
  newparam(:user)do
    desc "The user name for the domain."
  end
  newparam(:password)do
    desc "The user password for the domain."
  end
  newparam(:port)do
    desc "The port for the domain."
  end
end
