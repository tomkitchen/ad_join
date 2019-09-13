require 'puppet/resource_api/simple_provider'
require 'socket'
require 'net/ldap'
require 'rubygems'
puts $LOAD_PATH
#ad_port = 389
#username = "tom"
#password = "Kb-PwxS9.A>uFbL}"
#hostname = Socket.gethostname[/^[^.]+/]
#fqdn = Socket.gethostname

#computers_dn = "CN=Computers,DC=testing,DC=com"
#computer_sam = "#{hostname}$"
#os = "koji-linux-gnu"
#service_principal = ["host/#{hostname}", "host/#{fqdn}", "RestrictedKrbHost/#{hostname}", "RestrictedKrbHost/#{fqdn}"]

#dn = "CN=#{hostname},#{computers_dn}"

#attr = {
#  :sAMAccountName => computer_sam,
#  :objectclass => ["computer", "top", "person", "user", "organizationalPerson"],
#  :userAccountControl => "69632", # /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
#  :msDS-supportedEncryptionTypes => [nil, nil],
#  :dNSHostName => fqdn,
#  :operatingSystem => os,
#  :servicePrincipalName => service_principal
#}

#auth = {:method => :simple, :username => username, :password => password}
#Net::LDAP.open( :host => ad_host, :port => ad_port, :auth => auth ) do |ldap|
#puts(ldap.add( :dn => dn, :attributes => attr))
#end

 

# Implementation for the ldap type using the Resource API.
class Puppet::Provider::Ldap::Ldap < Puppet::ResourceApi::SimpleProvider
  def bind(context)
    #check that we can connect to the ldap server
    ldap Net::LDAP.new( :host => ad_host, :port => ad_port, :auth => auth )
  end

  def get(context)
    context.notice('Returning pre-canned example data')
    [
      {
        name: 'foo',
        ensure: 'present',
      },
      {
        name: 'bar',
        ensure: 'present',
      },
    ]
  end

  def create(context, name, should)
    puts("~~~~~~~~~~")
    context.notice("Creating '#{name}' with #{should.inspect}")
  end

  def update(context, name, should)
    context.notice("Updating '#{name}' with #{should.inspect}")
  end

  def delete(context, name)
    context.notice("Deleting '#{name}'")
  end
end
