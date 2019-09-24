require 'socket'
require 'net/ldap'
require 'yaml'
#require 'rubygems'
#require 'puppet/provider/ldap'
#require 'puppet/util/ldap'
#puts $LOAD_PATH
#puts resource[:name]
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

#ldap = Puppet::Provider::Ldap.manages
#puts @resource
Puppet::Type.type(:adjoin).provide(:ad, parent: Puppet::Provider) do
#  Puppet::Provider::Ldap.manager

  ad_port = 389
  #username = "tom"
  #username = resource[:user]
  #password = "Kb-PwxS9.A>uFbL}"
  hostname = Socket.gethostname[/^[^.]+/]
  fqdn = Socket.gethostname
  computers_dn = "CN=Computers,DC=testing,DC=com"
  computer_sam = "#{hostname}$"
  os = "koji-linux-gnu"
  service_principal = ["host/#{hostname}", "host/#{fqdn}", "RestrictedKrbHost/#{hostname}", "RestrictedKrbHost/#{fqdn}"]

#dn = "CN=#{hostname},#{computers_dn}"

  def bind(username, password, host, port)
#    auth = {:method => :simple, :username => username, :password => password}
#    ldap = Net::LDAP.new( :host => host, :port => port, :auth => auth )
    ldap = new_ldap
    ldap.bind
  end

  def new_ldap
    auth = {:method => :simple, :username => resource[:user], :password => resource[:password]}
    ldap = Net::LDAP.new( :host => resource[:domain], :port => resource[:port], :auth => auth )
    ldap
  end

  def exists?
    treebase = "dc=testing,dc=com"
    hostname = Socket.gethostname[/^[^.]+/]
    computer_sam = "#{hostname}$"
    filter = Net::LDAP::Filter.eq( "sAMAccountName", computer_sam )
    attrs = ["sAMAccountName"]
    result = bind(resource[:user], resource[:password], resource[:domain], 389)
    ldap = new_ldap
    search_result = []
    search = ldap.search( :base => treebase, :filter => filter, :attributes => attrs, :return_result => true ) # do |entry|
 #     search_result << entry.sAMAccountName
 #   end
    search[0].sAMAccountName[0] == computer_sam
  end

  def create
    puts "what"
  end

  def destroy
    puts "whatt"
  end

  def user
    puts "get user"
  end

  def user=(new_user)
    puts "new user #{new_user}"
  end

  def password
    puts "get password"
  end

  def password=(new_pass)
    puts "new pass #{new_pass}"
  end

  def port
    puts "get port"
  end

  def port=(new_port)
    puts "new port #{new_port}"
  end

#  puts @resource.value(:domain)

# Implementation for the ldap type using the Resource API.
#class Puppet::Provider::Adjoin::Adjoin < Puppet::Provider::Ldap
#  def exists?
#  end

#  def bind(context)
#    #check that we can connect to the ldap server
#    ldap Net::LDAP.new( :host => ad_host, :port => ad_port, :auth => auth )
#  end

#  def get(context)
#    context.notice('Returning pre-canned example data')
#    [
#      {
#        name: 'foo',
#        ensure: 'present',
#      },
#      {
#        name: 'bar',
#        ensure: 'present',
#      },
#    ]
#  end

#  def create(context, name, should)
#    puts("~~~~~~~~~~")
#    context.notice("Creating '#{name}' with #{should.inspect}")
#  end

#  def update(context, name, should)
#    context.notice("Updating '#{name}' with #{should.inspect}")
#  end

#  def delete(context, name)
#    context.notice("Deleting '#{name}'")
#  end
end
