# http://garylarizza.com/blog/2013/12/15/seriously-what-is-this-provider-doing/
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
  mk_resource_methods


#  Puppet::Provider::Ldap.manager
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

  def self.bind(username, password, host, port)
    ldap = new_ldap(username, password, host, port)
    ldap.bind
  end

  def self.new_ldap(username, password, host, port)
    auth = {:method => :simple, :username => username, :password => password}
    ldap = Net::LDAP.new( :host => host, :port => port, :auth => auth )
    ldap
  end

  def self.get_domain_list
    domains = []
    domain = {}
    domain["name"] = "testing.com"
    domain["user"] = "tom"
    domain["password"] = "Kb-PwxS9.A>uFbL}"
    domain["port"] = "389"
    domain1 = {}
    domain1["name"] = "1testing.com"
    domain1["user"] = "1tom"
    domain1["password"] = "1Kb-PwxS9.A>uFbL}"
    domain1["port"] = "1389"
    domains << domain
    domains << domain1
    domains
  end

#  def self.prefetch(resources)
    # Not the usual way we would use prefetch. See real_prefetch.
    # Using this method to return a list of catalogue resources.
    # We need this list as domains joined is not a property of the machine, rather an entry in some other ldap server,
    # so we only want to check for domains listed in the catalogue

#    resources
#  end

  def self.prefetch(resources)
    if resource = resources["testing.com"]
      puts resource.methods
      puts resource.original_parameters[:user]
    end
    instances().each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  def self.real_prefetch
    resources = prefetch()
    puts "PREFETCH:"
    resources.each do |resource|
      puts resource
    end
    this_resource = resources["testing.com"]
    puts this_resource.provider
    puts "PREFETCH END:"
#    puts resources[]
#    instances.each do |prov|
#      if resource = resources[prov.name]
#        resource.provider = prov
#      end
#    end
  end

  def self.get_adjoin_properties(username, password, host, port)
    adjoin_properties = {}
    puts "GET_ADJOIN_PROPERTIES"
    puts username
    ldap = new_ldap(username, password, host, port)
    treebase = "dc=testing,dc=com"
    hostname = Socket.gethostname[/^[^.]+/]
    computer_sam = "#{hostname}$"
    filter = Net::LDAP::Filter.eq( "sAMAccountName", computer_sam )
    puts "WTF"
    attrs = ["sAMAccountName"]
    result = bind(username, password, host, 389)
    search_result = []
    search = ldap.search( :base => treebase, :filter => filter, :attributes => attrs, :return_result => true ) # do |entry|
    puts search.count
    adjoin_properties[:ensure] = search.count == 0 ? :absent : :present
    adjoin_properties[:domain] = host
    puts adjoin_properties
    return adjoin_properties
  end

  def self.instances(resources)
    notice("SELF.INSTANCES")
    get_domain_list.each do |int|
      puts int["user"]
      adjoin_properties = get_adjoin_properties(int["user"], int["password"], int["name"], int["port"])
      new(adjoin_properties)
    end
  end

  def exists?
    
    puts "EXISTS_START"
#    puts self.class.instances()
    puts @provider_hash
    puts "EXISTS: #{resource[:name]}"
    puts @property_hash[:ensure]
    @property_hash[:ensure] == :present
  end

  def initialize(value={})
    super(value)
    @property_flush = {}
  end

#  def exists?
#    puts @ad_port
#    treebase = "dc=testing,dc=com"
#    hostname = Socket.gethostname[/^[^.]+/]
#    computer_sam = "#{hostname}$"
#    filter = Net::LDAP::Filter.eq( "sAMAccountName", computer_sam )
#    attrs = ["sAMAccountName"]
#    result = bind(resource[:user], resource[:password], resource[:domain], 389)
#    ldap = new_ldap
#    search_result = []
#    search = ldap.search( :base => treebase, :filter => filter, :attributes => attrs, :return_result => true )
#    unless search.count == 0
#      return_value = search[0].sAMAccountName[0] == computer_sam
#    else
#      return_value = false
#    end
#    return_value
#    false
#  end

  @test = "testing456"

  def create
    puts "what"
#    set_vars
    puts @test
  end

  def destroy
    puts "whatt"
  end

#  def user
#    puts "get user"
#  end

#  def user=(new_user)
#    puts "new user #{new_user}"
#  end

#  def password
#    puts "get password"
#  end

#  def password=(new_pass)
#    puts "new pass #{new_pass}"
#  end

#  def port
#    puts "get port"
#  end

#  def port=(new_port)
#    puts "new port #{new_port}"
#  end

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
puts "finished"
