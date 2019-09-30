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

  def initialize(value={})
    super(value)
    @property_flush = {}
  end


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

  def self.prefetch(resources)
    instances(resources).each do |prov|
      if resource = resources[prov.domain]
        resource.provider = prov
      end
    end
  end

  def self.get_adjoin_properties(username, password, host, port)
    adjoin_properties = {}
    ldap = new_ldap(username, password, host, port)
    treebase = "dc=testing,dc=com"
    hostname = Socket.gethostname[/^[^.]+/]
    computer_sam = "#{hostname}$"
    filter = Net::LDAP::Filter.eq( "sAMAccountName", computer_sam )
    attrs = ["sAMAccountName"]
    result = bind(username, password, host, 389)
    search_result = []
    search = ldap.search( :base => treebase, :filter => filter, :attributes => attrs, :return_result => true ) # do |entry|
    adjoin_properties[:ensure] = search.count == 0 ? :absent : :present
    adjoin_properties[:domain] = host
    return adjoin_properties
  end

  def self.instances(resources = nil)
    domain_list = []
    if resources
      resources.keys.each do |resource|
        domain = {}
        domain[:domain] = resource
        domain[:user] = resources[resource].original_parameters[:user]
        domain[:password] = resources[resource].original_parameters[:password]
        domain[:port] = resources[resource].original_parameters[:port]
        domain_list << domain
      end
    else
      domain_list = get_domain_list
    end
    domain_list.collect do |int|
      adjoin_properties = get_adjoin_properties(int[:user], int[:password], int[:domain], int[:port])
      new(adjoin_properties)
    end
  end

  def exists?
    @property_hash[:ensure] == :present
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

  def create
    puts "Creating:-"
    @property_flush[:ensure] = :present
  end

  def destroy
    puts "Destroying:-"
    @property_flush[:ensure] = :absent
  end

  def flush
    set_ldap

    # Collect the resources again once they've been changed (that way `puppet
    # resource` will show the correct values after changes have been made).
    @property_hash = self.class.get_adjoin_properties(resource[:user], resource[:password], resource[:domain], resource[:port])
  end

  def set_ldap
    hostname = Socket.gethostname[/^[^.]+/]
    fqdn = Socket.gethostname
    computers_dn = "CN=Computers,DC=testing,DC=com"
    computer_sam = "#{hostname}$"
    os = "koji-linux-gnu"
    service_principal = ["host/#{hostname}", "host/#{fqdn}", "RestrictedKrbHost/#{hostname}", "RestrictedKrbHost/#{fqdn}"]
    dn = "CN=#{hostname},#{computers_dn}"

    attr = {
      :sAMAccountName => computer_sam,
      :objectclass => ["computer", "top", "person", "user", "organizationalPerson"],
      :userAccountControl => "69632", # /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
 #    :msDS-supportedEncryptionTypes => [nil, nil],
      :dNSHostName => fqdn,
      :operatingSystem => os,
      :servicePrincipalName => service_principal
    }

    ldap = self.class.new_ldap(resource[:user], resource[:password], resource[:domain], resource[:port])
    
    if @property_flush[:ensure] == :absent
      ldap.delete :dn => dn
      return
    end
    if exists?
#      ops = [
#        [:add, :mail, "aliasaddress@example.com"],
#        [:replace, :mail, ["newaddress@example.com", "newalias@example.com"]],
#        [:delete, :sn, nil]
#      ]
#      ldap.modify :dn => dn, :operations => ops
#      return
    end
    ldap.add :dn => dn, :attributes => attr
  end
end
