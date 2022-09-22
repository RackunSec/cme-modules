from ldap3 import Server, Connection, NTLM, ALL

class CMEModule:
    '''
        List out all Domain Admin Accounts
        Module by Douglas Berdeaux (@RackunSec)
    '''
    name = 'list-da-members'
    description = 'List all Domain Admin members'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        self.context = context


    def on_login(self, context, connection):
        searchBase = connection.ldapConnection._baseDN

        searchFilter='(memberOf=CN=Domain Admins,OU=Groups,'+connection.baseDN+')'

        context.log.info(f"LDAP Filter: {searchFilter}")

        try:
            sc = ldap.SimplePagedResultsControl()
            records = connection.ldapConnection.search(searchFilter=searchFilter,
                attributes=['sAMAccountName', 'description'],
                sizeLimit=999, searchControls=[sc])
            for record in records:
                if isinstance(record,ldapasn1.SearchResultEntry):
                    for attribute in record['attributes']:
                        if str(attribute['type']) == 'sAMAccountName':
                            sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                            context.log.success(f"Domain Admin: {sAMAccountName}")
        except LDAPSearchError as e:
            context.log.error('Obtained unexpected exception: {}'.format(str(e)))
