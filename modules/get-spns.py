from ldap3 import Server, Connection, NTLM, ALL

class CMEModule:
    '''
        List out all SPNs for domain
        Module by Douglas Berdeaux (@RackunSec)
    '''
    ## context's log methods: .error(), .info(), .highlight(), .success()
    name = 'get-spns'
    description = 'List out all SPNs for domain'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        self.context = context

    def on_login(self, context, connection):
        searchBase = connection.ldapConnection._baseDN
        searchFilter='(servicePrincipalName=*)'
        context.log.info(f"LDAP Filter: {searchFilter}")

        try:
            sc = ldap.SimplePagedResultsControl()
            results = connection.ldapConnection.search(searchFilter=searchFilter,
                attributes=['sAMAccountName', 'description'],
                sizeLimit=999, searchControls=[sc])
            ## loop over results and display them:
            for result in results:
                if isinstance(result,ldapasn1.SearchResultEntry):
                    for attribute in result['attributes']:
                        if str(attribute['type'])=='sAMAccountName':
                            sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                            context.log.success(f"SPN: {sAMAccountName}")
        except LDAPSearchError as e:
            context.log.error('Obtained unexpected exception: {}'.format(str(e)))
