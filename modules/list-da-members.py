from ldap3 import Server, Connection, NTLM, ALL
#import sys ## DEBUG

class CMEModule:
    '''
        List out all Domain Admin members
        Module by Douglas Berdeaux (@RackunSec)
    '''
    name = 'list-da-members'
    description = 'List all Domain Admin members'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?



    def options(self, context, module_options):
        self.context = context

    def process_record(self, item):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        else:
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                        print(f"Domain Admin: {sAMAccountName}")
            except Exception as e:
                print(f"[DAFUQ]: {e}")

    def on_login(self, context, connection):
        searchBase = connection.ldapConnection._baseDN
        #sys.exit() ## DEBUG

        searchFilter='(memberOf=CN=Domain Admins,OU=Groups,'+connection.baseDN+')'

        context.log.info(f"LDAP Filter: {searchFilter}")

        try:
            sc = ldap.SimplePagedResultsControl()
            connection.ldapConnection.search(searchFilter=searchFilter,
                attributes=['sAMAccountName', 'description'],
                sizeLimit=999, searchControls=[sc],
                perRecordCallback=self.process_record)
        except LDAPSearchError as e:
            context.log.error('Obtained unexpected exception: {}'.format(str(e)))