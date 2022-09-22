from ldap3 import Server, Connection, NTLM, ALL
#import sys ## DEBUG

class CMEModule:
    '''
        List out all users and computers with unconstrained delegation
        Module by Douglas Berdeaux (@RackunSec)
    '''
    name = 'ud-check'
    description = 'List out all SPNs for domain'
    supported_protocols = ['ldap']
    opsec_safe = True #Does the module touch disk?
    multiple_hosts = True # Does it make sense to run this module on multiple hosts at a time?

    def options(self, context, module_options):
        self.context = context

    def on_login(self, context, connection):
        searchBase = connection.ldapConnection._baseDN
        sysSearchFilter='(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        userSearchFilter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))' # referenced: https://troopers.de/downloads/troopers19/TROOPERS19_AD_Fun_With_LDAP.pdf

        context.log.info(f"LDAP Computer Filter: {sysSearchFilter}")
        context.log.info(f"LDAP User Filter: {userSearchFilter}")

        ## Computers:
        sc = ldap.SimplePagedResultsControl()
        computer_records = connection.ldapConnection.search(searchFilter=sysSearchFilter,
            attributes=['sAMAccountName', 'description'],
            sizeLimit=999, searchControls=[sc])

        user_records = connection.ldapConnection.search(searchFilter=userSearchFilter,
                attributes=['sAMAccountName', 'description'],
                sizeLimit=999, searchControls=[sc])
        ## Handle the computer records:
        for record in computer_records:
            if isinstance(record,ldapasn1.SearchResultEntry):
                for attribute in record['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                        context.log.success(f"Computer Unconstrained Delegation: {sAMAccountName}")
        ## Handle the user records:
        for record in user_records:
            if isinstance(record,ldapasn1.SearchResultEntry):
                for attribute in record['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                        context.log.success(f"User Unconstrained Delegation: {sAMAccountName}")
