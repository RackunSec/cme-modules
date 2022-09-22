#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.dcerpc.v5.rrp import DCERPCSessionError

class CMEModule:
    '''
    Detect if the target has various Microsoft LSA protections enabled (Requires Admin)
    Module by @RackunSec
    '''
    name = 'ms-lsa-protect'
    description = 'Detect if the target has various Microsoft LSA protections enabled (Requires Admin)'
    supported_protocols = ['smb']
    opsec_safe= True
    multiple_hosts = True

    def options(self, context, module_options):
        pass

    def on_admin_login(self, context, connection):
        try:
            remoteOps = RemoteOperations(connection.conn, False)
            remoteOps.enableRegistry()

            if remoteOps._RemoteOperations__rrp:
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
                regHandle = ans['phKey']

                ## Check if SecureBoot is enabled:
                ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State')
                keyHandle = ans['phkResult']
                rtype, data = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, 'UEFISecureBootEnabled\x00')
                if int(data)==0:
                    context.log.highlight("Secure Boot disabled on host!")
                else:
                    context.log.error("Secure Boot enabled on host.")

                ## Check if RunAsPPL is enabled:
                try:
                    ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp,regHandle,'SYSTEM\\CurrentControlSet\\Control\\Lsa')
                    keyHandle = ans['phkResult']
                    rtype,data=rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp,keyHandle,'RunAsPPL\x00')
                    if int(data)==0:
                        context.log.highlight(f"RunAsPPL Disabled on host! {int(data)}")
                    else:
                        context.log.error("RunAsPPL enabled on host.")
                except Exception as e:
                    context.log.highlight(f"No registry entry identified for RunAsPPL.")

                ## Check if WDigest is enabled:
                try:
                    ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle,'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest')
                    keyHandle=ans['phkResult']
                    rtype,data=rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp,keyHandle,'UseLogonCredential\x00')
                    if int(data)==0:
                        context.log.error("WDigest disabled on host")
                    else:
                        context.log.highlight("WDigest enabled on host!")
                except Exception as e:
                    context.log.error("No registry entry identified for WDigest. You will have to create one.")

                ## Check for Windows Defender Remote Credential Guard:
                try:
                    ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp,regHandle,'SYSTEM\\CurrentControlSet\\Control\\Lsa')
                    keyHandle=ans['phkResult']
                    rtype,data=rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp,keyHandle,'LsaCfgFlags')
                    if int(data)==0:
                        context.log.highlight("Windows Defender Remote Credential Guard disabled!")
                    elif int(data)==1:
                        context.log.error("Windows Defender Credential Guard enabled with UEFI lock.")
                    elif int(data)==2:
                        context.log.error("Windows Defender Credential Guard enabled without UEFI lock.")
                except Exception as e:
                    context.log.highlight("No registry entry identified for Windows Defender Credential Guard!")

                ## Check for virtualization-based security:
                try:
                    ans=rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp,regHandle,'SYSTEM\\CurrentControlSet\\Control\\DeviceGuard')
                    keyHandle=ans['phkResult']
                    rtype,data=rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp,keyHandle,'EnableVirtualizationBasedSecurity')
                    if int(data)==0:
                        context.log.highlight("Virtualization-based security disabled on host!")
                    elif int(data)==1:
                        context.log.error("Virtualization-based security enabled on host.")
                except Exception as e:
                    context.log.highlight("No registry entry identified for virtualization-based security!")


            try:
                remoteOps.finish()
            except:
                pass

        except DCERPCSessionError as e:
            context.log.error(f"Something went wrong. {e}")
            try:
                remoteOps.finish()
            except:
                pass
