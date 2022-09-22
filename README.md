# Custom CME Modules
Just some [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) modules that I am working on. 
## Modules
### LDAP
 * [list-da-members](/modules/list-da-members.py) - Simply lists out all Domain Admin members for the domain
 * [get-spns](/modules/get-spns.py) - Simply list all Service Principle Names for the domain
### SMB
 * [ms-lsa-protect](/modules/ms-lsa-protect.py) - Check a system for Microsoft's LSA protections

## Usage
Clone the repository and place the module files in `./modules` into your CME modules directory. Then, simply run the following command to see if they are available:
```bash
poetry run crackmapexec (PROTOCOL) -L
```
where (PROTOCOL) is the one listed from above.
