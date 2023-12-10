# regdumper-rs
Nothing new, just a SAM, SYSTEM and SECURITY registry hives dumper, written in Rust for learning purposes.

## Usage
Just (compile and) execute the binary. 
The output will differ based on the privilege level:

- "User": it will extract, decode, and print the bootkey
- "Administrator": as above, plus dump SYSTEM and SAM as "sistemino.txt" and "samantha.txt", in local directory. Then it will elevate to "System" and dump SECURITY as "secco.txt", in local directory.

The created files can be parsed with "secretsdump", for example.

## Takeaways
- Any user can extract the Windows bootkey stored in HKLM\SYSTEM, no big secret
- User "Administrator" has full permissions over HKLM\SAM, but no permissions over HKLM\SAM\SAM, so as admins we cannot read/extract single subkeys of SAM, but we can dump the whole hive then extract the needed data...
- Finally, to save the SECURITY hive we need "System" privileges. This can be achieved in different ways; here we steal the "winlogon" process token, use it for impersonation and enable the privileges to operate on registry hives.
