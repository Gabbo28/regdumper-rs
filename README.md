# regdumper-rs
Nothing new, just a SAM, SYSTEM and SECURITY registry hives dumper, written in Rust for learning purposes.

## Usage
Just (compile and) execute the binary, as "Administrator" or "System".   
It will create the files "sistemino.txt" (SYSTEM), "samantha.txt" (SAM) and, if run as "System", "secco.txt" (SECURITY), which can be parsed with "secretsdump", for example.

## Takeaways
- Any user can extract the Windows bootkey stored in HKLM\SYSTEM, no big secret
- User "Administrator" has full permissions over HKLM\SAM, but no permissions over HKLM\SAM\SAM, so as admins we cannot read/extract single subkeys of SAM, but we can dump the whole hive then extract the needed data...
- Finally, to save the SECURITY hive we need "System" privileges
