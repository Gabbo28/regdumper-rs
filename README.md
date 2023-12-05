# regdumper-rs

Nothing new, just a SAM and SYSTEM registry hives dumper, written in Rust for learning purposes.

**Takeaways**
- Any user can extract the Windows bootkey stored in HKLM\SYSTEM, no big secret
- User "Administrator" has full permissions over HKLM\SAM, but no permissions over HKLM\SAM\SAM, so as admins we cannot read/extract single subkeys of SAM, but we can dump the whole hive then extract the needed data...
- Finally, to save the SECURITY hive we need "System" privileges
