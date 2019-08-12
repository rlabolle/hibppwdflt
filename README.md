# Offline "Have I been pwned" Password Filter for LSA

This module can be used to exclude leaked passwords from the "Have I been pwned" Password database from being used as a windows password, either locally or in an Active Directory domain.

## Building

You need rust for windows plateform to build it.

```
cargo build --release
```

## Generating the compact hash database

* Download the *NTLM* (ordered by hash) list from the [Have I been Pwned website](https://haveibeenpwned.com/Passwords)
* Extract the list and convert it with `convertdb.py`  python 3 script:
```
python3 ./convertdb.py pwned-passwords-ntlm-ordered-by-hash-v4.txt hibp.chdb
```

## Installation

* Copy `hibppwdflt.dll` file to `C:\Windows\System32\hibppwdflt.dll`
* Copy `hibp.chdb` file to `C:\Windows\System32\HIBPPwdFlt\hibp.chdb`
* [Register the Password Filter](https://docs.microsoft.com/en-us/windows/desktop/secmgmt/installing-and-registering-a-password-filter-dll)

## Configuration

You can configure this password filter with the following registry subkey of `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\HIBPPwdFlt` :

* `RejectOnError` (DWORD): set to 1 to reject passwords in case of IO errors (Default: `0`)
* `CheckOnSet` (DWORD): check the password on "set password" operations usualy from an admin account (Default: `0`) 
 * `DBPath` (STRING): Database path (Default: `C:\Windows\System32\HIBPPwdFlt\hibp.chdb`)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
