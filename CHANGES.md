## Branch 3.X ##

### 3.3.3 ###

* Security: added `warn_insecure_parameters()` in `environment_check` — warns about insecure cryptographic configuration:
  - `KEY_TYPE` not `EC` or `RSA` (e.g. DSA is deprecated/weak)
  - RSA `KEY_SIZE` < 2048 bits (INSECURE) or < 3072 bits (below NIST SP 800-57 recommendation)
  - EC `KEY_EC_CURVE` not in whitelist (`prime256v1`, `secp256r1`, `secp384r1`, `secp521r1`)
  - `pass:` passphrases shorter than 8 characters (weak) or 12 characters (recommended minimum)
  - `CRT_EXPIRE` > 398 days (CA/Browser Forum limit) or > 825 days (NIST SP 800-57 private PKI limit)
  - `CA_EXPIRE` > 7300 days (20 years — excessive root CA lifetime)
* Added: 40 new tests in `tests/test_16_warnings.bats` covering all parameter security warnings

### 3.3.2 ###

* Security: added `set -euo pipefail` for strict error handling (undefined variables, pipeline failures)
* Security: added `umask 077` — private keys and config files are no longer world-readable
* Security: added warning when `pass:` is used in `CA_PASS_TYPE`/`PKEY_PASS_TYPE`/`P12_PASS_TYPE` — passwords are visible in the process list (`ps`, `/proc/*/cmdline`); recommends `env:` or `file:` instead
* Security: added warning when `cert.conf` is readable by group/others — file contains passwords, recommends `chmod 600`
* Security: added `validate_cn()` — common names are validated against path traversal (`/`, `\`, `..`), leading `.`/`-`, and the RFC 5280 64-character limit
* Security: `rm -rf` now uses `--` and validates that the target path is inside `CRT_STORAGE_DIR` before deletion
* Security: PKCS#12 export now uses explicit AES-256-CBC encryption (`-certpbe`, `-keypbe`) and SHA-256 MAC (`-macalg sha256`)
* Security: `openssl verify` now uses `-x509_strict` for stricter RFC 5280 compliance checking
* Bugfix: ICA private keys are now encrypted with `CA_PASS_TYPE` (was `PKEY_PASS_TYPE`), fixing inconsistency where `openssl ca` could not read ICA keys signed with a different password
* Bugfix: `cert_revoke` error message corrected ("does not exist" instead of "already exists")
* Bugfix: `hook_exec` in `bash-functions` — fixed `$WORKINGDIR` typo (was `$WORKING_DIR`), hooks in working directory are now found correctly
* Changed: all shell variables are now properly quoted throughout the codebase (prevents word-splitting and glob expansion)
* Changed: removed deprecated `RANDFILE` directives from `openssl.conf` (unused since OpenSSL 1.1.1, internal CSPRNG is used)
* Changed: `bash-functions` — `print_heading`, `print_subheading`, `hook_exec`, `scriptd_exec` are now `set -u` safe

### 3.3.1 ###

* Security: private keys are now actually encrypted with AES-256-CBC — added `-aes-256-cbc` to `openssl genpkey` (previously `-pass` alone produced unencrypted PKCS#8 keys)
* Security: CRL is now generated as v2 with extensions (Authority Key Identifier) — added `crl_extensions = crl_ext` to `[CA_default]` in `openssl.conf`
* Changed: added `-passin` to all `openssl req`, `openssl ca`, and `openssl ca -gencrl` invocations to support encrypted CA and entity keys
* Added: comprehensive security compliance test suite (`tests/test_13_security.bats`, 85 tests) covering signature algorithms, key sizes, critical extensions, EKU/KU correctness, SAN, CRL v2, PKCS#12 encryption, validity periods, and revocation checks against NIST SP 800-57, RFC 5280, CA/Browser Forum Baseline Requirements

### 3.3.0 ###

* Added: optional subject alternative names (SANs) for `server add` and `host add` commands — additional domains can be passed as extra arguments, e.g. `x509-tool server add example.com www.example.com *.example.com`

### 3.2.0 ###

* Added: option to set p12 password type via `P12_PASS_TYPE`
* Added: option to set private key password type via `PKEY_PASS_TYPE`
* Added: option to set ca private key password type via `CA_PASS_TYPE`
* Changed: added `critical` attribute to `S/MIME` key usage
* Changed: added `clientAuth` to `S/MIME` key usage
* Changed: removed deprecated `-nodes` option from pkcs12 generation
* Bugfix: show/verify commands were broken due to refactoring

### 3.1.0 ###

* Added: fullchain certificate chain is maintained within intermediate authorities
* Added: fullchain added `p12` cert files

### 3.0.0 ###

* Refactored the whole codebase. Methods are splitted into multiple files
* Added: support for elliptic curves
* Added: support for smime certificates
* Added: support for intermediate certificate authorities
* Added: option to use resolved certificate common name as filename (pem,key,crt,csr,p12)
* Changed: cli commands for `ca` and `openvpn` initialization have changed
* Changed: default signature algorithm to sha384 (`openssl.conf`)

-------------------------------------------------

## Branch 2.X ##

### 2.2.2 ###

* Bugfix: added `clientAuth` to codesigning key usage
* Bugfix: code-signing cert revocation pre-check failed

### 2.2.1 ###

* Added: support for code-signing certificates
* Changed: removed plain-text output from certificate files `-notext`
* Bugfix: output directory name doesn't use the full common-name based on the configuration - only second name argument was used

### 2.1.0 ###

* Added: support for host/node certificates (client+server extended usage)
* Bugfix: `subjectAltName` was missing in server certs (required for self signed webserver auth) - new default `DNS:<COMMON_NAME>`
* Bugfix: `CLIENT_COMMON_NAME` template overrides other templates

### 2.0.1 ###

* Bugfix: Allow whitespaces in certificate common-name

### 2.0.0 ###

* Added: initialization for generic CAs (not openvpn related)
* Added: support for multiple servers
* Added: server certificate revocation
* Changed: License to MPL-2.0
* Changed: new Syntax is used

-------------------------------------------------

## Branch 1.X ##

## 1.1.0 ###
* Added: Server certificate is also converted into **p12** format
* Removed Password prompt when creating a new client
* Changed: openssl min version to **1.0.0**

### 1.0.0 ###

* Initial Public Release