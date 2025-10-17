# custom mTLS Setup for local TI components #

## 1. Adjust config file to match ECC NIST-256 curve

File: `cert.conf`

```conf
#!/bin/bash

# OpenSSL Related Configuration
# -----------------------------------------------

# ECC required from 2026!
export KEY_TYPE="EC"

# select curve e.g. NIST256 (prime256v1)
export KEY_EC_CURVE="prime256v1"

# Your Cert Params
export KEY_COUNTRY="DE"
export KEY_PROVINCE="BREMEN"
export KEY_CITY="BREMEN"
export KEY_ORG="Praxis XYZ"
export KEY_EMAIL="pki@praxis.tld"
export KEY_OU="Telematikinfrasturktur PKI"

# x509 tool settings
# -----------------------------------------------

# In how many days should the root CA key expire? 10 Years
CA_EXPIRE=3650

# In how many days should certificates expire? 10 Years
CRT_EXPIRE=3650

# certificate naming scheme: generic (client.crt) or based on common name (<cn>.crt)
CRT_SCHEME="cn"

# how should the private key password provided?
# https://docs.openssl.org/3.6/man1/openssl-passphrase-options
PKEY_PASS_TYPE="pass:geheim"

# how should the p12 password provided?
# https://docs.openssl.org/3.6/man1/openssl-passphrase-options
P12_PASS_TYPE="pass:geheim"

# Certificate Common Name Templates
# -----------------------------------------------

# The placeholder %s is replaced by the second CLI argument
CA_COMMON_NAME="%s"
ICA_COMMON_NAME="%s"
SRV_COMMON_NAME="%s"
CLIENT_COMMON_NAME="%s"
HOST_COMMON_NAME="%s"
CODESIGNING_COMMON_NAME="%s"
SMIME_COMMON_NAME="%s"
SMIME_EMAIL_NAME="%s"
```

## 2. Generate required structure

```bash
#!/usr/bin/env bash

set -xe

x509-tool ca init "Praxis TI Auth CA"
x509-tool server add "ti.gw.meinepraxis"
x509-tool client add "tomedo.ti.meinepraxis"
x509-tool client add "kimplus.ti.meinepraxis"
```

## 3. Upload Certs

* Upload `server/ti.gw.meinepraxis/ti.gw.meinepraxis.p12` to your TI Konnektor (TI gateway highspeed konnektor)
   Password is defined by the config file variable `P12_PASS_TYPE`
* Upload `client/tomedo.ti.meinepraxis/tomedo.ti.meinepraxis.p12` into your tomedo (PVS) konnektor setup
   Password is defined by the config file variable `P12_PASS_TYPE`
* Upload `client/kimplus.ti.meinepraxis/kimplus.ti.meinepraxis.{key,crt}` into your KIMplus client module
   Password is defined by the config file variable `PKEY_PASS_TYPE`