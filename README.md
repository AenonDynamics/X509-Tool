X509 PKI Setup Utility
==========================

Single-File-Utlity to create X509 Certificates/PKI Structure for your OpenVPN Server or **any** TLS based communication.

## Features ##

* Single File CLI Tool
* Create CA, TLS Auth, Server Cert, DH-Params **in one Step**
* Add Clients
* Revoke Clients
* View Certificates
* Verify Certificates
* Maintain Certificate revocation list

## Documentation and Tutorials ##

* [Usage/Available Commands](docs/Usage.md)
* [OpenVPN Client/Server Configuration](docs/OpenVPN.md)
* [DD-WRT Server Configuration](docs/OpenVPN_DDWRT.md)

## Preface ##

**The X509-Tool is designed as [easy-rsa](https://github.com/OpenVPN/easy-rsa) replacement**

The primary objective is the creation of a simple, bulletproof tool which allows users to setup Certificates for OpenVPN or Webserver/TLS Authentication.
Such tasks doesn't require a bunch of intermdiate CAs or multiple server certificates.

### Basic CA Structure ###

In most cases (e.g. OpenVPN or Webserver Auth) your typical PKI will look like this:

![Demo](assets/structure.png)

* 1 Certificate Authority
* 1 Server 
* 1 to N Clients
* No Intermediate CA
* Cerificate Depths of **1**

### Directory Structure ###

The **X506-Tool** will create the following directory structure in your working dir

```raw
<working-dir>
   |- ca (the Cerificate Authority files, database, ..)
   |     |- ca.crt
   |     |- ca.key
   |     |- db.txt (list of all issued/revoked certs)
   |     |- serial (certificate serial number counter)
   |     |- crl.pem (Certificate revocation list)
   |
   |- srv (the Server Certificate, Private Key, TLS Auth Key, DH-Params)
   |     |- server.crt
   |     |- server.key
   |     |- tls-auth.key
   |     |- server.csr
   |     |- dhparam4096.pem
   |
   |- clients (Storage of the Client Certificates)
        |- <client-name-a>
        |- <client-name-b>
            |- client.crt
            |- client.key
            |- client.p12 (Client Cert+Key + CA Cert as single file)
            |- tls-auth.key
            |- client.csr

```

### OpenSSL Configuration ###

The Tool is shipped with a customized `openssl.conf` file which matches the used directory structure as well as client/server handling.
**Do not edit** this file if your are not sure what you're doing!

## Initial Setup ##

### Configuration File ###

First of all, you have to create a configuration file name `cert.conf` in your desired **working directory** (/opt/pki-mgmt/server1 in the example above). 
This file contains some basic settings like the keysize, lifetime and certificate informations.

The `X_COMMON_NAME` variables allows you to customize the common names of the CA or any generated Cert. This is especially useful for HTTPS Authentication were the common-name has to match the URL!
By default, the tool prefixes the common-names with their task. The placeholder `%s` is expanded by the second cli argument (name).

**All Options are required** 

```bash
#!/bin/bash

# OpenSSL Related Configuration
# -----------------------------------------------

# Recommended Key Size: >= 3072 bit
export KEY_SIZE=4096

# In how many days should the root CA key expire?
export CA_EXPIRE=3650

# In how many days should certificates expire?
export CRT_EXPIRE=3650

# Your Cert Params
export KEY_COUNTRY="DE"
export KEY_PROVINCE="BERLIN"
export KEY_CITY="BERLIN"
export KEY_ORG="My Company"
export KEY_EMAIL="pki-test@yourdomain.tld"
export KEY_OU="OVPN-PKI Testing"

# Certificate Common Name Templates
# -----------------------------------------------

# The placeholder %s is replaced by the second CLI argument
CA_COMMON_NAME="CA-%s"
SRV_COMMON_NAME="SRV-%s"
CLIENT_COMMON_NAME="CLIENT-%s"
```

### Getting Started ###

Please refer to the [Usage/Available Commands](docs/Usage.md) Section for general usage informations

```raw
# Step 1
# create the CA (Crt+Key), Server (Crt+Key), Diffie-Hellman Parameter and TLS-Auth Key
# "MyCA" is the name of your CA/Server Cert (Variable SRV_COMMON_NAME, CA_COMMON_NAME)
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh init MyCA

# Step 2
# Create your first Client named "user1"
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh add-client user1
```

## Security Recommendations ##

* Keep your **Private Keys secret** - especially the CA Key.
* Consider to **encrypt** your Private Keys by a strong passphrase using AES256

### Ciphers ###

The following ciphers are used by default:

* 4096 Bit [RSA Keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* 4096 Bit [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) Parameters
* AES256-CBC Symmetric Packet Encryption (Context: OpenVPN)
* SHA256 Message Digest (Context: OpenVPN)

## Contributing ##
Contributors are welcome! Even if you are not familiar with X509 certificates or bash scripting you can help to improve the documentation!

## Resources ##

A set of useful resources

* [Public key infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure) | Page
* [AES](https://en.wikipedia.org/wiki/<Advanced_Encryption_Standard></Advanced_Encryption_Standard>) | Page
* [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) | Page
* [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html) | Page
* [OpenVPN HOWTO](https://openvpn.net/index.php/open-source/documentation/howto.html) | Page
* [easy-rsa](https://github.com/OpenVPN/easy-rsa) | Page
* [BSI Cryptographic Key Recommendations](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf?__blob=publicationFile) (German) | PDF
* [NIST Recommendation for Key Management](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf) | PDF

## License ##
X509-Tool is OpenSource and licensed under the Terms of [The MIT License (X11)](http://opensource.org/licenses/MIT). You're welcome to contribute!