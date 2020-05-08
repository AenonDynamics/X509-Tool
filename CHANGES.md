## Branch 2.X ##

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