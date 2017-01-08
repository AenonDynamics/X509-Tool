OpenVPN Setup
=============

First of all - read the [Official OpenVPN Documentation](https://openvpn.net/index.php/open-source/documentation/howto.html) and [OpenVPN Manual](https://openvpn.net/index.php/open-source/documentation/manuals/65-openvpn-20x-manpage.html)

**It is very important that you understand each of the following directives!**


## Server Configuration ##

Please take a look on the [Official OpenVPN Server Example](https://openvpn.net/index.php/open-source/documentation/howto.html#server)

In this example, we've used a routed subnet topology (10.200.200.0/24). There are no routes pushed to the client yet. This means the client can only reach the VPN Server. 

```ini
# use UDP as transport protocol
proto udp

# the virtual device name on linux systems (use "tun" on Windows)
dev tun0

# VPN Listening Port
port 1194

# Configure server mode (shortcut mode server && tls-server) and setup VPN Subnet
server 10.200.200.0 255.255.255.0

# Diffie hellman parameter file
dh <serverconfig>/dh4096.pem

# the server certificate - you can also use 3 PEM files (CA.crt, SERVER.crt, SERVER.key)
pkcs12 <serverconfig>/server.p12

# the TLS Authentication Key - argument "0" defines server-mode
tls-auth <serverconfig>/tls-auth.key 0

# Maintain a record of client virtual IP address (Assigned IP Addresses will survive reboots, reconnects)
ifconfig-pool-persist ipp.txt

# Send Beacons(Ping Messages) every 20s, assume the link is down after 120s without beacon
keepalive 20 120

# Encryption using secure ciphers (as of 2016)
cipher AES-256-CBC

# HMAC Algorithm for Packet Authentication
auth SHA256

# Force TLS cipher - Diffie–Hellman for key exchange; RSA for authentication; AES-256-CBC-SHA256 for the handshake
tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA256

# disable compression on the VPN link (performance impact)
comp-lzo no

# Downgrade privileges after initialization (non-Windows only)
# run the OpenVPN Client Instance as user/group openvpn (has to be created prior)
user openvpn
group openvpn

# Try to preserve some state across restarts.
persist-tun
persist-key

# Output status file (updated every minute) - contains connection info
status /var/log/openvpn-status.log

# Use a dedicated logfile
log-append /var/log/openvpn.log

# Set log file verbosity - show warnings and some impotant notices (connect..)
verb 3
```

## Client Configuration ##

Please take a look on the [Official OpenVPN Client Example](https://openvpn.net/index.php/open-source/documentation/howto.html#client)

```ini
# client mode -equivalent to pull && tls-client
client

# use UDP as transport protocol
proto udp

# the virtual device name on linux systems (use "tun" on Windows)
dev tun0

# insert the hostname/ipaddress of your OpenVPN Server - 1094 is the default port
remote <ipaddr/hostname> 1194 udp

# Verify the Server Common Name - replace it with the your servers cn
verify-x509-name "<SRV-YourServer>" name

# the user certificate - you can also use 3 PEM files (CA.crt, CLIENT.crt, CLIENT.key)
pkcs12 <clientdir>/client.p12

# the TLS Authentication Key - argument "1" defines client-mode
tls-auth <clientdir>/tls-auth.key 1

# Try to preserve some state across restarts.
persist-tun
persist-key

# Verify server certificate by checking that the certicate has the nsCertType field set to "server"
# Otherwise other clients could potentially act as server
ns-cert-type server

# disable compression on the VPN link (performance impact)
comp-lzo no

# Encryption using secure ciphers (as of 2016)
cipher AES-256-CBC

# HMAC Algorithm for Packet Authentication
auth SHA256

# Force TLS cipher - Diffie–Hellman for key exchange; RSA for authentication; AES-256-CBC-SHA256 for the handshake
tls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA256

# Keep trying indefinitely to resolve the host name of the OpenVPN server
resolv-retry infinite

# Downgrade privileges after initialization (non-Windows only)
# run the OpenVPN Client Instance as user/group openvpn (has to be created prior)
user openvpn
group openvpn

# Set log file verbosity - show warnings and some impotant notices (connect..)
verb 3

```
