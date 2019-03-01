# Do not use yet
Trust-ACME orders and manages certificates. DNS challenges and DANE are done with [Trust-DNS](https://github.com/bluejekyll/trust-dns).

User's trust should be founded on strong defaults and only a few chosen dependencies.

Currently it just reads its config file and orders all configured certificates without further logic.

## TODO
* verify whether this tutorial is actually working or not
* cleanup code
* reload services only at the end of processing all certs
* better error handling
* reintroduce (some) tests
* reuse one TCP connection to Trust-DNS
* order url should be stored in a certs/example.com.txt file to check validity/revocation status on each run.
* example.com_next.crt should be ordered 7 days before regular expiration, to have a smooth TLSA transition. Revocation would still hurt.
* option to provide a manually generated rsa key for postfix
* cleanup of certs/keys that are unknown to the config
* command line arguments
* having a Trust-DNS systemd service to offer DNS-over-TLS
* reconsider folder structure and everything

## Non-Goals
* Dependency terror
* Using OpenSSL
* Insecure HTTP challenges
* Hard to read code

## How to test

First we set up a [Trust-DNS](https://github.com/bluejekyll/trust-dns) server. Warning: This config is a personal flavor.
```console
# curl https://sh.rustup.rs -sSf | sh
# source $HOME/.cargo/env
# cargo install kt -f
# cargo install trust-dns-server --git https://github.com/bluejekyll/trust-dns --features dnssec-ring -f
# mkdir /etc/trust-dns; mkdir /etc/trust-dns/zones; mkdir /etc/trust-dns/keys
# kt generate ed25519 --out /etc/trust-dns/keys/dns_auth.pk8
# kt generate p384 --out /etc/trust-dns/keys/example.com.pk8
```

nano /etc/trust-dns/config.toml
```toml
listen_addrs_ipv4 = ["your public ipv4 address"]
listen_addrs_ipv6 = ["::1", "your public ipv6 address"]
listen_port = 53

[[zones]]
zone = "example.com"
zone_type = "Master"
enable_dnssec = true
stores = { type = "sqlite", zone_file_path = "example.com", journal_file_path = "example.com.jrnl", allow_update = true }
keys = [{key_path="keys/example.com.pk8", algorithm="ECDSAP384SHA384", is_zone_signing_key=true}, {key_path="keys/dns_auth.pk8", algorithm="ED25519", is_zone_update_auth=true}]
```
([Official examples](https://github.com/bluejekyll/trust-dns/blob/master/crates/server/tests/named_test_configs/dnssec_with_update.toml) don't use inline tables for `keys`; I just prefer to have compact zone configs.)

nano /etc/trust-dns/zones/example.com
```
@ 86400 IN SOA ns1.example.com. hostmaster.example.com. (
  201903010 ; Serial
  3600      ; Refresh
  600       ; Retry
  86400     ; Expire
  600)      ; Negative TTL
@ 86400 IN NS ns1.example.com.
@ 86400 IN NS ns2.example.com.
@ 86400 IN MX 5 mail.example.com.
@ 86400 IN TXT "v=spf1 mx -all"
@ 86400 IN CAA 0 issue "letsencrypt.org; validationmethods=dns-01"
@ 86400 IN CAA 0 iodef "mailto:hostmaster@example.com"
@ 86400 IN AAAA ::1
www 86400 IN AAAA ::1
www 86400 IN MX 0 .
ns1 86400 IN AAAA ::1
ns1 86400 IN A 127.0.0.1
ns1 86400 IN MX 0 .
ns2 86400 IN AAAA ::1
ns2 86400 IN A 127.0.0.1
ns2 86400 IN MX 0 .
mail 86400 IN AAAA ::1
mail 86400 IN A 127.0.0.1
```

Let's check how it goes:
```console
# cd /etc/trust-dns; named --config /etc/trust-dns/config.toml --zonedir /etc/trust-dns/zones
```

As long we don't have a nice systemd service:
```console
# cat << EOF > /root/trust-dns.sh
#!/bin/bash
cd /etc/trust-dns; screen -dmS trust-dns named --config /etc/trust-dns/config.toml --zonedir /etc/trust-dns/zones
EOF
# chmod +x /root/trust-dns.sh
```

How to get the DNSKEY for your DNS provider to make DNSSEC actually working?
```console
$ dig DNSKEY example.com @trust-dns-server-ip +short +nosplit
```
You just want to try it out with a sub domain as zone and need to generate a DS record?
Use https://filippo.io/dnskey-to-ds/.

Let's proceed and install trust-acme:
```console
# cargo install trust-acme -f
# mkdir /etc/trust-acme; mkdir /etc/trust-acme/certs
# kt generate p384 --out /etc/trust-acme/letsencrypt_account.pk8
```
nano /etc/trust-acme/config.toml
```toml
[ca.letsencrypt]
directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
account_key = "/etc/trust-acme/letsencrypt_account.pk8"
account_email = "hostmaster@example.com"

[trustdns.default]
server = "[::1]:53"
auth_key = "/etc/trust-dns/keys/dns_auth.pk8"

[[cert]]
zone = "example.com"
# whether there should be an additional openssl-style pem key (example.com.key)
pem_key = true
reload = ["nginx"]
san = [
    { name = "example.com", tcp = [443] },
    { name = "www.example.com", tcp = [443] },
]

#[[cert]]
#zone = "example.com"
#reload = ["trust-dns"]
#
#[[cert.san]]
#name = "ns.example.com"
#tcp = [853]
#udp = [853]
```
If you comment out `directory`, the real Let's Encrypt will be used. For simplicity regarding TLSA records it's currently not possible to have SAN entries from different zones. At the moment, only ECDSA P-384 certificates are supported.

To order, just run:
```console
# trust-acme
```

A certificate's first SAN entry will be used as its file name:
```
Certificate path: /etc/trust-acme/certs/example.com.crt
Key path (Rustls): /etc/trust-acme/certs/example.com.pk8
Key path (OpenSSL): /etc/trust-acme/certs/example.com.key
```
