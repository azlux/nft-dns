# nft-dns
Make the nftables resolve fqdn on-the-fly !

Back on iptables, fqdn was available into rules, but was resolved at start only. This have never been improved.

This project try to resolve this limitation.
NFT-DNS start with it own configuration file, will resolve the DNS and keep the TTL, then will populate the NFT [named SET](https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets_specifications).

The script will make DNS query each time the TTL reach zero, this way, your system will resolve the entries accept (or refused) by your firewall, even if the domain have change it IP.
The script is both IPv4 and IPv6 compatible.

-----
## Quick Start Guide
1. [Features](#features)
2. [Installation](#installation)
3. [TODO](#todo)

## Features
- FQDN support
   - *wildcard only if there are a Wildcard DNS record 
- Configuration via simple config files into a folder (allow multiple config file)
  - Config with .ini format 
- Packaged with apt
  - upgrade with APT 
  - Service packaged with systemd

## Installation
### With APT (recommended)
    echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ bookworm main" | sudo tee /etc/apt/sources.list.d/azlux.list
    sudo wget -O /usr/share/keyrings/azlux-archive-keyring.gpg  https://azlux.fr/repo.gpg
    sudo apt update
    sudo apt install nft-dns
    sudo systemctl enable nft-dns
    sudo systemctl start nft-dns

### Manually
You can just clone the project, it's a one-script (`nft-dns.py`). But you will have not auto-update.
You will need to create your one init service.

## Help
### Command line
Use `nft-dns.py --help` to get the usage help.

### Man page
TODO

Use `man nft-dns` to get the config help

## TODO
1. pcap capture (as option) to support true wildcard
2. MAN page
