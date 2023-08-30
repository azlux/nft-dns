# nft-dns
Make the nftables resolve fqdn on-the-fly !

Back on iptables, fqdn was available into rules, but was resolved at start only. This have never been improved.

This project try to resolve this limitation.
NFT-DNS start with it own configuration file, will resolve the DNS and keep the TTL, then will populate the NFT [named SET](https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets_specifications).

The script will make DNS query each time the TTL reach zero, this way, your system will resolve an entries already accepted (or refused) by your firewall, even if the domain have changed its IP.
The script is both IPv4 and IPv6 compatible.

-----
## Quick Start Guide
1. [Features](#features)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Help](#help)
5. [TODO](#todo)

## Features
- FQDN support
   - *wildcard only if there are a Wildcard DNS record 
- Configuration via simple config files into a folder (allow multiple config file)
  - Config with .ini format 
- Packaged with apt
  - upgrade with APT 
  - Service packaged with systemd
## Requirements

To use this program you need:
- At least **Debian 12** (I code with Pydantic Model (> 5.0))
- A NFTABLES with **already prepared** [named SET](https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets_specifications).
  - If the set doesn't exist, the program will stop itself.
  - For testing, you can have sets you don't call into a rule
- If your OS have systemd, the package will prepare the systemd service too.

## Installation
### With APT (recommended)
```bash
    echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ bookworm main" | sudo tee /etc/apt/sources.list.d/azlux.list
    sudo wget -O /usr/share/keyrings/azlux-archive-keyring.gpg  https://azlux.fr/repo.gpg
    sudo apt update
    sudo apt install nft-dns
    # Here you change the config
    # Then you can start and enable the service
    sudo systemctl enable nft-dns
    sudo systemctl start nft-dns
```

### Manually
You can just clone the project, the start script is `nft-dns.py`. But you will have not auto-update.
You will need to create your one init service.
You also need to install the dependencies with pip3 or debian packages.

## Configuration
You can write your own config file with [the manual](./MANUAL.md) (available also with `man nft-dns`)

Read the manual for explanation of configs entries.

You can also copy the `/etc/nft-dns.conf` file as a example, and uncomment values (`cp /etc/nft-dns.conf /etc/nft-dns.d/cutsom.conf`).

## Help
### Command line
Use `nft-dns.py --help` to get the usage help.

### Man page
Use `man nft-dns` to get the config help

## TODO
1. pcap capture (as option) to support true wildcard
