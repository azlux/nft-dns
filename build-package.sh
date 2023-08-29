#!/usr/bin/env bash

# Exit the script if any of the commands fail
set -e
set -u
set -o pipefail

# Set working directory to the location of this script
cd "$(dirname "${BASH_SOURCE[0]}")"

STARTDIR="$(pwd)"
DESTDIR="$STARTDIR/pkg"
OUTDIR="$STARTDIR/deb"
# get version
repo="azlux/nft-dns"
api=$(curl --silent "https://api.github.com/repos/$repo/releases/latest")
new=$(echo $api | grep -Po '"tag_name": "\K.*?(?=")')


# Remove potential leftovers from a previous build
rm -rf "$DESTDIR" "$OUTDIR"

## nft-dns
# Create directory
install -Dm 644 "$STARTDIR/nft-dns.service" "$DESTDIR/etc/systemd/system/nft-dns.service"
install -Dm 755 "$STARTDIR/nft-dns.py" "$DESTDIR/opt/nft-dns/nft-dns.py"
install -Dm 755 "$STARTDIR/entry.py" "$DESTDIR/opt/nft-dns/entry.py"
install -Dm 644 "$STARTDIR/nft-dns.conf" "$DESTDIR/etc/nft-dns.conf"
install -Dm 644 "$STARTDIR/nft-dns.d/.placeholder" "$DESTDIR/etc/nft-dns.d/.placeholder"

# Build .deb
mkdir "$DESTDIR/DEBIAN" "$OUTDIR"
cp "$STARTDIR/debian/"* "$DESTDIR/DEBIAN/"

# Set version
sed -i "s/VERSION-TO-REPLACE/$new/" "$DESTDIR/DEBIAN/control"

dpkg-deb --build "$DESTDIR" "$OUTDIR"
