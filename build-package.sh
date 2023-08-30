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
pandoc --standalone --to man "$STARTDIR/MANUAL.md" -o "$STARTDIR/nft-dns.1"
install -D -g 0 -o 0 -m 0644 "$STARTDIR/nft-dns.1" "$DESTDIR/usr/local/man/man1/nft-dns.1"

cat >"$STARTDIR/changelog"<<EOL
package ($new) stable; urgency=medium
  Please check the source repo for the full changelog
  You can found the link at https://packages.azlux.fr/
-- Azlux <github@azlux.fr>  $(date -R)
EOL
install -Dm 644 "$STARTDIR/changelog" "$DESTDIR/usr/share/doc/nft-dns/changelog.Debian"
gzip "$DESTDIR/usr/share/doc/nft-dns/changelog.Debian"


# Build .deb
mkdir "$DESTDIR/DEBIAN" "$OUTDIR"
cp "$STARTDIR/debian/"* "$DESTDIR/DEBIAN/"

# Set version
sed -i "s/VERSION-TO-REPLACE/$new/" "$DESTDIR/DEBIAN/control"

dpkg-deb --build "$DESTDIR" "$OUTDIR"
