#!/usr/bin/env python3
import argparse
import configparser
import logging
import re
import signal
import subprocess
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import dns.resolver
from pydantic import IPvAnyAddress

import entry

# Global singleton for NFQUEUE handler
nfqueue_handler = None

config = configparser.ConfigParser(interpolation=None)

values = []
stop_requested = False
logging.basicConfig(format="%(asctime)s %(levelname)s:%(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class NFQueueHandler:
    """NFQUEUE handler for capturing DNS responses. Singleton - only one instance allowed."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is not None:
            raise RuntimeError("Only one NFQueueHandler instance allowed")
        return super().__new__(cls)

    def __init__(self, queue_num: int = 1, values: list | None = None):
        if hasattr(self, "_initialized"):
            return  # Prevent re-initialization
        self.queue_num = queue_num
        self.values = values if values is not None else []  # shared reference to entries
        self.nfqueue = None
        self._thread = None
        self._stop_event = threading.Event()
        self._initialized = True

    def setup_nftables(self) -> None:
        """Setup nftables rules to redirect DNS to NFQUEUE."""
        self.cleanup_nftables()  # Clean up any leftover chains from previous runs

        # Create dedicated chain for DNS OUTPUT with HIGH priority (negative = evaluated first)
        # This ensures our DNS rules are evaluated BEFORE any existing OUTPUT rules
        run_command("nft add chain ip filter nft_dns_output { type filter hook output priority -10; policy accept; }")
        run_command(f"nft add rule ip filter nft_dns_output udp dport 53 queue num {self.queue_num}")
        logger.info(f"Added nftables nft_dns_output chain for NFQUEUE {self.queue_num} (priority -10)")

        # Create dedicated chain for DNS INPUT with HIGH priority
        run_command("nft add chain ip filter nft_dns_input { type filter hook input priority -10; policy accept; }")
        run_command(f"nft add rule ip filter nft_dns_input udp sport 53 queue num {self.queue_num}")
        logger.info(f"Added nftables nft_dns_input chain for NFQUEUE {self.queue_num} (priority -10)")

    def cleanup_nftables(self) -> None:
        """Remove nftables rules for NFQUEUE."""
        # Delete our dedicated chains (they have their own hooks, no need to delete rules from OUTPUT/INPUT)
        run_command("nft delete chain ip filter nft_dns_output 2>/dev/null || true")
        run_command("nft delete chain ip filter nft_dns_input 2>/dev/null || true")
        logger.info("Removed nftables rules for NFQUEUE")

    def process_packet(self, pkt):
        """Callback for NetfilterQueue to process DNS packets."""
        import dns.message

        logger.debug(f"Packet received, payload len={len(pkt.get_payload())}")

        try:
            # Get raw packet payload (IP layer payload = UDP header + DNS data)
            raw_data = pkt.get_payload()

            # Extract IP header length based on version
            ip_version = raw_data[0] >> 4
            if ip_version == 4:
                # IPv4: IHL field (lower 4 bits) gives header length in 4-byte words
                ip_header_len = (raw_data[0] & 0x0F) * 4
            elif ip_version == 6:
                # IPv6: fixed 40-byte header, no options
                ip_header_len = 40
            else:
                logger.warning(f"Unknown IP version: {ip_version}")
                pkt.accept()
                return

            # Skip IP header, then UDP header (8 bytes)
            dns_data = raw_data[ip_header_len + 8 :]

            # Parse DNS message from wire format
            msg = dns.message.from_wire(dns_data)

            # DNS header is 12 bytes: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
            # QR bit is bit 15 of flags (0x80 of flags high byte)
            dns_flags_bytes = dns_data[2:4].hex() if len(dns_data) >= 4 else "N/A"
            logger.debug(f"DNS packet type: {type(msg).__name__}, hasattr response: {hasattr(msg, 'response')}, dns header bytes: {dns_flags_bytes}")

            if hasattr(msg, "response") and msg.response:
                if not self.values:
                    pkt.accept()
                    return
                template = self.values[0]

                # Determine which record type to extract based on set type
                # typeof 4 = ipv4_addr (A records), typeof 6 = ipv6_addr (AAAA records)
                target_rdtype = 1 if template.typeof == 4 else 28  # 1=A, 28=AAAA

                ip_list = []
                domain = None

                # Extract query name from question section
                if msg.question:
                    q = msg.question[0]
                    domain = q.name.to_text().rstrip(".")

                # Extract answer records
                if msg.answer:
                    for rr in msg.answer:
                        if rr.rdtype == target_rdtype:
                            for item in rr:
                                ip_list.append(str(item))

                if ip_list and domain:
                    logger.info(f"NFQUEUE DNS response: {domain} -> {ip_list}")
                    run_command(f"nft add element {template.family} {template.table} {template.set_name} {{{', '.join(ip_list)}}}")

            pkt.accept()
        except (ValueError, AttributeError, IndexError, UnicodeDecodeError, dns.exception.FormError) as e:
            # Paquet DNS invalide ou structure inattendue - on accepte quand même
            logger.debug(f"Invalid DNS packet: {e}")
            pkt.accept()

    def _loop(self):
        """Main loop running in thread."""
        from netfilterqueue import NetfilterQueue

        self.setup_nftables()

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(self.queue_num, self.process_packet)
        logger.info(f"Starting NFQUEUE {self.queue_num} capture")
        try:
            self.nfqueue.run()
        except OSError as e:
            logger.error(f"NFQUEUE error: {e}")
        finally:
            self.cleanup_nftables()

    def start(self):
        """Start NFQUEUE capture in a daemon thread."""
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop NFQUEUE capture."""
        self._stop_event.set()
        if self.nfqueue:
            self.nfqueue.unbind()
            self.nfqueue = None
        logger.info("NFQUEUE stopped")


def read_config():
    if args.config_file and Path(args.config_file).is_file():
        logger.info(f"Reading config file : {Path(args.config_file).absolute()}")
        config.read(Path(args.config_file))
    else:
        logger.error("Config file not found, Exiting...")
        sys.exit(1)
    if config.has_option("GLOBAL", "include_config_dir"):
        config_dir = Path(config["GLOBAL"]["include_config_dir"])
        if not config_dir.is_dir():
            logger.error("Config directory is not a directory, Ignoring...")
        else:
            logger.info("Only config file with prefix .conf is read")
            logger.info(f"Reading config directory : {config_dir.absolute()}")
            list_config = list(config_dir.glob("*.conf"))
            [logger.info(f"   {i}") for i in list_config]
            config.read(list_config)
    logger.info("# Parsing the configuration")
    if args.verbose or (config.has_option("GLOBAL", "verbose") and config["GLOBAL"].getboolean("verbose")):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.basicConfig(format="%(asctime)s %(levelname)-8s: %(message)s - <%(filename)s:%(funcName)s:L%(lineno)d>")
    else:
        logging.basicConfig(format="%(asctime)s %(levelname)s:%(message)s")

    # Start NFQUEUE capture if configured
    if config.has_option("GLOBAL", "mode") and config["GLOBAL"]["mode"] == "capture":
        global nfqueue_handler
        nfqueue_handler = NFQueueHandler(queue_num=0, values=values)  # 0 = auto-assign by kernel
        nfqueue_handler.start()

    for section in config.sections():
        if section != "GLOBAL" and config[section].getboolean("enable", fallback=False):
            for fqdn in config[section]["domains"].split(","):
                if config[section].get("family", "") in ["ip", "ip6", "inet"]:
                    family = config[section]["family"]
                else:
                    logger.error(f"Config error, family of {fqdn} is not : ip, ip6 or inet")
                    sys.exit(1)
                table = config[section].get("table", fallback="filter")
                res = run_command(f"nft list set {family} {table} {config[section]['set_name']}")
                if not res:
                    logger.error(f"The named set '{family} {table} {config[section]['set_name']}' hasn't been found")
                    sys.exit(1)
                typeof = 4
                if not (args.dry_run or (config.has_option("GLOBAL", "verbose") and config["GLOBAL"].getboolean("dry_run", fallback=False))):
                    if "type ipv4_addr" in res:
                        typeof = 4
                        logger.debug(f"set {config[section]['set_name']} well defined in ipv4_addr family")
                    elif "type ipv6_addr" in res:
                        typeof = 6
                        logger.debug(f"set {config[section]['set_name']} well defined in ipv6_addr family")
                    else:
                        logger.error(f'Type of the {config[section]["set_name"]} set not defined to "ipv4_addr" or "ipv6_addr" into the nftables set. Only theses type are allowed.')
                        sys.exit(1)
                else:
                    logger.info('The dry_run option forces typeof to "ipv4" since nft list set command will not be executed to detect the type')
                result = entry.ModelEntry(
                    set_name=config[section]["set_name"],
                    family=family,
                    table=table,
                    typeof=typeof,
                    fqdn=fqdn.strip(),
                    ip_list=None,
                    ttl=None,
                    next_update=None,
                )
                values.append(result)
                logger.debug(result)
    if len(values) == 0:
        logger.error("No entries configurated, I've nothing to do, Exiting in tears...")
        sys.exit(1)

    logger.info("# End of Parsing")


def update_dns() -> None:
    global values
    if config.has_option("GLOBAL", "custom_resolver"):
        res = dns.resolver.make_resolver_at(config["GLOBAL"]["custom_resolver"])
    else:
        res = dns.resolver.Resolver()

    max_ttl = config["GLOBAL"].getint("max_ttl", fallback=86400)
    min_ttl = config["GLOBAL"].getint("min_ttl", fallback=300)

    for i in values:
        if i.next_update and i.next_update > datetime.now():
            continue
        old_ip_list = i.ip_list
        logger.debug(f"Update for {i} in progress...")
        try:
            rd_type = "A"
            if i.typeof == 6:
                rd_type = "AAAA"
            answer = res.resolve(i.fqdn, rdtype=rd_type)
            i.ip_list = [items.address for items in answer.rrset]
            i.ip_list.sort()
            i.ttl = answer.rrset.ttl
            logger.info(f"DNS resolution: {i.fqdn} -> {i.ip_list} (TTL: {i.ttl})")
            # calcul next update for this entry
            ttl_adjusted = max(min(i.ttl, max_ttl) + 1, min_ttl)  # Value between min_ttl and max_ttl
            i.next_update = datetime.now() + timedelta(seconds=ttl_adjusted + 1)  # +2 To be sure the cache is really cleared
        except dns.resolver.NXDOMAIN:
            logger.warning(f'Impossible to get the fqdn of "{i.fqdn}" from the "{i.set_name}" set, disabling.')
            continue
        logger.debug(i)
        if old_ip_list != i.ip_list:
            logger.info(f"Updating the IPv{i.typeof} for {i.fqdn} with {i.ip_list}")
            apply_config_entry(i, old_ip_list=old_ip_list)
        else:
            logger.debug(f"Nothing have change for the IPv{i.typeof} for {i.fqdn}")
    values = [i for i in values if i.ip_list is not None and i.next_update is not None]


def get_next_run_timer() -> datetime:
    valid_values = [date.next_update for date in values if date.next_update is not None]
    if not valid_values:
        min_ttl = config["GLOBAL"].getint("min_ttl", fallback=300)
        return datetime.now() + timedelta(seconds=min_ttl)
    return min(valid_values)


def apply_config_entry(one_entry: entry.ModelEntry, old_ip_list: list[IPvAnyAddress] | None) -> None:
    if old_ip_list:
        run_command(f"nft delete element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{', '.join([str(ip) for ip in old_ip_list])}}}")

    if one_entry.ip_list:
        run_command(f"nft add element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{', '.join([str(ip) for ip in one_entry.ip_list])}}}")


def remove_config_entries():
    logger.info("Cleaning all managed named sets")
    managed_sets = {(i.family, i.table, i.set_name) for i in values}
    for family, table, set_name in managed_sets:
        # run_command(f"nft delete element {i.family} {i.table} {i.set_name} {{{', '.join([str(ip) for ip in i.ip_list])}}}")
        run_command(f"nft flush set {family} {table} {set_name}")


def run_command(cmd: str):
    logger.debug(f"Command to run : {cmd}")
    if not (args.dry_run or (config.has_option("GLOBAL", "verbose") and config["GLOBAL"].getboolean("dry_run", fallback=False))):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logger.error(e.stdout)
            logger.error(e.stderr)
            return ""
        except FileNotFoundError:
            logger.error("The nft command isn't found, Run with --dry-run to avoid nftable change tries")
            sys.exit(1)
    else:
        logger.debug("Dry-run detected, logging only, the previous command isn't executed")
        return ""


def run_loop():
    global nfqueue_handler
    is_capture_mode = config.has_option("GLOBAL", "mode") and config["GLOBAL"]["mode"] == "capture"
    while True:
        # In capture mode, only NFQUEUE populates the set - skip DNS polling
        if not is_capture_mode:
            update_dns()
        next_run = get_next_run_timer()
        sleep_second = (next_run - datetime.now()).seconds + 1  # +1 because the sleep is rounded to the second
        logger.info(f"Sleeping for {sleep_second}s")

        for i in range(sleep_second):
            sleep(1)
            if stop_requested:
                if nfqueue_handler:
                    nfqueue_handler.cleanup_nftables()  # Delete chains and rules before stopping
                    nfqueue_handler.stop()
                    nfqueue_handler = None
                remove_config_entries()
                break
        if stop_requested:
            break


def main():
    read_config()
    run_loop()


def handler_stop(signum, frame):
    logger.warning(f"{signal.Signals(signum).name}({signum}) signal received. Exiting")
    global stop_requested, nfqueue_handler
    stop_requested = True
    if nfqueue_handler:
        nfqueue_handler.cleanup_nftables()  # Delete chains and rules before stopping
        nfqueue_handler.stop()
        nfqueue_handler = None
    remove_config_entries()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS plugin for NFTables")
    parser.add_argument("-c", "--config", type=str, dest="config_file", default="/etc/nft-dns.conf", help="Config file")
    parser.add_argument("-t", "--dry-run", dest="dry_run", action="store_true", help="Test Mode, dry-run will not run any nftables command, usefull with verbose mode")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose logging mode, will log all actions")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler_stop)  # For simple CTRL+C
    signal.signal(signal.SIGTERM, handler_stop)  # For Systemd stop
    main()
