#!/usr/bin/env python3

import argparse
import configparser
import logging
import signal
import subprocess
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import dns.exception
import dns.flags
import dns.message
import dns.rdatatype
import dns.resolver
from pydantic import IPvAnyAddress

import entry

config = configparser.ConfigParser(interpolation=None)

values = []
stop_requested = False
nfqueue_handler = None

logging.basicConfig(format="%(asctime)s %(levelname)s:%(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def is_dry_run() -> bool:
    return args.dry_run or config["GLOBAL"].getboolean("dry_run", fallback=False)


def run_command(cmd: str) -> str:
    logger.debug(f"Command to run: {cmd}")

    if is_dry_run():
        logger.debug(f"Dry-run detected, command not executed: {cmd}")
        return ""

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)

        if result.stdout:
            logger.debug(f"Command stdout: {result.stdout.rstrip()}")

        if result.stderr:
            logger.debug(f"Command stderr: {result.stderr.rstrip()}")

        return result.stdout

    except subprocess.CalledProcessError as error:
        logger.error(f"Command failed with return code {error.returncode}: {cmd}")

        if error.stdout:
            logger.error(f"Command stdout: {error.stdout.rstrip()}")

        if error.stderr:
            logger.error(f"Command stderr: {error.stderr.rstrip()}")

        return ""

    except FileNotFoundError:
        logger.error("The nft command was not found. Install nftables or use --dry-run to prevent nftables commands from being executed.")
        sys.exit(1)


class NFQueueHandler:
    """NFQUEUE handler used to capture DNS responses. Only one instance is allowed."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is not None:
            raise RuntimeError("Only one NFQueueHandler instance is allowed")

        instance = super().__new__(cls)
        cls._instance = instance
        return instance

    def __init__(self, queue_num: int = 0, values: list | None = None):
        if hasattr(self, "_initialized"):
            return

        self.queue_num = queue_num
        self.values = values if values is not None else []
        self.nfqueue = None
        self._thread = None
        self._stop_event = threading.Event()
        self._initialized = True

    def setup_nftables(self) -> None:
        """Create nftables base chains and redirect DNS UDP packets to NFQUEUE."""

        self.cleanup_nftables()

        run_command("nft 'add chain ip filter nft_dns_output { type filter hook output priority -10; policy accept; }'")
        run_command(f"nft 'add rule ip filter nft_dns_output udp dport 53 queue num {self.queue_num}'")
        logger.info(f"Added nftables nft_dns_output chain for NFQUEUE {self.queue_num} with priority -10")

        run_command("nft 'add chain ip filter nft_dns_input { type filter hook input priority -10; policy accept; }'")
        run_command(f"nft 'add rule ip filter nft_dns_input udp sport 53 queue num {self.queue_num}'")
        logger.info(f"Added nftables nft_dns_input chain for NFQUEUE {self.queue_num} with priority -10")

    def cleanup_nftables(self) -> None:
        """Remove nftables chains used by NFQUEUE."""

        run_command("nft delete chain ip filter nft_dns_output 2>/dev/null || true")
        run_command("nft delete chain ip filter nft_dns_input 2>/dev/null || true")

        logger.info("Removed nftables rules for NFQUEUE")

    @staticmethod
    def extract_dns_payload(raw_data: bytes) -> bytes | None:
        """Extract the DNS payload from an IPv4 or IPv6 UDP packet."""

        if not raw_data:
            logger.debug("Received an empty NFQUEUE packet")
            return None

        ip_version = raw_data[0] >> 4

        if ip_version == 4:
            if len(raw_data) < 20:
                logger.debug(f"Received truncated IPv4 packet with length {len(raw_data)}")
                return None

            ip_header_len = (raw_data[0] & 0x0F) * 4

            if ip_header_len < 20:
                logger.debug(f"Invalid IPv4 header length: {ip_header_len}")
                return None

            if len(raw_data) < ip_header_len + 8:
                logger.debug(f"IPv4 packet is too short to contain a UDP header: packet length={len(raw_data)}, IP header length={ip_header_len}")
                return None

            ip_protocol = raw_data[9]

            if ip_protocol != 17:
                logger.debug(f"Ignoring non-UDP IPv4 packet with protocol number {ip_protocol}")
                return None

        elif ip_version == 6:
            if len(raw_data) < 48:
                logger.debug(f"Received truncated IPv6 packet with length {len(raw_data)}")
                return None

            ip_header_len = 40
            next_header = raw_data[6]

            if next_header != 17:
                logger.debug(f"Ignoring IPv6 packet with next-header value {next_header}. IPv6 extension headers are not supported by this parser.")
                return None

        else:
            logger.debug(f"Unsupported IP version: {ip_version}")
            return None

        dns_offset = ip_header_len + 8

        if len(raw_data) < dns_offset + 12:
            logger.debug(f"Packet is too short to contain a complete DNS header: packet length={len(raw_data)}, DNS offset={dns_offset}")
            return None

        return raw_data[dns_offset:]

    def get_matching_entries(self, domain: str) -> list:
        """Return every configured entry matching the DNS query domain."""

        normalized_domain = domain.rstrip(".").lower()
        return [configured_entry for configured_entry in self.values if configured_entry.fqdn.rstrip(".").lower() == normalized_domain]

    @staticmethod
    def get_record_addresses(message: dns.message.Message, target_rdtype: dns.rdatatype.RdataType) -> list[str]:
        """Extract unique A or AAAA addresses from the DNS answer section."""

        addresses = []

        for rrset in message.answer:
            if rrset.rdtype != target_rdtype:
                continue

            for record in rrset:
                if hasattr(record, "address"):
                    addresses.append(record.address)

        return sorted(set(addresses))

    def process_packet(self, pkt) -> None:
        """Process a DNS packet received through NFQUEUE."""

        try:
            raw_data = pkt.get_payload()
            logger.debug(f"Packet received, payload length={len(raw_data)}")

            dns_data = self.extract_dns_payload(raw_data)

            if dns_data is None:
                return

            message = dns.message.from_wire(dns_data)

            logger.debug(
                f"DNS packet parsed: class={type(message).__name__}, flags=0x{message.flags:04x}, response={bool(message.flags & dns.flags.QR)}, questions={len(message.question)}, answers={len(message.answer)}"
            )

            if not message.flags & dns.flags.QR:
                logger.debug("Ignoring DNS query because the QR response flag is not set")
                return

            if not message.question:
                logger.debug("Ignoring DNS response without a question section")
                return

            domain = message.question[0].name.to_text().rstrip(".")
            matching_entries = self.get_matching_entries(domain)

            if not matching_entries:
                logger.debug(f"Ignoring DNS response for unconfigured domain: {domain}")
                return

            for configured_entry in matching_entries:
                target_rdtype = dns.rdatatype.A if configured_entry.typeof == 4 else dns.rdatatype.AAAA
                target_rdtype_name = dns.rdatatype.to_text(target_rdtype)
                ip_list = self.get_record_addresses(message, target_rdtype)

                if not ip_list:
                    logger.debug(f"No {target_rdtype_name} addresses found in the DNS response for {domain}")
                    continue

                elements = ", ".join(ip_list)

                logger.info(
                    f"NFQUEUE DNS response: {domain} -> {ip_list}, record type={target_rdtype_name}, nftables set={configured_entry.family}/{configured_entry.table}/{configured_entry.set_name}"
                )

                run_command(f"nft -exist add element {configured_entry.family} {configured_entry.table} {configured_entry.set_name} {{ {elements} }}")

        except (ValueError, AttributeError, IndexError, UnicodeDecodeError, dns.exception.FormError) as error:
            logger.debug(f"Invalid or unsupported DNS packet: {error}")

        except Exception as error:
            logger.exception(f"Unexpected error while processing an NFQUEUE packet: {error}")

        finally:
            try:
                pkt.accept()
            except Exception as error:
                logger.error(f"Unable to accept NFQUEUE packet: {error}")

    def _loop(self) -> None:
        """Run the NFQUEUE event loop in a dedicated thread."""

        from netfilterqueue import NetfilterQueue

        try:
            self.setup_nftables()

            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(self.queue_num, self.process_packet)

            logger.info(f"Starting NFQUEUE {self.queue_num} capture")

            self.nfqueue.run()

        except OSError as error:
            logger.error(f"NFQUEUE operating system error: {error}")

        except Exception as error:
            logger.exception(f"Unexpected NFQUEUE error: {error}")

        finally:
            if self.nfqueue:
                try:
                    self.nfqueue.unbind()
                except Exception:
                    pass

                self.nfqueue = None

            self.cleanup_nftables()
            logger.info(f"NFQUEUE {self.queue_num} capture loop stopped")

    def start(self) -> None:
        """Start NFQUEUE capture in a daemon thread."""

        if self._thread and self._thread.is_alive():
            logger.warning(f"NFQUEUE {self.queue_num} capture is already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name=f"nfqueue-{self.queue_num}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop NFQUEUE capture and wait briefly for the thread."""

        self._stop_event.set()

        if self.nfqueue:
            try:
                self.nfqueue.unbind()
            except OSError as error:
                logger.debug(f"NFQUEUE was already unbound: {error}")
            except Exception as error:
                logger.error(f"Unable to unbind NFQUEUE {self.queue_num}: {error}")

        if self._thread and self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2)

        self.nfqueue = None
        NFQueueHandler._instance = None

        logger.info(f"NFQUEUE {self.queue_num} stopped")


def configure_logging() -> None:
    verbose = args.verbose or config["GLOBAL"].getboolean("verbose", fallback=False)
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s %(levelname)-8s: %(message)s - <%(filename)s:%(funcName)s:L%(lineno)d>" if verbose else "%(asctime)s %(levelname)s:%(message)s"

    logging.basicConfig(level=log_level, format=log_format, force=True)


def read_config() -> None:
    global nfqueue_handler

    if not args.config_file or not Path(args.config_file).is_file():
        logger.error(f"Config file not found: {args.config_file}")
        sys.exit(1)

    config_file = Path(args.config_file)

    logger.info(f"Reading config file: {config_file.absolute()}")
    config.read(config_file)

    if not config.has_section("GLOBAL"):
        logger.error("The configuration file does not contain a GLOBAL section")
        sys.exit(1)

    if config.has_option("GLOBAL", "include_config_dir"):
        config_dir = Path(config["GLOBAL"]["include_config_dir"])

        if not config_dir.is_dir():
            logger.error(f"Config directory is not a directory and will be ignored: {config_dir}")
        else:
            logger.info(f"Reading configuration files with the .conf extension from: {config_dir.absolute()}")

            config_files = sorted(config_dir.glob("*.conf"))

            for included_config_file in config_files:
                logger.info(f"Reading included configuration file: {included_config_file}")

            config.read(config_files)

    configure_logging()

    logger.info("# Parsing the configuration")

    for section in config.sections():
        if section == "GLOBAL":
            continue

        if not config[section].getboolean("enable", fallback=False):
            logger.debug(f"Ignoring disabled configuration section: {section}")
            continue

        if not config[section].get("domains", fallback="").strip():
            logger.error(f"The configuration section {section} does not contain any domain")
            sys.exit(1)

        if not config[section].get("set_name", fallback="").strip():
            logger.error(f"The configuration section {section} does not contain a set_name")
            sys.exit(1)

        family = config[section].get("family", fallback="")

        if family not in {"ip", "ip6", "inet"}:
            logger.error(f"Invalid nftables family in section {section}: {family}. Allowed values are ip, ip6 and inet.")
            sys.exit(1)

        table = config[section].get("table", fallback="filter")
        set_name = config[section]["set_name"]

        nft_set_definition = run_command(f"nft list set {family} {table} {set_name}")

        if not is_dry_run() and not nft_set_definition:
            logger.error(f"The nftables set '{family} {table} {set_name}' was not found")
            sys.exit(1)

        if is_dry_run():
            address_type = 4
            logger.info(f"Dry-run mode forces set {set_name} to IPv4 because the nftables set definition cannot be inspected")
        elif "type ipv4_addr" in nft_set_definition:
            address_type = 4
            logger.debug(f"Set {set_name} is correctly defined with type ipv4_addr")
        elif "type ipv6_addr" in nft_set_definition:
            address_type = 6
            logger.debug(f"Set {set_name} is correctly defined with type ipv6_addr")
        else:
            logger.error(f'The nftables set "{family} {table} {set_name}" does not use type ipv4_addr or ipv6_addr. Only these address types are supported.')
            sys.exit(1)

        for fqdn in config[section]["domains"].split(","):
            normalized_fqdn = fqdn.strip().rstrip(".")

            if not normalized_fqdn:
                continue

            model_entry = entry.ModelEntry(
                set_name=set_name,
                family=family,
                table=table,
                typeof=address_type,
                fqdn=normalized_fqdn,
                ip_list=None,
                ttl=None,
                next_update=None,
            )

            values.append(model_entry)
            logger.debug(f"Loaded configuration entry: {model_entry}")

    if not values:
        logger.error("No enabled or valid entries were configured, exiting")
        sys.exit(1)

    if config["GLOBAL"].get("mode", fallback="poll").lower() == "capture":
        nfqueue_handler = NFQueueHandler(queue_num=0, values=values)
        nfqueue_handler.start()

    logger.info("# End of parsing")


def update_dns() -> None:
    if config.has_option("GLOBAL", "custom_resolver"):
        resolver = dns.resolver.make_resolver_at(config["GLOBAL"]["custom_resolver"])
    else:
        resolver = dns.resolver.Resolver()

    max_ttl = config["GLOBAL"].getint("max_ttl", fallback=86400)
    min_ttl = config["GLOBAL"].getint("min_ttl", fallback=300)

    for configured_entry in values:
        if configured_entry.next_update and configured_entry.next_update > datetime.now():
            continue

        old_ip_list = configured_entry.ip_list

        logger.debug(f"DNS update for {configured_entry} is in progress")

        try:
            record_type = "AAAA" if configured_entry.typeof == 6 else "A"
            answer = resolver.resolve(configured_entry.fqdn, rdtype=record_type)

            configured_entry.ip_list = sorted([record.address for record in answer.rrset])
            configured_entry.ttl = answer.rrset.ttl

            adjusted_ttl = max(min(configured_entry.ttl, max_ttl), min_ttl)
            configured_entry.next_update = datetime.now() + timedelta(seconds=adjusted_ttl + 1)

            logger.info(f"DNS resolution: {configured_entry.fqdn} -> {configured_entry.ip_list}, type={record_type}, DNS TTL={configured_entry.ttl}, effective TTL={adjusted_ttl}")

        except dns.resolver.NXDOMAIN:
            configured_entry.next_update = datetime.now() + timedelta(seconds=min_ttl)
            logger.warning(f'Domain "{configured_entry.fqdn}" does not exist according to the configured resolver. A new attempt will be made in {min_ttl} seconds.')
            continue

        except dns.resolver.NoAnswer:
            configured_entry.next_update = datetime.now() + timedelta(seconds=min_ttl)
            logger.warning(f'No usable DNS answer was returned for "{configured_entry.fqdn}". A new attempt will be made in {min_ttl} seconds.')
            continue

        except dns.resolver.NoNameservers:
            configured_entry.next_update = datetime.now() + timedelta(seconds=min_ttl)
            logger.warning(f'No DNS nameserver was able to answer for "{configured_entry.fqdn}". A new attempt will be made in {min_ttl} seconds.')
            continue

        except dns.exception.Timeout:
            configured_entry.next_update = datetime.now() + timedelta(seconds=min_ttl)
            logger.warning(f'DNS resolution timed out for "{configured_entry.fqdn}". A new attempt will be made in {min_ttl} seconds.')
            continue

        logger.debug(f"Updated entry: {configured_entry}")

        if old_ip_list != configured_entry.ip_list:
            logger.info(f"Updating IPv{configured_entry.typeof} addresses for {configured_entry.fqdn}: old={old_ip_list}, new={configured_entry.ip_list}")
            apply_config_entry(configured_entry, old_ip_list=old_ip_list)
        else:
            logger.debug(f"No IPv{configured_entry.typeof} address change detected for {configured_entry.fqdn}")


def get_next_run_timer() -> datetime:
    valid_next_update_values = [configured_entry.next_update for configured_entry in values if configured_entry.next_update is not None]

    if not valid_next_update_values:
        min_ttl = config["GLOBAL"].getint("min_ttl", fallback=300)
        return datetime.now() + timedelta(seconds=min_ttl)

    return min(valid_next_update_values)


def apply_config_entry(one_entry: entry.ModelEntry, old_ip_list: list[IPvAnyAddress] | None) -> None:
    if old_ip_list:
        old_elements = ", ".join(str(ip_address) for ip_address in old_ip_list)
        run_command(f"nft delete element {one_entry.family} {one_entry.table} {one_entry.set_name} {{ {old_elements} }}")

    if one_entry.ip_list:
        new_elements = ", ".join(str(ip_address) for ip_address in one_entry.ip_list)
        run_command(f"nft -exist add element {one_entry.family} {one_entry.table} {one_entry.set_name} {{ {new_elements} }}")


def remove_config_entries() -> None:
    logger.info("Cleaning all managed nftables sets")

    managed_sets = {(configured_entry.family, configured_entry.table, configured_entry.set_name) for configured_entry in values}

    for family, table, set_name in managed_sets:
        run_command(f"nft flush set {family} {table} {set_name}")


def shutdown() -> None:
    global nfqueue_handler

    if nfqueue_handler:
        nfqueue_handler.stop()
        nfqueue_handler = None

    remove_config_entries()


def run_loop() -> None:
    is_capture_mode = config["GLOBAL"].get("mode", fallback="poll").lower() == "capture"

    try:
        while not stop_requested:
            if not is_capture_mode:
                update_dns()

            next_run = get_next_run_timer()
            sleep_seconds = max(1, int((next_run - datetime.now()).total_seconds()) + 1)

            logger.info(f"Sleeping for {sleep_seconds}s")

            for _ in range(sleep_seconds):
                if stop_requested:
                    break

                sleep(1)

    finally:
        shutdown()


def handler_stop(signum, frame) -> None:
    global stop_requested

    signal_name = signal.Signals(signum).name
    logger.warning(f"{signal_name}({signum}) signal received, shutdown requested")

    stop_requested = True


def main() -> None:
    read_config()
    run_loop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS plugin for nftables")
    parser.add_argument("-c", "--config", type=str, dest="config_file", default="/etc/nft-dns.conf", help="Configuration file")
    parser.add_argument("-t", "--dry-run", dest="dry_run", action="store_true", help="Test mode. No nftables command will be executed.")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler_stop)
    signal.signal(signal.SIGTERM, handler_stop)

    main()
