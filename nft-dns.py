#!/usr/bin/env python3
from datetime import datetime, timedelta
import signal
from pathlib import Path
import configparser
from time import sleep
from typing import List

import argparse
import dns.resolver
import logging

import subprocess
from pydantic import IPvAnyAddress

import entry

config = configparser.ConfigParser(interpolation=None)

values = []
stop = False
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s')
logging.getLogger().setLevel(logging.INFO)


def read_config():
    if args.config_file and Path(args.config_file).is_file():
        logging.info(f'Reading config file : {Path(args.config_file).absolute()}')
        config.read(Path(args.config_file))
    else:
        logging.error('Config file not found, Exiting...')
        exit(1)
    if config.has_option('GLOBAL', 'include_config_dir'):
        config_dir = Path(config['GLOBAL']['include_config_dir'])
        if not config_dir.is_dir():
            logging.error(f"Config directory is not a directory, Ignoring...")
        else:
            logging.info('Only config file with prefix .conf is read')
            logging.info(f"Reading config directory : {config_dir.absolute()}")
            list_config = list(config_dir.glob("*.conf"))
            [logging.info(f"   {i}") for i in list_config]
            config.read(list_config)
    logging.info("# Parsing the configuration")
    if args.verbose or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('verbose')):
        logging.getLogger().setLevel(logging.DEBUG)

    global values
    for section in config.sections():
        if section != 'GLOBAL' and config[section].getboolean('enable', fallback=False):
            for fqdn in config[section]["domains"].split(','):
                if config[section]["family"] in ['ip', 'ip6', 'inet']:
                    family = config[section]["family"]
                else:
                    print(f"Erreur de config, family of {fqdn} not : ip, ip6 or inet")
                    exit(1)
                table = config[section].get('table', fallback='filter')
                res = run_command(f"nft list set {family} {table} {config[section]['set_name']}")
                typeof = 4
                if not (args.dry_run or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('dry_run', fallback=False))):
                    if "type ipv4_addr" in res:
                        typeof = 4
                        logging.debug(f"set {config[section]['set_name']} well defined in ipv4_addr family")
                    elif "type ipv6_addr" in res:
                        typeof = 6
                        logging.debug(f"set {config[section]['set_name']} well defined in ipv6_addr family")
                    else:
                        logging.error(f"Type of the {config[section]['set_name']} set not defined to \"ipv4_addr\" or \"ipv6_addr\" into the nftables set. Only theses type are allowed.")
                        exit(1)
                else:
                    logging.info('The dry_run option force the typeof to "ipv4" since not command are executed to check that')
                result = entry.ModelEntry(
                    set_name=config[section]["set_name"],
                    family=family,
                    table=table,
                    typeof=typeof,
                    fqdn=fqdn.strip(),
                    ip_list=None,
                    ttl=None,
                    next_update=None
                )
                values.append(result)
                logging.debug(result)
    if len(values) == 0:
        logging.error("No entries configurated, I've nothing to do, Exiting in tears...")
        exit(1)

    logging.info("# End of Parsing")


def update_dns() -> None:
    global values
    if config.has_option('GLOBAL', 'custom_resolver'):
        res = dns.resolver.make_resolver_at(config['GLOBAL']['custom_resolver'])
    else:
        res = dns.resolver.Resolver()
    max_ttl = config['GLOBAL'].getint('max_ttl', fallback=86400)
    min_ttl = config['GLOBAL'].getint('min_ttl', fallback=300)

    for i in values:
        if i.next_update and i.next_update > datetime.now():
            continue
        old_ip_list = i.ip_list
        logging.debug(f"Update for {i} in progress...")
        try:
            rd_type = "A"
            if i.typeof == 6:
                rd_type = "AAAA"
            answer = res.resolve(i.fqdn, rdtype=rd_type)
            i.ip_list = [items.address for items in answer.rrset]
            i.ip_list.sort()
            i.ttl = answer.rrset.ttl
            # Calcul next update for this entry
            ttl_adjusted = max(min(i.ttl, max_ttl) + 1, min_ttl)  # Value between min_ttl and max_ttl
            i.next_update = datetime.now() + timedelta(seconds=ttl_adjusted + 1)  # +2 To be sure the cache is really cleared
        except dns.resolver.NXDOMAIN:
            logging.warning(f"Impossible to get the fqdn of \"{i.fqdn}\" from the \"{i.set_name}\" set, disabling.")
            continue
        logging.debug(i)
        if old_ip_list != i.ip_list:
            logging.info(f"Updating the IPv{i.typeof} for {i.fqdn} with {i.ip_list}")
            apply_config_entry(i, old_ip_list=old_ip_list)
        else:
            logging.debug(f"Nothing have change for the IPv{i.typeof} for {i.fqdn}")
    values = [i for i in values if i.ip_list is not None]


def get_next_run_timer() -> datetime:
    return min([date.next_update for date in values])


def apply_config_entry(one_entry: entry.ModelEntry, old_ip_list: List[IPvAnyAddress] | None) -> None:
    if old_ip_list:
        run_command(f"nft delete element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{', '.join([str(ip) for ip in old_ip_list])}}}")

    if one_entry.ip_list:
        run_command(f"nft add element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{', '.join([str(ip) for ip in one_entry.ip_list])}}}")


def remove_config_entries():
    logging.info("Cleaning all entries")
    for i in values:
        run_command(f"nft delete element {i.family} {i.table} {i.set_name} {{{', '.join([str(ip) for ip in i.ip_list])}}}")


def run_command(cmd: str) -> str:
    logging.debug(f"Command to run : {cmd}")
    if not (args.dry_run or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('dry_run', fallback=False))):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logging.error(e.stdout)
            logging.error(e.stderr)
        except FileNotFoundError:
            logging.error("The nft command isn't found, Run with --dry-run to avoid nftable change tries")
            exit(1)
    else:
        logging.debug("Dry-run detected, logging only, the previous command isn't executed")


def run_loop():
    while True:
        update_dns()
        next_run = get_next_run_timer()
        sleep_second = (next_run - datetime.now()).seconds + 1  # +1 because the sleep is rounded to the second
        logging.info(f"Sleeping for {sleep_second}s")

        for i in range(sleep_second):
            sleep(1)
            if stop:
                remove_config_entries()
                break
        if stop:
            break


def main():
    read_config()
    run_loop()


def handler(signum, frame):
    logging.warning(f"{signal.Signals(signum).name}({signum}) signal received. Exiting")
    global stop
    stop = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS plugin for NFTables')
    parser.add_argument('-c', '--config', type=str, dest='config_file', default='/etc/nft-dns.conf', help='Config file')
    parser.add_argument('-t', '--dry-run', dest='dry_run', action="store_true", help="Test Mode, dry-run will not run any nftables command, usefull with verbose mode")
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help="Verbose logging mode, will log all actions")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler)  # For simple CTRL+C
    signal.signal(signal.SIGTERM, handler)  # For Systemd stop
    main()
