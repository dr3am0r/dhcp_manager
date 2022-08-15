#!/usr/bin/env python3

"""
The script helps to simplify some operations to DHCP server.

Usage:
  dhcp_manager.py log find <ip> [options]
  dhcp_manager.py config show_free_ip <config_network> [options]

Options:
  -h --help                                           Show this screen
  <ip>                                                IP address or network. For example: 10.0.10.5 or 10.0.10.5/24
  <config_network>                                    Network. For example: 10.0.10.5/24.
  --dhcp-log-files=<dhcp_log_files>                   DHCP log files, separated by comas or folder [default: /var/log/dhcpd/]
  --dhcp-config-file=<dhcp_config_file>               DHCP config file. [default: /etc/dhcp/dhcpd.conf]
"""


import os
import re
import sys
import gzip
import logging
import ipaddress
from pprint import pprint
from docopt import docopt
from prettytable import PrettyTable


# Preparing Arguments
arguments = docopt(__doc__)

# Init logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DHCP_LOG_HOST_ACK_REGEX = r"^.+DHCPACK.+\s(?P<ip>(\d{1,3}\.){1,3}\d{1,3}).+$"
DHCP_CONF_HOST_REGEX = r"^\s+host\snic_(?P<host_name>\S+)\s{\shardware\sethernet\s(?P<mac>(?:[0-9a-fA-F]:?){12});\sfixed-address\s(?P<ip>(\d{1,3}\.){1,3}\d{1,3});\s}$"

ARGUMENT_TYPE_REGEX_MAP = {
    'ip': r'^(\d{1,3}\.){3}\d{1,3}$',
    'network': r'^(\d{1,3}\.){3}\d{1,3}(/([1-9]|[12][0-9]|3[0-2]))?$',
}


def find_ips_in_file(ip_set: set, log_files_paths: list) -> dict:
    """
    Look for ips in provided files.
    :param ip_set: 
    :param log_files_paths: 
    :return: 
    """

    ip_log = dict()

    for file_path in natural_sort(log_files_paths):
        if not ip_set-set(ip_log):
            break

        logger.info("Scanning %s...", file_path)

        if file_path.endswith("gz"):
            try:
                with gzip.open(file_path, 'rt') as gz_log_file:
                    for line in gz_log_file:
                        res = re.match(DHCP_LOG_HOST_ACK_REGEX, line)
                        if res:
                            if not ip_log.get(res.groupdict().get('ip')):
                                ip_log[res.groupdict().get('ip')] = line.strip()
            except (OSError, UnicodeDecodeError) as error:
                logger.error("Can't open/read file %s. Continue...", file_path)
                continue

        else:
            try:
                with open(file_path, 'r') as log_file:
                    for line in log_file:
                        res = re.match(DHCP_LOG_HOST_ACK_REGEX, line)
                        if res:
                            if not ip_log.get(res.groupdict().get('ip')):
                                ip_log[res.groupdict().get('ip')] = line.strip()
            except OSError as error:
                logger.error("Can't open/read file %s", file_path)
                sys.exit(1)

    return {ip: ip_log.get(ip) for ip in ip_set}


def natural_sort(_list):
    """
    Natural sorting
    :param _list:
    :return:
    """
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]

    return sorted(_list, key=alphanum_key)


def check_arg_type(arg: str) -> str:
    """
    Check arguments type (ip or network)
    :param arg:
    :return:
    """
    for arg_type in ARGUMENT_TYPE_REGEX_MAP:
        res = re.match(ARGUMENT_TYPE_REGEX_MAP[arg_type], arg)
        if res:
            return arg_type
    return ""


def compose_list_of_files_to_check(pathes_list: list) -> set:
    """
    Compose list of files.
    In case if user passed a directory, all files from the directory go to the list.
    :param pathes_list:
    :return:
    """

    files = set()

    for path in pathes_list:
        if os.path.isfile(path):
            files.add(path)
        if os.path.isdir(path):
            for dir_path in os.listdir(path):
                full_path = '{}/{}'.format(re.sub("/$", "", path), dir_path)
                if os.path.isfile(full_path):
                    files.add(full_path)

    return files


def pretty_table(data: dict):
    """
    Prin pretty table
    :param data:
    :return:
    """

    table = PrettyTable(['IP', 'Last_log_record(DHCPACK)'])
    table.align['Last_log_record(DHCPACK)'] = 'l'

    for key in natural_sort(data.keys()):
        table.add_row([key, data[key]])

    return table


def is_network_in_conf(network_address: str,
                       network_mask: str,
                       path_to_conf_file: str) -> bool:
    """
    Scan conf file for network
    :param network_address:
    :param network_mask:
    :param path_to_conf_file:
    :return:
    """

    regex_line = r"^\s+subnet\s" + network_address + r"\snetmask\s" + network_mask + r"\s{.+$"

    try:
        with open(path_to_conf_file, 'r') as conf_file:
            for line in conf_file.readlines():
                res = re.match(regex_line, line)
                if res:
                    return True
            return False
    except OSError as error:
        logger.error("Can't open/read file %s. Error: %s", path_to_conf_file, error)
        sys.exit(1)


def network_to_conf_ip_diff(ip_set: set, path_to_conf_file: str) -> set:
    """
    Compare provided network addresses list with conf file addresses list.
    :param ip_set:
    :param path_to_conf_file:
    :return:
    """

    prefix = os.path.commonprefix(list(ip_set))
    regex_line = r"^\s+host\snic_(?P<host_name>\S+)\s{\shardware\sethernet\s(?P<mac>(?:[0-9a-fA-F]:?){12});\sfixed-address\s(?P<ip>" + prefix  + r".+);\s}$"

    try:
        with open(path_to_conf_file, 'r') as conf_file:
            for line in conf_file.readlines():
                res = re.match(regex_line, line)
                if res:
                    host_info = res.groupdict()
                    if host_info.get('ip') in ip_set:
                        ip_set.remove(host_info.get('ip'))
            return ip_set
    except OSError as error:
        logger.error("Can't open/read file %s. Error: %s", path_to_conf_file, error)
        sys.exit(1)



if __name__ == "__main__":

    if arguments.get('log') and arguments.get('find'):
        ips = set()

        arg_type = check_arg_type(arguments["<ip>"])

        if not arg_type:
            logger.error('Wrong ip address: %s', arguments["<ip>"])
            sys.exit(1)

        files_to_check = compose_list_of_files_to_check([raw_path.strip() for raw_path in arguments["--dhcp-log-files"].split(",")])

        if not files_to_check:
            logger.error('Wrong argument: %s', arguments["--dhcp-log-files"])
            sys.exit(1)

        if arg_type == 'network':
            try:
                ips = set([str(ip) for ip in ipaddress.IPv4Network(arguments["<ip>"])][1:-1])
            except ValueError as error:
                logger.error('Wrong network address: %s', arguments["<ip>"])
                sys.exit(1)
        else:
            ips.add(arguments["<ip>"])

        print(pretty_table(find_ips_in_file(ips, files_to_check)))

    elif arguments.get('config') and arguments.get('show_free_ip'):
        ip_info = ipaddress.IPv4Network(arguments.get('<config_network>'))

        if not is_network_in_conf(str(ip_info.network_address), str(ip_info.netmask), arguments.get('--dhcp-config-file')):
            logger.error('The network %s is not present in config %s',
                         arguments.get('<config_network>'),
                         arguments.get('--dhcp-config-file'))
            sys.exit(1)

        ip_set = set([str(ip) for ip in ip_info][1:-1])

        pprint(natural_sort(network_to_conf_ip_diff(ip_set, arguments.get('--dhcp-config-file'))))

