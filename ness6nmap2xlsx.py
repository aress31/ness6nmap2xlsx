#!/usr/bin/env python3
#    Copyright (C) 2017 - 2019 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

from nessrest import ness6rest
# from parsers.ness6rest import ness6rest
from parsers.nmap import Nmap

import argparse
import logging
import sys
import time
import xlsxwriter


# help required for:
# add findings breakdown
# add new worksheet 'Vulnerabilities' including 'Remediation'
# checking files extension
# forbidding '--list' and '-oX' arguments to be used together
# making 'folders' or 'scans' or list 'mandatory'
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Parse the output from various penetration testing tools into an"
            "Excel workbook"
        ))

    parser.add_argument(
        "-oX",
        "-output--xml",
        default="results_{}.xlsx".format(time.strftime("%Y%m%d-%H%M%S")),
        dest="output_file",
        help="output results to a specified <OUTPUT_FILE> in XLSX format",
        required=False,
        type=str
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
        dest="loglevel",
        help="enable debug output",
        required=False
    )

    subparsers = parser.add_subparsers(
        dest="subcommand"
    )
    subparsers.required = True

    # Nessus subparser
    ness6rest_parser = subparsers.add_parser("ness6rest")

    ness6rest_exclusion_group = ness6rest_parser.add_mutually_exclusive_group(
        required=False
    )

    ness6rest_parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        help="configuration file for custom vulnerabilities",
        type=argparse.FileType("r")
    )

    ness6rest_exclusion_group.add_argument(
        "-f",
        "--folders",
        dest="folders",
        help="folder(s) to process (support regular expressions)",
        nargs="+",
        type=str
    )

    ness6rest_parser.add_argument(
        "--host",
        default="localhost",
        dest="host",
        help="hostname (default value: localhost)",
        required=False,
        type=str
    )

    ness6rest_parser.add_argument(
        "-l",
        "--login",
        dest="login",
        help="login for Nessus authentication",
        required=True,
        type=str
    )

    ness6rest_parser.add_argument(
        "--list",
        choices=[
            "folders",
            "scans"
        ],
        dest="list",
        help="list folder(s) or scan(s) (support regular expressions)",
        required=False,
        type=str
    )

    ness6rest_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        help="password for Nessus authentication",
        required=True,
        type=str
    )

    ness6rest_parser.add_argument(
        "--port",
        default="8834",
        dest="port",
        help="port (default value: 8834)",
        required=False,
        type=str
    )

    ness6rest_exclusion_group.add_argument(
        "-s",
        "--scans",
        dest="scans",
        help="scan(s) to process (support regular expressions)",
        nargs="+",
        type=str
    )

    nmap_parser = subparsers.add_parser("nmap")

    nmap_parser.add_argument(
        "-iX",
        "--input-xml",
        dest="input_files",
        help="input from nmap file(s) in XML format",
        nargs="+",
        required=True,
        type=argparse.FileType("r")
    )

    return parser.parse_args()


def print_ness6rest_vars():
    logging.info("URL: https://{}:{}".format(args.host, args.port))
    logging.info("login: {}".format(args.login))
    logging.info("password: {}".format(args.password))

    if args.folders:
        logging.info("folder(s): {}".format(sorted(args.folders)))
    if args.scans:
        logging.info("scan(s): {}".format(sorted(args.scans)))
    if args.config_file:
        logging.info(
            "configuration file for custom vulnerabilities: {}".format(
                args.config_file.name
            ))

    logging.info("output file: {}".format(args.output_file))


def print_nmap_vars(input_files, output_file):
    logging.info("input file(s): {}".format(
        sorted([x.name for x in input_files])))
    logging.info("output file: {}".format(output_file))


def main():
    args = parse_args()

    logging.basicConfig(
        format="%(levelname)-8s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
        level=args.loglevel
    )
    # disable the logging for the 'urllib3' lib
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

    # help required to:
    # tidy-up this piece of code
    if args.subcommand == "ness6rest":
        print_ness6rest_vars()

        scanner = ness6rest.Scanner(
            insecure=True,
            login=args.login,
            password=args.password,
            url="https://{}:{}".format(args.host, args.port)
        )

        if args.list:
            if args.list == "folders":
                if args.folders:
                    results = nessus.get_folders(scanner, args.folders)
                else:
                    results = nessus.get_all_folders(scanner)
            elif args.list == "scans":
                if args.folders:
                    results = nessus.fetch_scans(scanner, args.folders)
                elif args.scans:
                    results = nessus.get_scans(scanner, args.scans)
                else:
                    results = nessus.get_all_scans(scanner)

            logging.info("{}".format(sorted(result["name"])))

        elif args.folders or args.scans:
            if args.folders:
                scans = nessus.fetch_scans(scanner, args.folders)
            elif args.scans:
                scans = nessus.get_scans(scanner, args.scans)

            if scans:
                workbook = xlsxwriter.Workbook("{}".format(args.output_file))

                logging.info("generating worksheet 'Host vs Vulnerabilities'...")
                parse_ness_host_vulns(workbook, scanner, scans, config_file=args.config_file)
                logging.info("generating 'Vulnerability vs Hosts' worksheet...")
                parse_ness_vuln_hosts(workbook, scanner, scans, config_file=args.config_file)
                logging.info("generating worksheet 'Host vs OSs'...")
                parse_ness_host_oss(workbook, scanner, scans)
                logging.info("generating worksheet 'OS vs Hosts'...")
                parse_ness_os_hosts(workbook, scanner, scans)

                workbook.close()

    elif args.subcommand == "nmap":
        print_nmap_vars(args.input_files, args.output_file)

        workbook = xlsxwriter.Workbook("{}".format(args.output_file))

        nmap = Nmap(args.input_files, workbook)

        logging.info("generating worksheet 'Host vs Services'...")
        nmap.parse_host_services()
        logging.info("generating worksheet 'Host vs OSs'...")
        nmap.parse_host_oss()
        logging.info("generating worksheet 'OS vs Hosts'...")
        nmap.parse_os_hosts()

        workbook.close()


if __name__ == "__main__":
    main()
