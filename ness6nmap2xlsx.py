#!/usr/bin/env python3
#    Copyright (C) 2017 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import logging
import sys
import time
import xlsxwriter

from nessrest import ness6rest
from parsers import nessus
from parsers import nmap

# custom levels for the logging lib
RESULT = 21


# help required for:
# add findings breakdown
# add new worksheet 'Vulnerabilities' including 'Remediation'
# checking files extension
# forbidding '--list' and '-oX' arguments to be used together
# making 'folders' or 'scans' or list 'mandatory'
def parse_args():
    """ Parse and validate the command line
    """
    parser = argparse.ArgumentParser(
        description=(
            "Parse Nessus results into an Excel spreadsheet for quicker "
            "and easier reporting"
        )
    )

    # generic options
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
        dest="loglevel",
        help="enable debug output",
        required=False
    )

    parser.add_argument(
        "-oX",
        dest="output_file",
        help="output results in XLSX to the given filename",
        required=False,
        type=str
    )

    subparsers = parser.add_subparsers(
        dest="subcommand"
    )
    subparsers.required = True

    # Nessus subparser
    nessus_parser = subparsers.add_parser("nessus")

    nessus_exclusion_group = nessus_parser.add_mutually_exclusive_group(
        required=False
    )

    nessus_parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        help="Configuration file for custom vulnerabilities",
        type=argparse.FileType("r")
    )

    nessus_exclusion_group.add_argument(
        "-f",
        "--folders",
        dest="folders",
        help="folder(s) to process (support regular expressions)",
        nargs="+",
        type=str
    )

    nessus_parser.add_argument(
        "--host",
        default="localhost",
        dest="host",
        help="hostname (default value: localhost)",
        required=False,
        type=str
    )

    nessus_parser.add_argument(
        "-l",
        "--login",
        dest="login",
        help="login for Nessus authentication",
        required=True,
        type=str
    )

    nessus_parser.add_argument(
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

    nessus_parser.add_argument(
        "-p",
        "--password",
        dest="password",
        help="password for Nessus authentication",
        required=True,
        type=str
    )

    nessus_parser.add_argument(
        "--port",
        default="8834",
        dest="port",
        help="port (default value: 8834)",
        required=False,
        type=str
    )

    nessus_exclusion_group.add_argument(
        "-s",
        "--scans",
        dest="scans",
        help="scan(s) to process (support regular expressions)",
        nargs="+",
        type=str
    )

    # Nmap subparser
    nmap_parser = subparsers.add_parser("nmap")

    nmap_parser.add_argument(
        "-iX",
        dest="input_files",
        help="XML scan results files(s)",
        nargs="+",
        required=True,
        type=argparse.FileType("r")
    )

    return parser.parse_args()


# Help required for:
# adding column formula to convert 'severity' to 'text'
def write_worksheet(workbook, worksheet, freeze_panes_count,
                    table_headers, table_data):
    """ Create an Excel worksheet containing the 'table_headers' and 'table_data' dataset
    """
    if not table_data:
        logging.warning("'{}' has not been created - empty dataset".format(
            worksheet
        ))
        return
    else:
        worksheet = workbook.add_worksheet("{}".format(worksheet))

        column_count = 0
        row_count = 0
        table_column_count = column_count + len(table_headers) - 1
        table_row_count = row_count + len(table_data)

        logging.debug("{}".format(table_headers))

        for table_datum in table_data:
            logging.debug("{}".format(table_datum))

        worksheet.add_table(
            row_count,
            column_count,
            table_row_count,
            table_column_count,
            {
                "banded_rows": True,
                "columns": table_headers,
                "data": table_data,
                "first_column": True,
                "style": "Table Style Medium 1"
            }
        )

        # freeze the two first columns in the worksheet
        for i in range(freeze_panes_count):
            worksheet.freeze_panes(0, i + 1)



def parse_host_vulns(workbook, scanner, scans, config_file=None):
    table_data = []
    table_headers = [
        {"header": "Scan"},
        {"header": "Affected Host IP"},
        {"header": "Affected Port"},
        {"header": "Vulnerability"},
        {"header": "Severity Rating"}
    ]

    for scan in scans:
        host_vulns = nessus.get_host_vulns(scanner, scan)

        if config_file:
            host_vulns = nessus.post_process_vulns(
                config_file, host_vulns, type=0
            )

        for host_id, plugin_id in host_vulns.items():
            for plugin_id, values in plugin_id.items():
                for value in values:
                    table_data.append(
                        [
                            value["scan"],
                            value["host_ip"],
                            ";".join(value["plugin_output"]["ports"]),
                            value["plugin_name"],
                            value["severity"]
                        ]
                    )

    write_worksheet(workbook, "Hosts vs Vulnerabilties", 2,
                    table_headers, table_data)


def parse_vuln_hosts(workbook, document, scanner, scans, config_file=None):
    table_data = []
    table_headers = [
        {"header": "Scan"},
        {"header": "Vulnerability"},
        {"header": "IP Count"},
        {"header": "Affected Host IP"},
        {"header": "Port Count"},
        {"header": "Affected Port"},
        {"header": "Severity Rating"}
    ]

    for scan in scans:
        vuln_hosts = nessus.get_vuln_hosts(scanner, scan)

        if config_file:
            vuln_hosts = nessus.post_process_vulns(
                config_file, vuln_hosts, type=1
            )

        for value in vuln_hosts.values():
            # unify, sort and stringify
            table_data.append(
                [
                    ";".join(sorted(set(value["scan"]))),
                    value["plugin_name"],
                    len(value["host_ip"]),
                    ";".join(sorted(
                        set(value["host_ip"]),
                        key=lambda x: tuple(map(int, x.split('.')))
                    )),
                    len(set(value["plugin_output"]["ports"])),
                    ";".join(sorted(
                        set(value["plugin_output"]["ports"]),
                        key=lambda x: int(x.split("/")[0])
                    )),
                    value["severity"]
                ]
            )

    write_worksheet(workbook, "Vulnerabilities vs Hosts", 2,
                    table_headers, table_data)


def parse_vulns(workbook, scanner, scans, config_file=None):
    table_data = []
    table_headers = [
        {"header": "Scan"},
        {"header": "Vulnerability"},
        {"header": "IP Count"},
        {"header": "Affected Host IP"},
        {"header": "Port Count"},
        {"header": "Affected Port"},
        {"header": "Severity Rating"}
    ]

    for scan in scans:
        vuln_hosts = nessus.get_vuln_hosts(scanner, scan)

        if config_file:
            vuln_hosts = nessus.post_process_vulns(
                config_file, vuln_hosts, type=1
            )

        for value in vuln_hosts.values():
            # unify, sort and stringify
            table_data.append(
                [
                    ";".join(sorted(set(value["scan"]))),
                    value["plugin_name"],
                    len(value["host_ip"]),
                    ";".join(sorted(
                        set(value["host_ip"]),
                        key=lambda x: tuple(map(int, x.split('.')))
                    )),
                    len(set(value["plugin_output"]["ports"])),
                    ";".join(sorted(
                        set(value["plugin_output"]["ports"]),
                        key=lambda x: int(x.split("/")[0])
                    )),
                    value["severity"]
                ]
            )

    write_worksheet(workbook, "Vulnerabilities vs Hosts", 2,
                    table_headers, table_data)


def parse_nessus_host_os(workbook, scanner, scans):
    table_data = []
    table_headers = [
        {"header": "Scan"},
        {"header": "Host IP"},
        {"header": "Operating System"},
        {"header": "Confidence Level"},
        {"header": "Method"},
    ]

    for scan in scans:
        host_os = nessus.get_host_os(scanner, scan)

        for value in host_os.values():
            table_data.append(
                [
                    value["scan"],
                    value["host_ip"],
                    value["operating_system"],
                    value["confidence_level"],
                    value["method"]
                ]
            )

    write_worksheet(workbook, "Hosts vs OS", 2, table_headers, table_data)


def parse_nessus_os_hosts(workbook, scanner, scans):
    table_data = []
    table_headers = [
        {"header": "Scan"},
        {"header": "Operating System"},
        {"header": "Host IP Count"},
        {"header": "Host IP"},
        {"header": "Method"}
    ]

    for scan in scans:
        os_hosts = nessus.get_os_hosts(scanner, scan)

        for operating_system, value in sorted(os_hosts.items()):
            # unify, sort and stringify
            table_data.append(
                [
                    ";".join(sorted(set(value["scan"]))),
                    operating_system,
                    len(value["host_ip"]),
                    ";".join(sorted(
                        set(value["host_ip"]),
                        key=lambda x: tuple(map(int, x.split('.')))
                    )),
                    ";".join(sorted(set(value["method"])))
                ]
            )

    write_worksheet(workbook, "OS vs Hosts", 2, table_headers, table_data)


def parse_host_services(workbook, input_files):
    table_data = []
    table_headers = [
        {"header": "File"},
        {"header": "Host IP"},
        {"header": "Port"},
        {"header": "Protocol"},
        {"header": "Service"},
        {"header": "State"},
        {"header": "Banner"},
        {"header": "Reason"}
    ]

    for input_file in input_files:
        host_services = nmap.get_host_services(input_file)

        for host_ip, values in sorted(host_services.items()):
            for value in values:
                table_data.append(
                    [
                        value["file"],
                        host_ip,
                        value["port"],
                        value["protocol"],
                        value["service"],
                        value["state"],
                        value["banner"],
                        value["reason"]
                    ]
                )

    write_worksheet(workbook, "Hosts vs Services", 2,
                    table_headers, table_data)


def parse_nmap_host_os(workbook, input_files):
    table_data = []
    table_headers = [
        {"header": "File"},
        {"header": "Host IP"},
        {"header": "Operating System"},
        {"header": "Accuracy"}
    ]

    for input_file in input_files:
        host_os = nmap.get_host_os(input_file)

        for host_ip, value in sorted(host_os.items()):
            table_data.append(
                [
                    value["file"],
                    host_ip,
                    value["name"],
                    value["accuracy"]
                ]
            )

    write_worksheet(workbook, "Hosts vs OS", 2, table_headers, table_data)


def parse_nmap_os_hosts(workbook, input_files):
    table_data = []
    table_headers = [
        {"header": "File"},
        {"header": "Operating System"},
        {"header": "Host IP Count"},
        {"header": "Host IP"}
    ]

    for input_file in input_files:
        host_os = nmap.get_os_hosts(input_file)

        for operating_system, value in sorted(host_os.items()):
            # unify, sort and stringify
            table_data.append(
                [
                    ";".join(sorted(set(value["file"]))),
                    operating_system,
                    len(value["host_ip"]),
                    ";".join(sorted(
                        set(value["host_ip"]),
                        key=lambda x: tuple(map(int, x.split('.')))
                    ))
                ]
            )

    write_worksheet(workbook, "OS vs Hosts", 2, table_headers, table_data)


def main():
    try:
        args = parse_args()

        logging.addLevelName(RESULT, "RESULT")
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
        if args.subcommand == "nessus":
            if args.output_file and not args.list:
                output_file = "{}.xlsx".format(args.output_file)
            elif not args.output_file and not args.list:
                output_file = "nessus-results_{}".format(
                    time.strftime("%Y%m%d-%H%M%S")
                )
            else:
                output_file = "N/A"
        elif args.subcommand == "nmap":
            if args.output_file:
                output_file = "{}".format(args.output_file)
            else:
                output_file = "nmap-results_{}".format(
                    time.strftime("%Y%m%d-%H%M%S")
                )

        if args.subcommand == "nessus":
            # variables summary
            logging.info("Nessus login: {}".format(args.login))
            logging.info("Nessus password: {}".format(args.password))
            if args.folders:
                logging.info("Nessus folder(s): {}".format(
                    ";".join(sorted(args.folders))
                ))
            if args.scans:
                logging.info("Nessus scan(s): {}".format(";".join(
                    sorted(args.scans))
                ))
            logging.info("Nessus URL: https://{}:{}".format(
                args.host, args.port
            ))
            if args.config_file:
                logging.info(
                    "Configuration file for Nessus vulnerabilities: {}".format(
                        args.config_file.name
                    )
                )
            logging.info("XLSX results output_file: {}.xlsx".format(output_file))

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

                for result in results:
                    logging.log(RESULT, "{}".format(result["name"]))
            elif args.folders or args.scans:
                if args.folders:
                    scans = nessus.fetch_scans(scanner, args.folders)
                elif args.scans:
                    scans = nessus.get_scans(scanner, args.scans)

                if scans:
                    document = Document()
                    workbook = xlsxwriter.Workbook("{}.xlsx".format(output_file))

                    logging.log(
                        RESULT,
                        "generating 'Hosts vs Vulnerabilities' worksheet..."
                    )
                    parse_host_vulns(
                        workbook, scanner, scans, config_file=args.config_file
                    )

                    document.save("{}.docx".format(output_file))

                    logging.log(
                        RESULT,
                        "generating 'Vulnerabilities vs Hosts' worksheet..."
                    )
                    parse_vuln_hosts(
                        workbook, document, scanner, scans, config_file=args.config_file
                    )

                    logging.log(
                        RESULT,
                        "generating 'Hosts vs OS' worksheet..."
                    )
                    parse_nessus_host_os(workbook, scanner, scans)
                    logging.log(
                        RESULT,
                        "generating 'OS vs Hosts' worksheet..."
                    )
                    parse_nessus_os_hosts(workbook, scanner, scans)

                    workbook.close()

        elif args.subcommand == "nmap":
            # variables summary
            # help required to:
            # add regex support
            input_files = []
            for input_file in args.input_files:
                input_files.append(input_file.name)
            logging.info("Nmap XML results file(s): {}".format(
                ";".join(sorted(input_files))
            ))
            logging.info("XLSX results file: {}.xlsx".format(output_file))

            workbook = xlsxwriter.Workbook("{}.xlsx".format(output_file))
            logging.log(RESULT, "generating 'Hosts vs Services' worksheet...")
            parse_host_services(workbook, input_files)
            logging.log(RESULT, "generating 'Hosts vs OS' worksheet...")
            parse_nmap_host_os(workbook, input_files)
            logging.log(RESULT, "generating 'OS vs Hosts' worksheet...")
            parse_nmap_os_hosts(workbook, input_files)

            workbook.close()
    except KeyboardInterrupt:
        logging.exception("'CTRL+C' pressed, exiting...")


if __name__ == "__main__":
    main()
