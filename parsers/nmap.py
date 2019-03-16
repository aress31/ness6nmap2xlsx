#!/usr/bin/env python3
#    Copyright (C) 2017 - 2019 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

from libnmap.parser import NmapParser
from .parser import Parser

import logging


class Nmap(Parser):
    def __init__(self, input_files, workbook):
        super(Parser, self).__init__()
        self._input_files = input_files
        self._workbook = workbook

    def draw_table(self, worksheet, table_headers, table_data):
        column_count = 0
        row_count = 0
        table_column_count = column_count + len(table_headers) - 1
        table_row_count = row_count + len(table_data)

        logging.debug("{}".format(table_headers))
        logging.debug("{}".format(table_data))

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

    def parse_host_services(self):
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

        for input_file in self._input_files:
            host_services = get_host_services(input_file.name)

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

        worksheet = self._workbook.add_worksheet("Host vs Services")
        self.draw_table(worksheet, table_headers, table_data)

    def parse_host_oss(self):
        table_data = []
        table_headers = [
            {"header": "File"},
            {"header": "Host IP"},
            {"header": "Operating System"},
            {"header": "Accuracy"}
        ]

        for input_file in self._input_files:
            host_os = get_host_oss(input_file.name)

            for host_ip, value in sorted(host_os.items()):
                table_data.append(
                    [
                        value["file"],
                        host_ip,
                        value["name"],
                        value["accuracy"]
                    ]
                )

        worksheet = self._workbook.add_worksheet("Host vs OSs")
        self.draw_table(worksheet, table_headers, table_data)

    def parse_os_hosts(self):
        table_data = []
        table_headers = [
            {"header": "File"},
            {"header": "Operating System"},
            {"header": "Host IP Count"},
            {"header": "Host IP"}
        ]

        for input_file in self._input_files:
            host_os = get_os_hosts(input_file.name)

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

        worksheet = self._workbook.add_worksheet("OS vs Hosts")
        self.draw_table(worksheet, table_headers, table_data)


def get_host_services(filepath):
    results = {}

    nmap = NmapParser.parse_fromfile(filepath)

    for host in nmap.hosts:
        if host.is_up():
            services = []

            for port in host.get_ports():
                service = host.get_service(port[0], port[1])

                services.append(
                    {
                        "banner":   service.banner,
                        "file":     filepath,
                        "port":     service.port,
                        "protocol": service.protocol,
                        "reason":   service.reason,
                        "service":  service.service,
                        "state":    service.state
                    }
                )

            results[host.address] = services

    return results


def get_host_oss(filepath):
    results = {}

    nmap = NmapParser.parse_fromfile(filepath)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            operating_systems = host.os_match_probabilities()

            # the first match has the highest accuracy
            if operating_systems:
                results[host.address] = {
                        "file":     filepath,
                        "name":     operating_systems[0].name,
                        "accuracy": operating_systems[0].accuracy
                }
        else:
            logging.debug(
                "OS fingerprinting has not been performed for {}".format(
                    host.address
                )
            )

    return results


def get_os_hosts(filepath):
    results = {}

    nmap = NmapParser.parse_fromfile(filepath)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            operating_systems = host.os_match_probabilities()

            if operating_systems:
                # the first match has the highest accuracy
                if operating_systems[0].name in list(results.keys()):
                    results[operating_systems[0].name]["file"].extend(
                        [filepath]
                    )
                    results[operating_systems[0].name]["host_ip"].extend(
                        [host.address]
                    )
                else:
                    results[operating_systems[0].name] = {
                            "file":     [filepath],
                            "host_ip":  [host.address],
                    }
        else:
            logging.debug(
                "OS fingerprinting has not been performed for {}".format(
                    host.address
                )
            )

    return results
