#!/usr/bin/env python3
#    Copyright (C) 2017 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

import logging

from libnmap.parser import NmapParser


def get_host_services(input_file):
    results = {}

    nmap = NmapParser.parse_fromfile(input_file)

    for host in nmap.hosts:
        if host.is_up():
            services = []

            for port in host.get_ports():
                service = host.get_service(port[0], port[1])

                services.append(
                    {
                        "banner": service.banner,
                        "file": input_file,
                        "port": service.port,
                        "protocol": service.protocol,
                        "reason": service.reason,
                        "service": service.service,
                        "state": service.state
                    }
                )

            results[host.address] = services

    return results


def get_host_os(input_file):
    results = {}

    nmap = NmapParser.parse_fromfile(input_file)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            operating_systems = host.os_match_probabilities()

            # the first match has the highest accuracy
            if operating_systems:
                results[host_ip] = {
                        "file": input_file,
                        "host_ip": host.address,
                        "name": operating_systems[0].name,
                        "accuracy": operating_systems[0].accuracy
                }
        else:
            logging.debug(
                "OS fingerprinting has not been performed for {}".format(
                    host.address
                )
            )

    return results


def get_os_hosts(input_file):
    results = {}

    nmap = NmapParser.parse_fromfile(input_file)

    for host in nmap.hosts:
        if host.is_up() and host.os_fingerprinted:
            operating_systems = host.os_match_probabilities()

            if operating_systems:
                # the first match has the highest accuracy
                if operating_systems[0].name in list(results.keys()):
                    results[operating_systems[0].name]["file"].extend(
                        [input_file]
                    )
                    results[operating_systems[0].name]["host_ip"].extend(
                        [host.address]
                    )
                else:
                    results[operating_systems[0].name] = {
                            "file": [input_file],
                            "host_ip": [host.address],
                    }
        else:
            logging.debug(
                "OS fingerprinting has not been performed for {}".format(
                    host.address
                )
            )

    return results
