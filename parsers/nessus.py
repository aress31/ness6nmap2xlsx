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

import copy
import json
import logging
import re
import sys

from collections import defaultdict


def get_all_folders(scanner):
    results = []

    scanner.action(
        action="folders",
        method="GET"
    )

    for folder in scanner.res["folders"]:
        results.append(folder)

    return sorted(results, key=lambda x: x["name"])


def get_folders(scanner, p_folders):
    folders = get_all_folders(scanner)
    results = []

    for p_folder in p_folders:
        exist = False
        pattern = re.compile(p_folder)

        for folder in folders:
            if pattern.match(folder["name"]):
                exist = True
                results.append(folder)

        if not exist:
            logging.warning("{} folder do not exist".format(p_folder))

    return sorted(results, key=lambda x: x["name"])


def get_all_scans(scanner):
    results = []

    scanner.action(
        action="scans",
        method="GET"
    )

    for scan in scanner.res["scans"]:
        results.append(scan)

    return sorted(results, key=lambda x: x["name"])


def get_scans(scanner, p_scans):
    results = []
    scans = get_all_scans(scanner)

    for p_scan in p_scans:
        exist = False
        pattern = re.compile(p_scan)

        for scan in scans:
            if pattern.match(scan["name"]):
                exist = True
                results.append(scan)

        if not exist:
            logging.warning("{} scan do not exist".format(p_scan))

    return sorted(results, key=lambda x: x["name"])


def fetch_scans(scanner, p_folders):
    folders = get_folders(scanner, p_folders)

    results = []

    for folder in folders:
        scanner.action(
            action="scans?folder_id={}".format(folder["id"]),
            method="GET"
        )

        if scanner.res["scans"]:
            for scan in scanner.res["scans"]:
                results.append(scan)

    return sorted(results, key=lambda x: x["name"])


def get_host_vulns(scanner, scan):
    results = defaultdict(dict)

    scanner.action(
        action="scans/{}".format(scan["id"]),
        method="GET"
    )

    for host in scanner.res["hosts"]:
        scanner.action(
            action="scans/{}/hosts/{}".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )
        host_ip = scanner.res["info"]["host-ip"]

        for data in scanner.res["vulnerabilities"]:
            plugin_output = get_plugin_output(scanner, scan, data)
            results[host["host_id"]][data["plugin_id"]] = []

            for port in plugin_output["port"]:
                results[host["host_id"]][data["plugin_id"]].append({
                    "CVE": plugin_output["CVE"],
                    "host_ip": host_ip,
                    "hostname": data["hostname"],
                    "plugin_name": data["plugin_name"],
                    "port": port,
                    "scan": scan["name"],
                    "severity": data["severity"]
                })

    return results


# improve by returning dict[plugin_id][host_id] = details instead
def get_vuln_hosts(scanner, scan):
    results = {}

    scanner.action(
        action="scans/{}".format(scan["id"]),
        method="GET"
    )

    for host in scanner.res["hosts"]:
        scanner.action(
            action="scans/{}/hosts/{}".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )
        host_ip = scanner.res["info"]["host-ip"]

        for data in scanner.res["vulnerabilities"]:
            plugin_output = get_plugin_output(scanner, scan, data)

            if data["plugin_id"] in list(results.keys()):
                results[data["plugin_id"]]["host_id"].extend(
                    [data["host_id"]]
                )
                results[data["plugin_id"]]["host_ip"].extend(
                    [host_ip]
                )
                results[data["plugin_id"]]["hostname"].extend(
                    [data["hostname"]]
                )
                results[data["plugin_id"]]["port"].extend(
                    plugin_output["port"]
                )
                results[data["plugin_id"]]["scan"].extend(
                    [scan["name"]]
                )
            else:
                results[data["plugin_id"]] = {
                    "CVE": plugin_output["CVE"],
                    "host_id": [host["host_id"]],
                    "host_ip": [host_ip],
                    "hostname": [data["hostname"]],
                    "plugin_name": data["plugin_name"],
                    "port": plugin_output["port"],
                    "scan": [scan["name"]],
                    "severity": data["severity"]
                }

    return results


def get_plugin_output(scanner, scan, data):
    ports = []
    results = {}

    scanner.action(
        action="scans/{}/hosts/{}/plugins/{}".format(
            scan["id"],
            data["host_id"],
            data["plugin_id"]
        ),
        method="GET"
    )

    for output in scanner.res["outputs"]:
        for key in output["ports"].keys():
            formatted_port = "{}/{}".format(
                key.split("/")[0], key.split("/")[1].upper()
            ).replace(" ", "")
            ports.append(formatted_port)

    # a more elegant method than using a try-catch block?
    try:
        CVEs = []

        # plugin_description also contains the 'CVSS' information
        plugin = scanner.res["info"]["plugindescription"]
        plugin_ref = plugin["pluginattributes"]["ref_information"]["ref"]

        for entry in plugin_ref:
            # follow the schema below to add more reference sources
            if entry["name"].upper() == "CVE":
                CVEs.extend(entry["values"]["value"])
            else:
                continue
                # logging.warning("unparsed reference: {} {}".format(
                #     entry["name"].upper(), entry["values"]["value"]
                # ))

    except KeyError as ex:
        pass
        # logging.warning("no reference available for: plugin {}".format(
        #     data["plugin_id"]
        # ))

    results = {
        "port": ports,
        "CVE": CVEs
    }

    return results


def post_process_vulns(config_file, data, type=None):
    # reset the file pointer
    config_file.seek(0)

    try:
        config = json.load(config_file)
        logging.debug("JSON configuration file")
        logging.debug(json.dumps(config, indent=4, sort_keys=True))
    except json.decoder.JSONDecodeError as ex:
        logging.exception("{}".format(ex))
        sys.exit(1)

    # convert 'plugin_id' to int for easier use in later code
    config = {int(k): v for k, v in config.items()}

    # type == 0: host_vulns
    # type == 1: vuln_hosts
    if type == 0:
        # create a copy of the dict and work on the copy rather than the
        # original to avoid 'RuntimeError'
        for host_id, plugin_id in copy.deepcopy(data).items():
            for plugin_id, values in plugin_id.items():
                if plugin_id in list(config.keys()):
                    for i, value in enumerate(values):
                            if not config[plugin_id]["enable"]:
                                logging.debug(
                                    "removing vulnerabilty id {}".format(
                                        plugin_id
                                    )
                                )
                                del data[host_id][plugin_id]
                                break
                            else:
                                logging.debug(
                                    "editing vulnerabilty id {}".format(
                                        plugin_id
                                    )
                                )
                                data[host_id][plugin_id][i]["plugin_name"] = config[plugin_id]["plugin_name"]
                                data[host_id][plugin_id][i]["severity"] = config[plugin_id]["severity"]
                else:
                    continue
    elif type == 1:
        # create a copy of the dict and work on the copy rather than the
        # original to avoid 'RuntimeError'
        for plugin_id in copy.deepcopy(data).keys():
                if plugin_id in list(config.keys()):
                    if not config[plugin_id]["enable"]:
                        logging.debug("removing vulnerabilty id {}".format(
                            plugin_id
                        ))
                        del data[plugin_id]
                        continue
                    else:
                        logging.debug("editing vulnerabilty id {}".format(
                            plugin_id
                        ))
                        data[plugin_id]["plugin_name"] = config[plugin_id]["plugin_name"]
                        data[plugin_id]["severity"] = config[plugin_id]["severity"]
                else:
                    continue

    return data


def get_host_os(scanner, scan):
    results = {}

    scanner.action(
        action="scans/{}".format(scan["id"]),
        method="GET"
    )

    for host in scanner.res["hosts"]:
        # plugin '11936' corresponds to 'OS Identification'
        scanner.action(
            action="scans/{}/hosts/{}".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )
        host_ip = scanner.res["info"]["host-ip"]

        scanner.action(
            action="scans/{}/hosts/{}/plugins/11936".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )

        if scanner.res["outputs"]:
            # usually just one output per host per vulnerabilty, this
            # needs to be confirmed though
            for output in scanner.res["outputs"]:
                operating_system_match = re.search(
                    "Remote operating system : (.+)",
                    output["plugin_output"]
                )
                confidence_level_match = re.search(
                    "Confidence level : (\d{,2})",
                    output["plugin_output"]
                )
                method_match = re.search(
                    "Method : (.+)",
                    output["plugin_output"]
                )

                if operating_system_match:
                    operating_system = operating_system_match.group(1)
                if confidence_level_match:
                    confidence_level = confidence_level_match.group(1)
                if method_match:
                    method = method_match.group(1)

                results[host["host_id"]] = {
                    "confidence_level": int(confidence_level),
                    "host_ip": host_ip,
                    "method": method,
                    "operating_system": operating_system,
                    "scan": scan["name"]
                }

    return results


def get_os_hosts(scanner, scan):
    results = {}

    scanner.action(
        action="scans/{}".format(scan["id"]),
        method="GET"
    )

    for host in scanner.res["hosts"]:
        # plugin '11936' corresponds to 'OS Identification'
        scanner.action(
            action="scans/{}/hosts/{}".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )
        host_ip = scanner.res["info"]["host-ip"]

        scanner.action(
            action="scans/{}/hosts/{}/plugins/11936".format(
                scan["id"],
                host["host_id"]
            ),
            method="GET"
        )
        operating_systems = []

        if scanner.res["outputs"]:
            # usually just one output per host per vulnerabilty, this
            # needs to be confirmed though
            for output in scanner.res["outputs"]:
                operating_system_match = re.search(
                    "Remote operating system : (.+)",
                    output["plugin_output"]
                )
                method_match = re.search(
                    "Method : (.+)",
                    output["plugin_output"]
                )

                if operating_system_match:
                    operating_system = operating_system_match.group(1)
                if method_match:
                    method = method_match.group(1)

                if operating_system in list(results.keys()):
                    results[operating_system]["host_id"].extend(
                        [host["host_id"]]
                    )
                    results[operating_system]["host_ip"].extend(
                        [host_ip]
                    )
                    results[operating_system]["method"].extend(
                        [method]
                    )
                    results[operating_system]["scan"].extend(
                        [scan["name"]]
                    )
                else:
                    results[operating_system] = {
                        "host_id": [host["host_id"]],
                        "host_ip": [host_ip],
                        "method": [method],
                        "operating_system": operating_system,
                        "scan": [scan["name"]]
                    }

    return results
