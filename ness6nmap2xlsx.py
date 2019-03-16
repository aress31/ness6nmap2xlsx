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

# TODO:
# * add support for Nessus v7+

from parsers.nmap import Nmap
from parsers.testssl import Testssl

import argparse
import logging
import sys
import time


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Parse the output from various penetration testing tools into an "
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
        help="increase verbosity level",
        required=False
    )

    subparsers = parser.add_subparsers(
        dest="subcommand"
    )
    subparsers.required = True

    nmap_subparser = subparsers.add_parser("nmap")

    nmap_subparser.add_argument(
        "-iX",
        "--input-xml",
        dest="input_files",
        help="input from nmap file(s) in XML format",
        nargs="+",
        required=True,
        type=argparse.FileType("r")
    )

    testssl_subparser = subparsers.add_parser("testssl")

    testssl_subparser.add_argument(
        "-iJ",
        "--input-json",
        dest="input_files",
        help="input from testssl file(s) in JSON format",
        nargs='+',
        required=True,
        type=argparse.FileType('r')
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        format="%(levelname)-8s %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
        level=args.loglevel
    )

    if args.subcommand == "nmap":
        nmap = Nmap(args.input_files, args.output_file)
        nmap.print_vars()
        nmap.parse()

    elif args.subcommand == "testssl":
        testssl = Testssl(args.input_files, args.output_file)
        testssl.print_vars()
        testssl.parse()


if __name__ == "__main__":
    main()
