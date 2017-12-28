![ness6nmap2xlsx](images/ness6nmap2xlsx.png)
# ness6nmap2xlsx

This script parses Nessus (via its API) and Nmap scans results into clear and complete Excel worksheets (XLSX) for quicker and easier reporting (useful when dealing with big scope).

The following worksheets are generated when parsing Nessus scans results:
* `Hosts vs Vulnerabilities`
* `Vulnerabilities vs Hosts`
* `Hosts vs OS`
* `OS vs Hosts`

The following worksheets are generated when parsing Nmap scans results:
* `Hosts vs Services`
* `Hosts vs OS`
* `OS vs Hosts`

Note: The `Hosts vs OS` and `OS vs Hosts` worksheets are **only** generated when Nmap scans contain OS information (using the `-O` option in Nmap).

## Installation
    $ git clone https://github.com/AresS31/ness6nmap2xlsx
    # python -m pip install -r ness6nmap_to_xlsx/requirements.txt

## Usage
### Generic usage
    $ python ness6nmap_to_xlsx.py [-h] [-d] [-oX OUTPUT_FILE] {nessus,nmap} ...
    
    positional arguments:
      {nessus,nmap}

    optional arguments:
      -h, --help       show this help message and exit
      -d, --debug      enable debug output
      -oX OUTPUT_FILE  output results in XLSX to the given filename

### Nessus usage
    $ python ness6nmap_to_xlsx.py nessus [-h] [-c CONFIG_FILE] [-f FOLDERS [FOLDERS ...]] [--host HOST] -l LOGIN [--list {folders,scans}] -p PASSWORD [--port PORT] [-s SCANS [SCANS ...]]

    optional arguments:
      -h, --help            show this help message and exit
      -c CONFIG_FILE, --config CONFIG_FILE
                            Configuration file for custom vulnerabilities
      -f FOLDERS [FOLDERS ...], --folders FOLDERS [FOLDERS ...]
                            folder(s) to process (support regular expressions)
      --host HOST           hostname (default value: localhost)
      -l LOGIN, --login LOGIN
                            login for Nessus authentication
      --list {folders,scans}
                            list folder(s) or scan(s) (support regular expressions)
      -p PASSWORD, --password PASSWORD
                            password for Nessus authentication
      --port PORT           port (default value: 8834)
      -s SCANS [SCANS ...], --scans SCANS [SCANS ...]
                            scan(s) to process (support regular expressions)

This script offers the option to `enable` the processing of specific Nessus plugins. It also offers the option to override their `name`, `description` and `severity` with custom values using a JSON file formatted as follows (the JSON key, in this case `34460`, corresponds to the `plugin id`):
```json
{
    "34460": {
        "description": "foo",
        "enable": true,
        "plugin_name": "bar",
        "severity": 666
    }
} 
```

### Nmap usage
    $ ness6nmap_to_xlsx.py nmap [-h] -iX INPUT_FILES [INPUT_FILES ...]

    optional arguments:
      -h, --help            show this help message and exit
      -iX INPUT_FILES [INPUT_FILES ...]
                            XML scan results files(s)

## Possible Improvements
* Adding new features.
* Adding new relevant worksheets.
* Source code optimisation.

## Licenses
### ness6nmap2xlsx
Copyright (C) 2017 Alexandre Teyar

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. 
