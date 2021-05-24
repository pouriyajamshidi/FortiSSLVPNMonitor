# Fortigate SSL VPN

Python script that is written to display your connected SSL VPN users in an systematized manner.

## Features

* Query multiple firewalls (specified in yaml file)
* Helps you find users who are possibly sharing their account credentials
* Be aware of your IP assignments and address pool depletion
* Possibly find SSL VPN daemon issues of FortiOS
* Cross-platform. Runs on Windows, Linux and Mac OS.

## Requirements

Netmiko is needed to run this script. You can install it using below command.

```bash
pip3 install netmiko
```

## Usage

Download all the files in this repository and place them in the same directory.

Populate the `firewalls.yaml` according to your environment:

* name: Firewall name
* mgmt_ip: management IP address
* port: SSH port
* vdom: Vdom name, in case you are not using any, set it as `none`
* ip_pool: IP address pool size for VPN users. E.g. 254 for /24

For FortiOS versions **below 6.4**:

```bash
python3 pysslvpnmonitor_below_6.4_Version.py
```

For FortiOS versions **6.4 and above**:

```sh
python3 pysslvpnmonitor.py
```

## Tested on

Windows and Debian derivatives.

## Contributing

Pull requests are welcome.

## License

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
