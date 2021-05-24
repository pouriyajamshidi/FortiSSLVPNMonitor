#!/usr/bin/env python3

import signal
import time
from os import getenv
from os.path import isfile
from netmiko import ConnectHandler
from yaml import safe_load


class txtcolor:
    """
    This class helps with terminal output colorization
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    CYAN = '\033[1;36m'
    ORANGE = '\033[43m'
    PURPLE = '\033[45m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class FortiateSSLVPN:
    def __init__(self):
        signal.signal(signal.SIGINT, self.SignalHandler)
        self.filename_list = []

    def SignalHandler(self, frame, signal):
        print("\nCaught SIGINT\nExiting...")
        exit(1)

    def CalcTime(self):
        '''
        Calculate time to append to files.
        '''
        return time.strftime("%Y%m%d%H%M")

    def WriteFile(self, filename, inputcontent):
        '''
        Write gathered SSH output to file.
        '''

        self.timestamp = self.CalcTime()
        self.filename = str(filename + "_" + self.timestamp + ".log")

        print(f"[+] Saving to {filename}")

        with open(self.filename, 'w+') as file:
            file.write(inputcontent)

        self.filename_list.append(self.filename)

        print(f"[+] {self.filename} created and populated.")

    def ReadFile(self, filename):
        '''
        Read and return file content
        for further processing.
        '''

        print(f"[+] Reading {filename}")

        with open(filename, "r") as file:
            return file.readlines()

    def GenerateSSLVPNDic(self, content):
        '''
        Generate SSL-VPN user dictionary
        for further processing.
        '''
        printer = False
        usrdic = {}
        self.general_IP_pool = []

        for line in content:

            if line.strip() == "SSL VPN sessions:":
                printer = True
                continue
            if "Index" in line:
                continue
            if printer == True:
                if len(line) <= 4:
                    continue

                line = line.rstrip().split(" ")
                VPNIPAddr = line[10].strip()
                username = line[3]
                PubIPAddr = line[5]
                cnt = 0

                self.general_IP_pool.append(VPNIPAddr)

                if username in usrdic:
                    usrdic[username][2] += 1
                    usrdic[username].append([VPNIPAddr, PubIPAddr])
                    continue

                usrdic[username] = [VPNIPAddr, PubIPAddr, cnt + 1]

        return sorted(usrdic.items())

    def DisplaySSLUsers(self):
        '''
        Display currently connected SSL-VPN
        Users and create duplicate list.
        '''

        filenamelist = self.filename_list

        for filename in filenamelist:
            content = self.ReadFile(filename)
            sorted_usrdic = self.GenerateSSLVPNDic(content)
            self.dup_users = []
            lncounter = 1

            fwname = filename.split('-')[0]

            print(f"[+] Currently Connected SSL-VPN Users in {fwname}:")
            print("=" * 85)
            print("# Username\t\t\t VPN IP\t\t\tPublic IP\t\tAppeared")
            print("=" * 85)

            for i in sorted_usrdic:
                userlen = len(i[0])
                username = i[0]
                VPNIP = i[1][0].strip()
                PubIP = i[1][1].strip()
                Seen = i[1][2]
                print(f"{lncounter}) {username}" + " " * (30 - userlen) + f"{VPNIP}" + "\t\t"
                      + f"{PubIP}" + f"\t\t{Seen}")
                print("-" * 85)
                lncounter += 1

                if Seen >= 2:
                    self.dup_users.append(i)

            self.total_users = len(sorted_usrdic)

            if len(self.dup_users) > 0:
                self.DisplayDuplicateSSLUsers(fwname)

            self.SSLVPNSummary(fwname, self.total_users, self.general_IP_pool)

    def DisplayDuplicateSSLUsers(self, fwname):
        '''
        Display users who have connected
        more than once.
        '''
        print("\n\n")
        print(f"[+] Duplicate SSL-VPN Users in {fwname}")
        print("=" * 85)
        print("# Username\t\t\t VPN IP\t\t\tPublic IP")
        print("=" * 85)
        lncounter = 1

        dup_users = self.dup_users
        dup_users.sort(key=lambda x: x[1][2], reverse=True)

        for j in dup_users:
            count = j[1][2]
            VPNIP = j[1][0].strip()
            PubIP = j[1][1].strip()
            username = j[0]
            userlen = len(j[0])
            Seen = j[1][2]

            if count > 1:
                print("-" * 85)
                print(f"{lncounter}) {username}" + " " *
                      (30 - userlen) + f"{VPNIP}" + "\t\t" + f"{PubIP}")
                for k in j[1]:
                    if isinstance(k, int):
                        pass
                    elif len(k) == 2:
                        VPNIP = k[0].strip()
                        PubIP = k[1].strip()
                        print(f"{lncounter}) {username}" + " " * (30 -
                                                                  userlen) + f"{VPNIP}" + "\t\t" + f"{PubIP}")
                print(f"[*] Seen User for {Seen} times!")
                lncounter += 1
        print("-" * 85)

    def SSLVPNSummary(self, fwname, total_users, IP_pool):

        print(
            f"\n[+] Total number of connected users in {fwname}: {total_users}")
        print(
            f"[+] Remaining IP addresses: {int(self.available_IP_pool) - len(IP_pool)}\n")

        return

    def handle_yaml_file(self,):
        '''
        Open YAML file to get firewall info
        '''

        if isfile("firewalls.yml"):
            with open("firewalls.yml", "r") as fwfile:
                firewalls = safe_load(fwfile)
            return firewalls
        else:
            print("Could not read firewalls.yml file")
            exit(1)

    def fetch_firewall_info(self, user, passwd):
        '''
        get firewall name, IP and port
        '''

        firewalls = self.handle_yaml_file()

        for fw in firewalls["firewalls"]:
            fwname = fw["name"]
            fwip = fw["mgmt_ip"]
            fwport = fw["port"]
            fwvdom = fw["vdom"]
            self.available_IP_pool = fw["ip_pool"]
            self.SSHConnect(fwname, fwip, fwport, fwvdom, user, passwd)

    def SSHConnect(self, name, ip, port, fwvdom, user, passwd):
        '''
        Connect to Firewall.
        '''

        if passwd == None:
            firewall = {
                'device_type': 'fortinet',
                'ip': ip,
                'port': port,
                'username': user,
                'use_keys': True,
                'key_file': '/root/.ssh/id_rsa',
            }
        elif passwd:
            firewall = {
                'device_type': 'fortinet',
                'ip': ip,
                'port': port,
                'username': user,
                'password': passwd,
            }

        print(f"[+] Initiating connection to {name} - {ip}")

        try:
            net_connect = ConnectHandler(**firewall)
        except Exception as e:
            print(f"[-] Failed to connect to {name} using {ip}")
            print(e)
            return

        print(f"[+] Connected to {name}")
        print("[+] Sending commands")

        if fwvdom != "none":
            net_connect.send_command(
                "config vdom", expect_string=r"#", delay_factor=1)
            net_connect.send_command(
                f"edit {fwvdom}", expect_string=r"#", delay_factor=1)
            output = net_connect.send_command(
                "get vpn ssl monitor", expect_string=r"#", delay_factor=1)
        else:
            output = net_connect.send_command(
                "get vpn ssl monitor", expect_string=r"#", delay_factor=1)

        print("[+] Output gathered")

        filename = f"{name}-SSLVPN"
        self.WriteFile(filename, output)

        net_connect.disconnect()

        print(f"[+] Disconnected from {name}.")

    def fetch_credentials(self):

        print("[+] Fetching credentials")

        user = getenv("FORTIUSER")
        passwd = getenv("FORTIPASS")

        if user == None or passwd == None:
            print("Could not fetch credentials from ENV")
            user = input("Username: ")
            passwd = input("Password: ")

        return user, passwd

    def Run(self):

        user, passwd = self.fetch_credentials()

        self.fetch_firewall_info(user, passwd)

        Forti.DisplaySSLUsers()


if __name__ == "__main__":
    Forti = FortiateSSLVPN()
    Forti.Run()
