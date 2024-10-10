import json
from scapy.all import *
from application.interfaces.controllers.snmp_controller import SnmpController  # Import the SnmpController
from infrastructure.data.file import File


class SnmpScanner:
    """
    A class to scan a subnet for live hosts and check for SNMP-enabled devices using SnmpController.

    Attributes:
        subnet (str): The subnet to scan (e.g., 192.168.1.0/24).
        version (str): The SNMP version ('v1', 'v2c', 'v3').
        community (str): The SNMP community string (for v1 and v2c).
        user (str): SNMPv3 username.
        auth_key (str): SNMPv3 authentication key.
        priv_key (str): SNMPv3 privacy key.
    """

    def __init__(self, subnet, version='v2c', community='public', user='', auth_key='', priv_key=''):
        self.subnet = subnet
        self.version = version
        self.community = community
        self.user = user
        self.auth_key = auth_key
        self.priv_key = priv_key
        self.file = File("./database/")

    def ping_sweep(self):
        """
        Performs a ping on a single host to check if it's live.
        """
        print(f"Pinging host {self.subnet}...")
        live_hosts = []
        answered, unanswered = sr(IP(dst=self.subnet) / ICMP(), timeout=2, verbose=0)

        for sent, received in answered:
            live_hosts.append(received.src)
        if live_hosts:
            print(f"Host {self.subnet} found.")
            return live_hosts
        return False

    def scan_snmp(self):
        """
        Scans live hosts in the subnet to check for SNMP-enabled devices using SnmpController
        and writes the response in JSON format to a file with param-to-param mapping.
        """
        live_hosts = self.ping_sweep()
        snmp_enabled_hosts = []

        for host in live_hosts:
            print(f"Checking {host} for SNMP...")
            # Create SnmpController instance for each host
            controller = SnmpController(
                target=host,
                version=self.version,
                community=self.community,
                user=self.user,
                auth_key=self.auth_key,
                priv_key=self.priv_key
            )

            # OIDs to check (system group, interfaces, and more)
            oids = {
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysObjectID': '1.3.6.1.2.1.1.2.0',
                'sysUpTime': '1.3.6.1.2.1.1.3.0',
                'sysContact': '1.3.6.1.2.1.1.4.0',
                'sysName': '1.3.6.1.2.1.1.5.0',
                'sysLocation': '1.3.6.1.2.1.1.6.0',
                'sysServices': '1.3.6.1.2.1.1.7.0',

                # Interfaces information
                'ifNumber': '1.3.6.1.2.1.2.1.0',
                'ifIndex': '1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '1.3.6.1.2.1.2.2.1.2',
                'ifType': '1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
                'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
                'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
                'ifLastChange': '1.3.6.1.2.1.2.2.1.9',
                'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
                'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',

                # Host resources (available on many devices)
                'hrSystemUptime': '1.3.6.1.2.1.25.1.1.0',
                'hrMemorySize': '1.3.6.1.2.1.25.2.2.0',
                'hrStorageTypes': '1.3.6.1.2.1.25.2.3.1.2',
                'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
                'hrSystemProcesses': '1.3.6.1.2.1.25.1.6.0',
                'hrSWInstalledName': '1.3.6.1.2.1.25.6.3.1.2'
            }

            # Dictionary to store results for this host
            host_snmp_data = {}

            # Iterate over each OID and store the result
            for oid_name, oid in oids.items():
                print(f"Querying OID {oid} ({oid_name}) on {host}")
                result = controller.execute('get', oid)
                if result:
                    print(f"Received {result} for OID {oid} ({oid_name})")
                    host_snmp_data[oid_name] = result
                else:
                    print(f"No SNMP response for OID {oid} ({oid_name}) on {host}")

            if host_snmp_data:
                # Convert the dictionary to JSON format
                result_json = json.dumps(host_snmp_data, indent=4)

                # Update file path and write JSON data to file
                self.file.update_path(f"./database/{host}.json")
                self.file.write(result_json)

                print(f"SNMP data for {host}: {result_json}")
                snmp_enabled_hosts.append((host, host_snmp_data))
            else:
                print(f"No SNMP response from {host}.")

        return snmp_enabled_hosts
