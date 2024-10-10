from scapy.all import *
from application.interfaces.controllers.snmp_controller import SnmpController  # Import the SnmpController
from infrastructure.data.file import File


class SnmpNetworkScanner:
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
        Performs a ping sweep across the subnet to find live hosts.
        """
        print(f"Scanning subnet {self.subnet} for live hosts...")
        live_hosts = []
        answered, unanswered = sr(IP(dst=f"{self.subnet}/24") / ICMP(), timeout=2, verbose=0)
        for sent, received in answered:
            live_hosts.append(received.src)
        print(f"Found {len(live_hosts)} live hosts.")
        return live_hosts

    def scan_snmp(self):
        """
        Scans live hosts in the subnet to check for SNMP-enabled devices using SnmpController.
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

            # Attempt an SNMP GET request for sysDescr OID
            oid = '1.3.6.1.2.1.1.1.0'  # sysDescr OID
            result = controller.execute('get', oid)

            if result:
                self.file.update_path("./database/{host}.json")
                self.file.write(result)
                print(f"SNMP enabled on {host}: {result}")
                snmp_enabled_hosts.append((host, result))
            else:
                print(f"No SNMP response from {host}.")

        return snmp_enabled_hosts
