import sys
from pysnmp.hlapi import *


class SnmpPresenter:
    """
    A class to handle SNMP operations for all versions (v1, v2c, v3).

    Attributes:
        target (str): The target IP or hostname.
        port (int): The target port, default is 161.
        version (str): The SNMP version ('v1', 'v2c', 'v3').
        community (str): The SNMP community string (for v1 and v2c).
        user (str): The SNMPv3 username.
        auth_key (str): The SNMPv3 authentication key.
        priv_key (str): The SNMPv3 privacy key.
    """

    def __init__(self, target, port=161, version='v2c', community='public',
                 user='', auth_key='', priv_key=''):
        self.target = target
        self.port = port
        self.version = version
        self.community = community
        self.user = user
        self.auth_key = auth_key
        self.priv_key = priv_key

    def _get_auth(self):
        if self.version == 'v3':
            return UsmUserData(self.user, self.auth_key, self.priv_key)
        if self.version in ['v1', 'v2c']:
            # return CommunityData(self.community, mpModel=0 if self.version == 'v1' else 1)
            return CommunityData(self.community)
        raise ValueError('Unsupported SNMP version.')

    def get(self, oid):
        """
        Perform an SNMP GET operation.

        Args:
            oid (str): The OID to query.

        Returns:
            str: The value retrieved from the SNMP agent.
        """
        # error_indication, error_status, error_index, var_binds = next(
        #     getCmd(
        #         SnmpEngine(),
        #         self._get_auth(),
        #         UdpTransportTarget((self.target, self.port)),
        #         ContextData(),
        #         ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        #     )
        # )
        #

        iterator = getCmd(SnmpEngine(),
                          CommunityData('public'),
                          UdpTransportTarget(('192.168.1.231', 161)),
                          ContextData(),
                          ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_status:  # SNMP agent errors
            print('%s at %s' % (error_status.prettyPrint(), var_binds[int(error_index) - 1] if error_index else '?'))
        else:
            for varBind in var_binds:  # SNMP response contents
                print(' = '.join([x.prettyPrint() for x in varBind]))

        if error_indication:
            raise Exception(error_indication)
        if error_status:
            raise Exception(f'{error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1] or "?"}')

        return var_binds[0].prettyPrint()

    def walk(self, oid):
        """
        Perform an SNMP WALK operation.

        Args:
            oid (str): The base OID to walk.

        Returns:
            list: A list of (OID, value) tuples.
        """
        result = []
        for error_indication, error_status, error_index, var_binds in nextCmd(
                SnmpEngine(),
                self._get_auth(),
                UdpTransportTarget((self.target, self.port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
        ):
            if error_indication:
                raise Exception(error_indication)
            if error_status:
                raise Exception(
                    f'{error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1] or "?"}')
            result.extend((vb.prettyPrint() for vb in var_binds))

        return result
