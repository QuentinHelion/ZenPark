from application.interfaces.presenters.snmp_presenter import SnmpPresenter


class SnmpController:
    """
    A controller class to handle user inputs and interact with the SnmpPresenter for SNMP operations.

    Attributes:
        presenter (SnmpPresenter): The SNMP presenter to handle SNMP operations.
    """

    def __init__(self, target, port=161, version='v2c', community='public',
                 user='', auth_key='', priv_key=''):
        """
        Initializes the SnmpController with the specified SNMP parameters.

        Args:
            target (str): The target IP or hostname.
            port (int): The target port (default is 161).
            version (str): The SNMP version (v1, v2c, v3).
            community (str): The SNMP community string (for v1 and v2c).
            user (str): The SNMPv3 username.
            auth_key (str): The SNMPv3 authentication key.
            priv_key (str): The SNMPv3 privacy key.
        """
        self.presenter = SnmpPresenter(target, port, version, community, user, auth_key, priv_key)

    def execute(self, operation, oid):
        """
        Executes an SNMP operation based on user input.

        Args:
            operation (str): The SNMP operation to perform ('get' or 'walk').
            oid (str): The OID to query.

        Returns:
            str/list: The result of the SNMP operation.
        """
        try:
            if operation == 'get':
                return self.presenter.get(oid)
            elif operation == 'walk':
                return self.presenter.walk(oid)
            else:
                raise ValueError(f"Unknown operation: {operation}. Use 'get' or 'walk'.")
        except Exception as e:
            return str(e)