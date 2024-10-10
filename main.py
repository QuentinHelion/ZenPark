"""
Main app file, all api route are declared there
"""

from flask import Flask, request, jsonify, abort

from pysnmp.hlapi import *
from flask_cors import CORS

from infrastructure.data.args import Args
from infrastructure.data.env_reader import EnvReader
# from infrastructure.data.token import generate_token
from application.use_cases.snmp_scanner import SnmpScanner
from application.use_cases.snmp_network_scanner import SnmpNetworkScanner
from application.interfaces.controllers.snmp_controller import SnmpController

args_checker = Args()

app = Flask(__name__)
CORS(app)

env_reader = EnvReader()
env_reader.load()


@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status': 'pong'}), 200


@app.route('/snmp/scan', methods=['GET'])
def snmp_scan():
    """
    Snmp scan endpoint
    """
    scanner = SnmpScanner(
        subnet=request.form.get("subnet", default=None, type=str),
        version=request.form.get("version", default="v2c", type=str),
        community=request.form.get("community", default="public", type=str),
        user=request.form.get("user", default=None, type=str),
        auth_key=request.form.get("authentication_key", default=None, type=str),
        priv_key=request.form.get("private_key", default=None, type=str)
    )

    snmp_enabled_hosts = scanner.scan_snmp()

    # Display results
    print("\nScan complete.")
    if snmp_enabled_hosts:
        print("SNMP-enabled devices found:")
        for host, description in snmp_enabled_hosts:
            print(f"Host: {host}, Description: {description}")
    else:
        print("No SNMP-enabled devices found.")

    return jsonify({'status': 'ok'}), 200

@app.route('/snmp/network_scan', methods=['GET'])
def snmp_network_scan():
    """
    Snmp scan endpoint
    """
    scanner = SnmpScanner(
        subnet=request.form.get("subnet", default=None, type=str),
        version=request.form.get("version", default="v2c", type=str),
        community=request.form.get("community", default="public", type=str),
        user=request.form.get("user", default=None, type=str),
        auth_key=request.form.get("authentication_key", default=None, type=str),
        priv_key=request.form.get("private_key", default=None, type=str)
    )

    snmp_enabled_hosts = scanner.scan_snmp()

    # Display results
    print("\nScan complete.")
    if snmp_enabled_hosts:
        print("SNMP-enabled devices found:")
        for host, description in snmp_enabled_hosts:
            print(f"Host: {host}, Description: {description}")
    else:
        print("No SNMP-enabled devices found.")

    return jsonify({'status': 'ok'}), 200


@app.route('/snmp/get', methods=['GET'])
def snmp_get():
    """
    Snmp get endpoint
    :return:
    """
    scanner = SnmpController(
        target=request.form.get("subnet", default=None, type=str),
        version=request.form.get("version", default="v2c", type=str),
        community=request.form.get("community", default="public", type=str),
        user=request.form.get("user", default=None, type=str),
        auth_key=request.form.get("authentication_key", default=None, type=str),
        priv_key=request.form.get("private_key", default=None, type=str)
    )

    result = scanner.execute(
        operation="get",
        oid="1.3.6.1.2.1.1.1.0"
    )
    return jsonify({'status': result}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
