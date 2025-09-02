"""
SNMP scanner module: tests SNMP community strings and enumerates via various tools.
"""

import argparse
import ipaddress
import json
import pathlib
import subprocess
from typing import Optional

DEFAULT_PORT = 161
TIMEOUT = 5


def run_onesixtyone(address: str, port: int, community_file: Optional[str] = None) -> str:
    """
    Run the onesixtyone SNMP community scanner.
    Returns its stdout output.
    """
    cmd = ['onesixtyone', '-p', str(port), address]
    if community_file:
        cmd[1:1] = ['-c', community_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ''
    except FileNotFoundError:
        return ''


def run_snmp_check(address: str, port: int, community: str) -> str:
    """
    Run snmp-check for detailed enumeration.
    Returns its stdout output.
    """
    cmd = ['snmp-check', '-p', str(port), '-c', community, '-v', '2c', address]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ''


def run_snmpwalk(address: str, port: int, community: str, oid: str = "") -> str:
    """
    Run snmpwalk for MIB enumeration.
    Returns its stdout output.
    """
    cmd = ['snmpwalk', '-v', '2c', '-c', community, f"{address}:{port}"]
    if oid:
        cmd.append(oid)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        return result.stdout
    except subprocess.TimeoutExpired:
        return ''


def test_snmp_access(address: str, port: int) -> dict:
    """
    Test basic SNMP read/write access using common community strings.
    Returns a dict mapping community->access type and sysDescr.
    """
    common = ['public', 'private', 'community', 'snmp']
    results = {}
    for c in common:
        out = run_snmpwalk(address, port, c, "1.3.6.1.2.1.1.1.0")
        if out:
            access = 'read'
            # test write
            cmd = ['snmpset', '-v', '2c', '-c', c, f"{address}:{port}",
                   '1.3.6.1.2.1.1.4.0', 's', 'test']
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
                if res.returncode == 0:
                    access = 'write'
            except subprocess.TimeoutExpired:
                pass
            results[c] = {'access': access, 'sysDescr': out.strip()}
    return results


def process(args: argparse.Namespace):
    """
    Orchestrate SNMP scanning: access tests and detailed enumeration.
    Writes JSON if requested.
    """
    try:
        ip = ipaddress.ip_address(args.address)
    except ValueError:
        print(f"Invalid IP address: {args.address}")
        return

    address = str(ip)
    port = args.port
    access = test_snmp_access(address, port)
    detailed = {}
    for community, info in access.items():
        detailed[community] = info
        detailed[community]['snmp_check'] = run_snmp_check(address, port, community)
        detailed[community]['system_info'] = run_snmpwalk(address, port, community, "1.3.6.1.2.1.1")
        detailed[community]['interfaces'] = run_snmpwalk(address, port, community, "1.3.6.1.2.1.2")

    if args.json:
        result = {
            'address': address,
            'port': port,
            'accessible': bool(access),
            'communities': detailed
        }
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(detailed, indent=2))


def main():
    """Entry point for snmp.py scanner script."""
    parser = argparse.ArgumentParser()
    parser.add_argument('address', help="IP address of SNMP agent")
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f"SNMP port (default {DEFAULT_PORT})")
    parser.add_argument('--json', type=pathlib.Path,
                        help="Path to output JSON results")
    args = parser.parse_args()
    process(args)


if __name__ == '__main__':
    main()
