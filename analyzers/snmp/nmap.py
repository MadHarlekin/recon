"""
Parser for SNMP results extracted from Nmap XML scans.
"""

import copy
import xml.etree.ElementTree as ET
from .. import AbstractParser

SERVICE_SCHEMA = {
    'address': None,
    'port': None,
    'transport_protocol': None,
    'hostname': None,
    'snmp_version': None,
    'community_strings': [],
    'system_description': None,
    'software_info': [],
    'script_outputs': {},
    'issues': []
}

class Parser(AbstractParser):
    """
    Nmap XML parser for SNMP services. Populates SERVICE_SCHEMA fields
    based on <service> and <script> outputs.
    """
    def __init__(self):
        super().__init__()
        self.name = 'nmap'
        self.file_type = 'xml'

    def parse_file(self, path):
        super().parse_file(path)
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            self.__class__.logger.warning('Could not parse XML file %s: %s', path, e)
            return self.services

        for host in root.findall('host'):
            addr_elem = host.find('.//address[@addrtype="ipv4"]') \
                       or host.find('.//address[@addrtype="ipv6"]')
            if addr_elem is None:
                continue
            address = addr_elem.get('addr')

            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol', 'udp')

                svc = port.find('service')
                if svc is None or 'snmp' not in svc.get('name', '').lower():
                    continue

                identifier = f"{address}:{port_id} ({protocol})"
                service = copy.deepcopy(SERVICE_SCHEMA)
                service['address'] = address
                service['port'] = int(port_id)
                service['transport_protocol'] = protocol

                product = svc.get('product', '')
                extrainfo = svc.get('extrainfo', '')
                hostname_attr = svc.get('hostname', '')

                if 'SNMPv1' in product:
                    service['snmp_version'] = 'v1'
                elif 'SNMPv2' in product or 'SNMPv2c' in product:
                    service['snmp_version'] = 'v2c'
                elif 'SNMPv3' in product:
                    service['snmp_version'] = 'v3'

                if extrainfo and extrainfo.strip():
                    service['community_strings'].append(extrainfo.strip())

                if hostname_attr:
                    service['hostname'] = hostname_attr

                for script in port.findall('script'):
                    sid = script.get('id')
                    out = script.get('output', '')
                    service['script_outputs'][sid] = out

                    if sid == 'snmp-sysdescr':
                        service['system_description'] = out
                    elif sid in ('snmp-win32-software', 'snmp-processes'):
                        lines = [l.strip() for l in out.split('\n') if l.strip()]
                        service['software_info'].extend(lines)
                    elif sid == 'snmp-interfaces':
                        service['script_outputs'][sid] = out

                self.__class__.logger.debug('Found SNMP service: %s', identifier)
                self.__class__.logger.debug('Version: %s', service['snmp_version'])
                self.__class__.logger.debug('Communities: %s', service['community_strings'])

                self.services[identifier] = service

        return self.services
