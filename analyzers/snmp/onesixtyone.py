"""
Parser for SNMP community strings output by the onesixtyone scanner.
"""

import copy
import re
from .. import AbstractParser

SERVICE_SCHEMA = {
    'address': None,
    'port': None,
    'transport_protocol': 'udp',
    'community_strings': [],
    'issues': []
}

class Parser(AbstractParser):
    """
    Parses onesixtyone log lines of the form:
      <community> <ip>:<port> <response time>
    """
    def __init__(self):
        super().__init__()
        self.name = 'onesixtyone'
        self.file_type = 'log'

    def parse_file(self, path):
        super().parse_file(path)
        with open(path, encoding='utf-8') as f:
            for line in f:
                m = re.match(
                    r'(?P<community>\S+)\s+(?P<addr>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)',
                    line.strip()
                )
                if not m:
                    continue

                community = m.group('community')
                address = m.group('addr')
                port = int(m.group('port'))
                identifier = f"{address}:{port} (udp)"

                service = self.services.get(identifier)
                if not service:
                    service = copy.deepcopy(SERVICE_SCHEMA)
                    service['address'] = address
                    service['port'] = port
                    self.services[identifier] = service

                if community not in service['community_strings']:
                    service['community_strings'].append(community)

        return self.services
