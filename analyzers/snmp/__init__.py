"""
SNMP analyzer module: identifies security issues based on SNMP scan results.
"""

import ipaddress
import re
from .. import Issue, AbstractAnalyzer

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

class Analyzer(AbstractAnalyzer):
    """
    Analyzer for SNMP services. Flags insecure protocol versions,
    default community strings, public exposure, and information disclosure.
    """
    def analyze(self, files):
        super().analyze(files)
        services = self.parser.parse_files(files)
        self.services = services

        for service in services.values():
            issues = service.setdefault('issues', [])

            # Determine public/private
            try:
                addr = service.get('address')
                if addr:
                    ip = ipaddress.ip_address(addr)
                    service['public'] = ip.is_global
                    service['private'] = ip.is_private
            except ValueError:
                service['public'] = False
                service['private'] = False

            protocol = service.get('transport_protocol', 'udp')
            version = service.get('snmp_version')

            # Version checks
            if version == 'v1':
                issues.append(Issue(
                    'insecure snmp version',
                    version='SNMPv1',
                    protocol=protocol,
                    details='SNMPv1 transmits community strings in plaintext'
                ))
            elif version == 'v2c':
                issues.append(Issue(
                    'weak snmp version',
                    version='SNMPv2c',
                    protocol=protocol,
                    details='SNMPv2c transmits community strings in plaintext'
                ))

            # Unusual transport
            if protocol == 'tcp':
                issues.append(Issue(
                    'unusual transport protocol',
                    protocol='TCP',
                    details='SNMP over TCP is uncommon and may indicate misconfiguration'
                ))

            # Public exposure
            if service.get('public'):
                issues.append(Issue(
                    'public snmp exposure',
                    protocol=protocol,
                    version=version or 'unknown',
                    port=service.get('port'),
                    address=service.get('address'),
                    details='SNMP service exposed on public internet'
                ))

            # Default community strings
            defaults = self.recommendations.get('default_communities', [])
            for community in service.get('community_strings', []):
                if community.lower() in (d.lower() for d in defaults):
                    issues.append(Issue(
                        'default community string',
                        community=community,
                        access='detected in service banner',
                        protocol=protocol,
                        exposure='public' if service.get('public') else 'private'
                    ))

            # Information disclosure patterns
            desc = service.get('system_description', '')
            patterns = [
                (r'Linux [^\s]+ [\d\.]+[^\s]*', 'Operating system version'),
                (r'Windows [^\n\r]+', 'Operating system version'),
                (r'[\d]+\.[\d]+\.[\d]+\.[\d]+', 'IP addresses'),
                (r'\b(?:admin|root|administrator|user)\b', 'User account names'),
                (r'Ubuntu [^\s]+', 'Operating system distribution'),
                (r'#[\d]+-[^\s]+', 'Kernel build information'),
            ]
            for pattern, info_type in patterns:
                if re.search(pattern, desc, re.IGNORECASE):
                    details = f"Revealed via SNMP: {desc[:80]}..."
                    issues.append(Issue(
                        'information disclosure',
                        info_type=info_type,
                        source='system description',
                        protocol=protocol,
                        exposure='CRITICAL' if service.get('public') else 'WARNING',
                        public=service.get('public', False),
                        details=details
                    ))

            # Software enumeration
            sw = service.get('software_info', [])
            if sw:
                details = f"Exposed {len(sw)} software packages/processes"
                issues.append(Issue(
                    'information disclosure',
                    info_type='installed software',
                    source='SNMP enumeration',
                    protocol=protocol,
                    exposure='CRITICAL' if service.get('public') else 'WARNING',
                    public=service.get('public', False),
                    count=len(sw),
                    details=details
                ))

            # Interfaces
            if 'snmp-interfaces' in service.get('script_outputs', {}):
                issues.append(Issue(
                    'information disclosure',
                    info_type='network interfaces',
                    source='SNMP enumeration',
                    protocol=protocol,
                    exposure='CRITICAL' if service.get('public') else 'WARNING',
                    public=service.get('public', False),
                    details='Network interface information exposed'
                ))

            # Processes
            scripts = service.get('script_outputs', {})
            if 'snmp-processes' in scripts:
                issues.append(Issue(
                    'information disclosure',
                    info_type='running processes',
                    source='SNMP enumeration',
                    protocol=protocol,
                    exposure='CRITICAL' if service.get('public') else 'WARNING',
                    public=service.get('public', False),
                    details='Process information exposed via SNMP'
                ))

            # Windows software
            if 'snmp-win32-software' in scripts:
                issues.append(Issue(
                    'information disclosure',
                    info_type='Windows software inventory',
                    source='SNMP enumeration',
                    protocol=protocol,
                    exposure='CRITICAL' if service.get('public') else 'WARNING',
                    public=service.get('public', False),
                    details='Installed software list exposed'
                ))

        return services
