"""
Port Scanner Module — Lightweight TCP port scanning with service detection.

Enhanced with:
    • Service-specific probe payloads (HTTP, SSH, SMTP, FTP, Redis, etc.)
    • Version extraction from banner responses
    • SSL/TLS detection on non-standard ports
    • Risk scoring per open port

Uses socket connect scanning with configurable timeout.
"""
import re
import socket
import ssl
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ── Port Dictionaries ──────────────────────────────────────────────────────
# TOP_PORTS_SHALLOW  → used for depth='shallow'  (~50 ports)
# COMMON_PORTS       → used for depth='medium'   (~200 ports)
# EXTENDED_PORTS     → used for depth='deep'     (~1000+ ports, matches nmap top-1000)

# Always-scan critical ports (shallow)
TOP_PORTS_SHALLOW = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    2082: 'cPanel',
    2083: 'cPanel SSL',
    2086: 'WHM',
    2087: 'WHM SSL',
    2375: 'Docker API',
    2376: 'Docker API SSL',
    3000: 'Node.js/Grafana',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8000: 'HTTP Alt',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    8888: 'HTTP Alt',
    9090: 'Prometheus/Cockpit',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
    27018: 'MongoDB Alt',
    27019: 'MongoDB Alt',
    6443: 'Kubernetes API',
    10250: 'Kubernetes Kubelet',
    10255: 'Kubernetes Kubelet (RO)',
    2379: 'etcd',
    2380: 'etcd Peer',
    11211: 'Memcached',
    50070: 'Hadoop NameNode',
    9042: 'Cassandra',
    9160: 'Cassandra Thrift',
}

# Medium scan: everything above + common services
COMMON_PORTS = {
    **TOP_PORTS_SHALLOW,
    # Additional web
    4443: 'HTTPS Alt',
    4000: 'HTTP Alt',
    5000: 'Docker Registry/Flask',
    5001: 'HTTP Alt',
    7000: 'HTTP Alt',
    7001: 'WebLogic',
    7002: 'WebLogic SSL',
    8001: 'HTTP Alt',
    8008: 'HTTP Alt',
    8009: 'Tomcat AJP',
    8081: 'HTTP Alt',
    8082: 'HTTP Alt',
    8083: 'HTTP Alt',
    8084: 'HTTP Alt',
    8085: 'HTTP Alt',
    8086: 'InfluxDB',
    8090: 'HTTP Alt',
    8181: 'HTTP Alt',
    8280: 'HTTP Alt',
    8300: 'Consul RPC',
    8443: 'HTTPS Alt',
    8500: 'Consul HTTP',
    8600: 'Consul DNS',
    8834: 'Nessus',
    8880: 'HTTP Alt',
    9000: 'SonarQube/Portainer',
    9001: 'HTTP Alt',
    9003: 'HTTP Alt',
    9080: 'HTTP Alt',
    9093: 'Alertmanager',
    9094: 'Kafka',
    9100: 'Prometheus Node Exporter',
    9300: 'Elasticsearch Transport',
    9418: 'Git',
    9443: 'HTTPS Alt',
    10000: 'Webmin',
    10080: 'HTTP Alt',
    10443: 'HTTPS Alt',
    # Messaging & streaming
    1883: 'MQTT',
    5672: 'RabbitMQ AMQP',
    5673: 'RabbitMQ AMQPS',
    6000: 'X11',
    9092: 'Kafka',
    15672: 'RabbitMQ Management',
    15671: 'RabbitMQ Management SSL',
    61613: 'ActiveMQ STOMP',
    61614: 'ActiveMQ STOMP SSL',
    61616: 'ActiveMQ',
    # Databases
    1234: 'DB Alt',
    1999: 'DB Alt',
    3050: 'Firebird DB',
    3351: 'Odette FTP',
    4848: 'GlassFish Admin',
    5005: 'Java Debug',
    5433: 'PostgreSQL Alt',
    6432: 'PgBouncer',
    7474: 'Neo4j HTTP',
    7687: 'Neo4j Bolt',
    8529: 'ArangoDB',
    9229: 'Node.js Debug',
    28015: 'RethinkDB',
    28016: 'RethinkDB Admin',
    # Distributed systems
    2181: 'ZooKeeper',
    2888: 'ZooKeeper Peers',
    3888: 'ZooKeeper Leader Election',
    4001: 'etcd Alt',
    4040: 'Spark WebUI',
    4194: 'cAdvisor',
    6060: 'HTTP Alt',
    7077: 'Spark Master',
    8088: 'Hadoop YARN',
    8042: 'Hadoop NodeManager',
    8888: 'Jupyter / HTTP Alt',
    16010: 'HBase Master',
    16020: 'HBase RegionServer',
    50090: 'Hadoop Secondary NameNode',
    # Security & admin tools
    389: 'LDAP',
    636: 'LDAPS',
    1080: 'SOCKS Proxy',
    1194: 'OpenVPN',
    1723: 'PPTP VPN',
    4500: 'IPSec NAT-T',
    5060: 'SIP',
    5061: 'SIP TLS',
    5601: 'Kibana',
    7777: 'Oracle XML DB',
    8161: 'ActiveMQ Web Console',
    9090: 'Prometheus/Cockpit',
    11443: 'HTTPS Alt',
    50000: 'Jenkins Agent / SAP',
    # Mail
    465: 'SMTPS',
    2525: 'SMTP Alt',
    # Remote access
    5985: 'WinRM HTTP',
    5986: 'WinRM HTTPS',
    902: 'VMware ESXi',
    903: 'VMware ESXi',
    # Misc high-value
    1099: 'Java RMI',
    4899: 'RAdmin',
    8649: 'Ganglia',
    9200: 'Elasticsearch',
    9600: 'Logstash',
    9999: 'HTTP Alt',
    10001: 'SCP Alt',
    27020: 'MongoDB Alt',
}

# Deep scan: everything COMMON + more obscure/dangerous ports
EXTENDED_PORTS = {
    **COMMON_PORTS,
    # IANA well-known dangerous/interesting ports
    1: 'TCP Port Service Multiplexer',
    7: 'Echo',
    9: 'Discard',
    13: 'Daytime',
    19: 'Chargen',
    20: 'FTP Data',
    37: 'Time Protocol',
    69: 'TFTP',
    79: 'Finger',
    98: 'Linuxconf',
    102: 'Siemens S7',
    104: 'DICOM',
    137: 'NetBIOS Name',
    138: 'NetBIOS Datagram',
    161: 'SNMP',
    162: 'SNMP Trap',
    179: 'BGP',
    194: 'IRC',
    201: 'AppleTalk',
    264: 'BGMP',
    311: 'Apple Xserver',
    383: 'HP OpenView',
    407: 'Timbuktu',
    443: 'HTTPS',
    444: 'HTTPS Alt',
    449: 'Cray NFS',
    500: 'IKE/IPSec',
    502: 'Modbus',
    503: 'Modbus Alt',
    512: 'RSH Exec',
    513: 'RSH Login',
    514: 'RSH Shell/Syslog',
    515: 'LPD Printer',
    520: 'RIP',
    522: 'ULP',
    540: 'UUCP',
    548: 'AFP',
    554: 'RTSP',
    563: 'NNTP SSL',
    593: 'HTTP RPC',
    594: 'HTTP RPC',
    631: 'IPP/CUPS',
    666: 'Doom',
    691: 'MS Exchange Routing',
    749: 'Kerberos Administration',
    873: 'rsync',
    902: 'VMware Auth',
    989: 'FTPS Data',
    990: 'FTPS',
    992: 'Telnet SSL',
    994: 'IRC SSL',
    1024: 'Reserved',
    1026: 'Windows IIS',
    1027: 'Windows IIS',
    1028: 'Windows IIS',
    1029: 'Windows IIS',
    1110: 'NFS Alt',
    1119: 'Battle.net',
    1167: 'Phone',
    1234: 'VLC',
    1241: 'Nessus',
    1243: 'Sub7 Trojan',
    1256: 'FTP Alt',
    1270: 'SCOM',
    1311: 'Dell OpenManage',
    1433: 'MSSQL',
    1434: 'MSSQL Monitor',
    1524: 'Ingres',
    1533: 'IBM Lotus',
    1604: 'Citrix ICA',
    1645: 'RADIUS Auth Alt',
    1646: 'RADIUS Acct Alt',
    1701: 'L2TP VPN',
    1720: 'H.323',
    1741: 'CiscoWorks',
    1755: 'MS Media Services',
    1812: 'RADIUS Auth',
    1813: 'RADIUS Acct',
    1900: 'SSDP/uPnP',
    1944: 'Close Combat Alt',
    1972: 'InterSystems Cache',
    2000: 'Cisco SCCP',
    2002: 'Cisco ACS',
    2003: 'Finger / Brutus',
    2049: 'NFS',
    2064: 'Distributed Lock Mgr',
    2082: 'cPanel',
    2100: 'Oracle XDB FTP',
    2103: 'MSRPC over TCP',
    2105: 'MSRPC over TCP',
    2107: 'MSRPC over TCP',
    2121: 'FTP Alt',
    2161: 'APC Agent',
    2222: 'SSH Alt / DirectAdmin',
    2301: 'HP System Mgmt',
    2381: 'HP iLO SSL',
    2401: 'CVS',
    2433: 'Timbuktu Alt',
    2443: 'HTTPS Alt',
    2482: 'Oracle XML DB HTTP',
    2483: 'Oracle DB',
    2484: 'Oracle DB SSL',
    2567: 'RCST',
    2598: 'Citrix ICA',
    2638: 'Sybase DB',
    2701: 'SMS Remote Control',
    2702: 'SMS Remote Control',
    2703: 'SMS Remote Control',
    2704: 'SMS Remote Control',
    2967: 'Symantec AV',
    3001: 'HTTP Alt',
    3002: 'HTTP Alt',
    3017: 'HTTP Alt',
    3031: 'Apple Remote Desktop',
    3128: 'Squid Proxy',
    3268: 'LDAP Global Catalogue',
    3269: 'LDAP Global Catalogue SSL',
    3283: 'Apple Remote Desktop',
    3299: 'SACP',
    3310: 'ClamAV',
    3333: 'HTTP Alt',
    3352: 'Odette FTP Alt',
    3372: 'TIP2',
    3386: 'GTP',
    3690: 'SVN',
    4001: 'etcd Peer',
    4002: 'MLDonkey Web',
    4045: 'Sun AnswerBook',
    4100: 'WatchGuard SSLVPN',
    4111: 'XgridController',
    4125: 'MS Remote Web Workplace',
    4242: 'Quake',
    4333: 'mSQL',
    4444: 'Metasploit / Blaster',
    4445: 'Universal Binary Upload',
    4446: 'Universal Binary Upload',
    4449: 'TeamViewer',
    4569: 'IAX',
    4643: 'Virtuozzo',
    4659: 'AppWorx',
    4672: 'Remote Anything',
    4782: 'DbVis',
    4800: 'Icona Shared',
    4848: 'GlassFish Admin',
    4899: 'RAdmin',
    4983: 'HTTP Alt',
    5038: 'Asterisk',
    5040: 'HTTP Alt',
    5080: 'Phone5',
    5100: 'Socalia',
    5101: 'Talarian',
    5120: 'AdobeServer',
    5190: 'AIM/ICQ',
    5247: 'iControl',
    5250: 'IBM iSeries',
    5269: 'XMPP Server',
    5280: 'XMPP BOSH',
    5357: 'WSD',
    5400: 'VNC Alt',
    5500: 'VNC Alt',
    5510: 'Ace FTP',
    5520: 'HTTP Alt',
    5550: 'DameWare',
    5554: 'Fastbackserver',
    5555: 'ADB / HP OmniBack',
    5560: 'HTTP Alt',
    5800: 'VNC HTTP',
    5820: 'ControlUp',
    5825: 'ControlUp',
    5850: 'COMIT SE HTTP',
    5900: 'VNC',
    5910: 'VNC Alt',
    5915: 'VNC Alt',
    5938: 'TeamViewer',
    5984: 'CouchDB',
    6001: 'X11',
    6002: 'X11',
    6003: 'X11',
    6004: 'X11',
    6005: 'X11',
    6006: 'TensorFlow',
    6007: 'X11 Alias',
    6025: 'X11 Alias',
    6050: 'Nortel SAM',
    6051: 'Nortel SAM',
    6100: 'BackWeb',
    6101: 'BlackBerry Enterprise',
    6110: 'Soft Cmdr',
    6111: 'Cisco UBE',
    6150: 'Paritel',
    6200: 'LARA',
    6201: 'LARA',
    6262: 'HTTP Alt',
    6300: 'BPQ AX.25',
    6346: 'Gnutella',
    6347: 'Gnutella Alt',
    6400: 'Net Optix',
    6500: 'Net Support',
    6503: 'Danware',
    6504: 'Danware',
    6505: 'Danware',
    6506: 'Danware',
    6660: 'IRC',
    6661: 'IRC',
    6662: 'IRC',
    6663: 'IRC',
    6664: 'IRC',
    6665: 'IRC',
    6666: 'IRC',
    6667: 'IRC',
    6668: 'IRC',
    6669: 'IRC',
    6697: 'IRC SSL',
    6776: 'Sub7 Trojan',
    6881: 'BitTorrent',
    6887: 'CPHA',
    6888: 'MUSE',
    6889: 'MUSE',
    6901: 'Windows Live Messenger',
    6970: 'QuickTime',
    7025: 'Zimbra',
    7047: 'Zimbra',
    7070: 'RealServer',
    7100: 'X Font Service',
    7144: 'Peercast',
    7145: 'Peercast',
    7403: 'Oracle DB',
    7443: 'HTTPS Alt',
    7510: 'HP iLO',
    7627: 'Diesel',
    7676: 'Imqbrokerd',
    7741: 'SCRIPTVIEW',
    7744: 'Bamboo',
    7800: 'HTTP Alt',
    7878: 'HTTP Alt',
    7900: 'Xinetd',
    7920: 'HTTP Alt',
    7921: 'HTTP Alt',
    7937: 'NSR client',
    7938: 'NSR server',
    7999: 'iRDMI',
    8007: 'HTTP Alt',
    8023: 'HTTP Alt',
    8025: 'HTTP Alt',
    8060: 'HTTP Alt',
    8080: 'HTTP Proxy',
    8098: 'Riak',
    8100: 'HTTP Alt',
    8111: 'HTTP Alt',
    8181: 'HTTP Alt',
    8200: 'VMware vCenter',
    8222: 'VMware vCenter',
    8243: 'WSO2 HTTPS',
    8280: 'WSO2 HTTP',
    8333: 'Bitcoin',
    8400: 'HTTP Alt',
    8401: 'HTTP Alt',
    8402: 'HTTP Alt',
    8403: 'HTTP Alt',
    8484: 'HTTP Alt',
    8585: 'Aria Security',
    8600: 'HTTP Alt',
    8686: 'JMX',
    8787: 'HTTP Alt / RDT',
    8800: 'HTTP Alt',
    8812: 'HTTP Alt',
    8848: 'Nacos',
    8888: 'Jupyter Notebook',
    8983: 'Solr',
    8989: 'HTTP Alt',
    9001: 'Tor Hidden Service',
    9007: 'Tianyin',
    9009: 'Pichat',
    9010: 'Sype SEM',
    9011: 'HTTP Alt',
    9043: 'WebSphere Admin',
    9060: 'WebSphere Admin',
    9080: 'WebSphere HTTP',
    9081: 'Trac.io',
    9083: 'IBM Cognos',
    9084: 'IBM Cognos',
    9085: 'IBM Cognos',
    9086: 'IBM Cognos',
    9090: 'Prometheus/Cockpit',
    9091: 'Transmission BitTorrent',
    9095: 'IBM Cognos',
    9096: 'IBM Cognos',
    9099: 'HTTP Alt',
    9103: 'Bacula FD',
    9104: 'MySQL Proxy',
    9105: 'Bacula SD',
    9200: 'Elasticsearch',
    9207: 'ObjectStore',
    9222: 'Chrome Remote Debugger',
    9229: 'Node.js Inspector',
    9298: 'HTTP Alt',
    9390: 'OpenVAS',
    9391: 'OpenVAS',
    9392: 'OpenVAS',
    9393: 'OpenVAS',
    9394: 'OpenVAS',
    9415: 'HTTP Alt',
    9443: 'HTTPS Alt',
    9444: 'HTTPS Alt',
    9502: 'HTTP Alt',
    9503: 'HTTP Alt',
    9595: 'PCC',
    9655: 'UFTP',
    9800: 'Subversion WebDAV',
    9981: 'Tvheadend',
    9982: 'Tvheadend',
    9988: 'RemoteWare',
    9998: 'HTTP Alt',
    10010: 'Control TCP',
    10100: 'VERITAS',
    10101: 'eZproxy',
    10500: 'ACT',
    10809: 'NBD',
    11000: 'HTTP Alt',
    11211: 'Memcached',
    11300: 'Beanstalkd',
    12000: 'IBM DB2',
    12443: 'HTTPS Alt',
    13722: 'NetBackup',
    13782: 'NetBackup',
    13783: 'NetBackup',
    14000: 'PRSYNC',
    15000: 'HTTP Alt',
    16443: 'Microk8s API',
    18080: 'Monero',
    18081: 'Monero RPC',
    18091: 'Couchbase',
    18092: 'Couchbase',
    19999: 'HTTP Alt',
    20000: 'Webmin Alt / DNP',
    21000: 'HTTP Alt',
    22222: 'PowerSchool',
    25000: 'HTTP Alt',
    27019: 'MongoDB Alt',
    28017: 'MongoDB Web',
    28080: 'HTTP Alt',
    28443: 'HTTPS Alt',
    30000: 'HTTP Alt',
    32400: 'Plex Media Server',
    32443: 'Plex Media Server SSL',
    37777: 'Dahua DVR',
    39000: 'HTTP Alt',
    40000: 'SafetyNET-P',
    43210: 'HTTP Alt',
    44158: 'Helium',
    44818: 'Ethernet/IP',
    47808: 'BACnet',
    49152: 'Windows Dynamic',
    50050: 'Cobalt Strike Beacon',
    52869: 'MiniUPnP',
    55553: 'Metasploit',
    60000: 'HTTP Alt',
    60443: 'HTTPS Alt',
    61000: 'HTTP Alt',
    65000: 'HTTP Alt',
    65443: 'HTTPS Alt',
    # ── Additional nmap top-1000 ports ──────────────────────────────────────
    # Well-known services
    3: 'CompressNET',
    6: 'Remote Job Entry',
    17: 'QOTD',
    24: 'Any Private Mail',
    26: 'RSFTP',
    42: 'WINS Name Server',
    43: 'WHOIS',
    49: 'TACACS Login',
    70: 'Gopher',
    81: 'HTTP Alt',
    82: 'HTTP Alt',
    83: 'HTTP Alt',
    84: 'HTTP Alt',
    88: 'Kerberos Authentication',
    99: 'HTTP Alt',
    100: 'HTTP Alt',
    106: '3COM-TSMUX',
    113: 'Ident/Auth',
    116: 'ANSA REX notify',
    119: 'NNTP',
    144: 'NeWS',
    163: 'CMIP Manager',
    177: 'XDMCP',
    199: 'SMUX',
    222: 'Berkeley rsh',
    256: 'FW-1 SecureRemote',
    259: 'ESRO-GEN',
    280: 'HTTP-Management',
    301: 'ThinLinc Web Admin',
    306: 'Unknown',
    366: 'ODMR SMTP',
    406: 'IMSP',
    416: 'Silverplatter',
    417: 'Onmux',
    425: 'ICAD-El',
    427: 'SLP',
    458: 'Apple QuickTime',
    464: 'Kpasswd',
    481: 'PH Service',
    497: 'Retrospect',
    524: 'NCP',
    541: 'UUCP-Rlogin',
    543: 'Klogin',
    544: 'Kshell',
    545: 'ekshell',
    555: 'Whurly',
    616: 'SCO SysAdmin',
    617: 'SCO Desktop Admin',
    625: 'AppleShare IP Registry',
    646: 'LDP',
    648: 'RRP',
    667: 'Disclose',
    668: 'Mecomm',
    683: 'CORBA IIOP',
    687: 'AppleShare',
    700: 'EPP',
    705: 'AgentX',
    711: 'Cisco TDP',
    714: 'Cisco TDP Alt',
    720: 'Unknown',
    722: 'SSH Alt',
    726: 'Unknown',
    765: 'Webster',
    777: 'Multi-UO',
    783: 'SpamAssassin',
    800: 'HTTP Alt',
    801: 'SOS',
    808: 'CCProxy HTTP',
    843: 'Adobe Flash Policy',
    880: 'HTTP Alt',
    888: 'HTTP Alt',
    898: 'MC Relay Protocol',
    900: 'OMG Initial Refs',
    901: 'Samba SWAT',
    911: 'NCA',
    912: 'APEX edge',
    981: 'Unknown',
    987: 'HTTPS Alt',
    999: 'Garcon',
    1000: 'HTTP Alt',
    1001: 'HTTP Alt',
    1002: 'HTTP Alt',
    1007: 'CAMEL ITU-T',
    1009: 'Unknown',
    1010: 'Unknown',
    1011: 'Unknown',
    1021: 'HTTP Alt',
    1022: 'HTTP Alt',
    1023: 'Reserved',
    1025: 'Windows RPC',
    1030: 'Windows IIS',
    1031: 'Windows IIS',
    1032: 'Windows IIS',
    1033: 'Windows IIS',
    1034: 'Windows IIS',
    1035: 'Windows IIS',
    1036: 'Windows IIS',
    1037: 'Windows IIS',
    1038: 'Windows IIS',
    1039: 'Windows IIS',
    1040: 'Netarx',
    1041: 'Danf',
    1042: 'Afrog',
    1043: 'BOINC',
    1044: 'Dev Consortium',
    1045: 'Fingerprint Image',
    1046: 'WFREMOTERTM',
    1047: 'NetMgmt Agent',
    1048: 'Sun Cluster Mgr',
    1049: 'ToPin',
    1050: 'J2EE Alt',
    1051: 'Optika',
    1052: 'Dynamic DNS',
    1053: 'Remote AS',
    1054: 'BRVREAD',
    1055: 'ANSYSLMD',
    1056: 'VFO',
    1057: 'STARTRON',
    1058: 'nim',
    1059: 'nimreg',
    1060: 'POLESTAR',
    1061: 'KIOSK',
    1062: 'Veracity',
    1063: 'KyoceraNetDev',
    1064: 'JSTEL',
    1065: 'SYSCOMLAN',
    1066: 'FPO-FNS',
    1067: 'InstallBootstrap',
    1068: 'InstallBootstrap',
    1069: 'COGNEX-INSIGHT',
    1070: 'GMX',
    1071: 'BSQUARE-VOIP',
    1072: 'CARDAX',
    1073: 'BridgeControl',
    1074: 'Fastech',
    1075: 'RDRMSHC',
    1076: 'HTTP Alt',
    1077: 'IMGames',
    1078: 'emanagecstp',
    1079: 'ASPide',
    1081: 'PVUNIWIEN',
    1082: 'AMT-ESD-PROT',
    1083: 'Anasoft License',
    1084: 'SoftCOM',
    1085: 'Web Objects',
    1086: 'Cplscrambler',
    1087: 'Cplscrambler',
    1088: 'CPL Scrambler',
    1089: 'FF Annex B',
    1090: 'FF FMS',
    1091: 'FF System Mgmt',
    1092: 'Open Business',
    1093: 'NEXGEN',
    1094: 'INET-EPS',
    1095: 'NICELINK',
    1096: 'Alta Analytics',
    1097: 'Sun Cluster Mgr',
    1098: 'RMI Activation',
    1100: 'Special Traffic',
    1102: 'Adobe Server',
    1104: 'XRL',
    1105: 'FTRANHC',
    1106: 'ISOIP-1',
    1107: 'ISOIP-2',
    1108: 'Ratio ADPv2',
    1111: 'LM Social Server',
    1112: 'Intelligent Data',
    1113: 'Lupa',
    1114: 'Mini SQL',
    1117: 'ARDUS Unicast',
    1121: 'Dldap',
    1122: 'NT-AMSM',
    1123: 'Murray',
    1124: 'HP VMM Agent',
    1126: 'HP VMM Alt',
    1130: 'CALICSUpdater',
    1131: 'CALICSTracer',
    1132: 'KVM',
    1137: 'TRIM Eventlog',
    1138: 'TRIM ICE',
    1145: 'X9 iCue',
    1147: 'CalicoSoftware',
    1148: 'Elfiq Networks',
    1149: 'Bvtsonar',
    1151: 'Unizensus Login',
    1152: 'Winpopup LAN',
    1154: 'Community Svc',
    1163: 'SmartDialer',
    1164: 'QSM Proxy',
    1165: 'QSM GUI',
    1166: 'QSM RemoteExec',
    1169: 'TRIPWIRE',
    1174: 'FlashNet Remote',
    1175: 'DossierServer',
    1183: 'LL Surf',
    1185: 'Catchpole',
    1186: 'MySQL Cluster Mgr',
    1187: 'Alias Service',
    1192: 'CAIDS Sensors',
    1198: 'cajo',
    1199: 'DMIDI',
    1201: 'Nucleus Sand',
    1213: 'NetMgmt',
    1216: 'ETEBAC 5',
    1217: 'HPSS-NDAPI',
    1218: 'AeroFlight',
    1233: 'Unknown',
    1236: 'BVCONTROL',
    1244: 'VIS',
    1247: 'VISIBroker',
    1248: 'hermes',
    1259: 'Open Network Insight',
    1271: 'eXodus',
    1272: 'CSPMLockMgr',
    1277: 'miva-mqs',
    1287: 'RouteMatch',
    1296: 'Dossier Server',
    1300: 'H323 Hostcall',
    1301: 'H323 Hostcall Alt',
    1309: 'JTAG server',
    1310: 'Husky',
    1322: 'NOVATION',
    1328: 'Exo-config',
    1334: 'writesrv',
    1352: 'IBM Lotus Notes',
    1417: 'TriFox',
    1443: 'IANA Registered',
    1455: 'EQLDB',
    1461: 'ibm-wrless-lan',
    1494: 'Citrix ICA',
    1500: 'VLSI License Mgr',
    1501: 'VLSI PLM',
    1503: 'Databeam',
    1533: 'IBM Lotus Alt',
    1556: 'VERITAS DGD',
    1580: 'tml-sme',
    1583: 'SIMCO',
    1594: 'sixtrak',
    1600: 'issd',
    1641: 'SantaProject',
    1658: 'sixnetudr',
    1666: 'netview-aix-6',
    1687: 'nsjtp-ctrl',
    1688: 'nsjtp-data',
    1700: 'mps-raft',
    1717: 'fj-hpnp',
    1718: 'H.323 Annex E',
    1719: 'H.323 Gatekeeper',
    1721: 'caicci',
    1761: 'landesk-rc',
    1782: 'hp-hcip-gwy',
    1783: 'hp-hcip',
    1801: 'Microsoft MSMQ',
    1805: 'plato-lm',
    1839: 'netopia-vo1',
    1840: 'netopia-vo2',
    1862: 'mysql-cm-agent',
    1863: 'MSN Messenger',
    1864: 'paradym-31',
    1875: 'Westell-stats',
    1914: 'elm-momentum',
    1935: 'Macromedia Flash / RTMP',
    1947: 'SentinelSRM',
    1971: 'netop-school',
    1974: 'DRP',
    1984: 'BigBrother',
    1998: 'CISCO X.25',
    2001: 'DC',
    2004: 'mailbox',
    2005: 'berknet',
    2006: 'invokator',
    2007: 'dectalk',
    2008: 'conf',
    2009: 'news',
    2010: 'search/dossier',
    2013: 'raid-am',
    2020: 'xinupageserver',
    2021: 'servexec',
    2022: 'unknown',
    2030: 'device2',
    2033: 'glogger',
    2034: 'scoremgr',
    2035: 'imsldoc',
    2038: 'objectmanager',
    2040: 'lam',
    2041: 'interbase',
    2042: 'isis',
    2043: 'isis-bcast',
    2045: 'cdfunc',
    2046: 'sdfunc',
    2047: 'dls',
    2048: 'dls-monitor',
    2065: 'dlsrpn',
    2068: 'avocentkvm',
    2099: 'H.225 Call Signalling',
    2106: 'MZAP',
    2111: 'DSATP',
    2119: 'GSIGATEKEEPER',
    2126: 'pktcable-cops',
    2135: 'grid-resources',
    2144: 'I/O-2144',
    2160: 'apc-2160',
    2170: 'eyetv',
    2179: 'RDP Gateway',
    2190: 'TiVoConnect',
    2191: 'tvbus',
    2200: 'ICI',
    2223: 'Rockwell CSP2',
    2251: 'Distributed Framework',
    2260: 'apc-2260',
    2288: 'NEtml Comm',
    2323: 'Record Matching',
    2366: 'IDCP',
    2382: 'MS OLAP 3',
    2383: 'MS OLAP 4',
    2393: 'MS OLAP 1',
    2394: 'MS OLAP 2',
    2399: 'FileMaker',
    2492: 'Groove',
    2500: 'RTSSERV',
    2522: 'windb',
    2557: 'nicetec-nmsvc',
    2601: 'zebra',
    2602: 'ripd',
    2604: 'ospfd',
    2605: 'bgpd',
    2607: 'connection',
    2608: 'wag-service',
    2710: 'Single Object Cache',
    2717: 'pn-requester',
    2718: 'pn-requester2',
    2725: 'MSOLAP 4',
    2800: 'ACC RAID',
    2809: 'CORBA LOC',
    2811: 'GSI FTP',
    2869: 'SSDP Event Notification',
    2875: 'DX',
    2909: 'mxit',
    2920: 'ROAMLINK',
    2968: 'ENPP',
    2998: 'realsecure-sendlog',
    3003: 'PeerVPN',
    3005: 'Genius License',
    3006: 'DesktopWorks',
    3007: 'Lotus Mail Tracking',
    3011: 'Trusted Web',
    3013: 'Gilatskysurfer',
    3030: 'arepa-raft',
    3052: 'APC PowerChute',
    3071: 'csd-mgmt-port',
    3077: 'ORBIX 2000',
    3168: 'poweronnud',
    3211: 'HP SAN Mgmt',
    3221: 'Global Maintech',
    3260: 'iSCSI',
    3261: 'winShadow',
    3300: 'DRCM',
    3301: 'Tarantella',
    3322: 'ACTIVE Networks',
    3323: 'ACTIVE Networks',
    3324: 'ACTIVE Networks',
    3325: 'ACTIVE Networks',
    3390: 'Deco-Scheme',
    3404: 'UNKNOWN',
    3476: 'NVIDIA RPC',
    3493: 'APC UPS',
    3517: 'IEEE 802.11 Mgmt',
    3527: 'VERITAS UDP',
    3546: 'unknown',
    3551: 'Apcupsd',
    3580: 'nati-svrloc',
    3659: 'Apple SASL',
    3689: 'iTunes DAAP',
    3703: 'Adobe Server',
    3737: 'XPANEL',
    3766: 'SmartDialer',
    3784: 'BFD Control',
    3800: 'PrintSrv Protocol',
    3801: 'ibm-mgd',
    3809: 'Java DB',
    3814: 'NMSigPort',
    3826: 'WarMUX',
    3827: 'netmpi',
    3828: 'neteh',
    3851: 'spectraport',
    3869: 'ovsam-mgmt',
    3871: 'avocent-adsap',
    3878: 'fotogcad',
    3880: 'igrs',
    3889: 'D2000 Kernel',
    3905: 'Mailbox',
    3914: 'ListMGR Port',
    3918: 'Sunray Config',
    3920: 'TGP',
    3945: 'EMCADS',
    3971: 'LAMPLink',
    3986: 'unknown',
    3995: 'SXP Connection',
    3998: 'DNXP',
    4003: 'PXC-SPLR-FT',
    4004: 'PXC-ROID',
    4005: 'PXC-Pin',
    4006: 'PXC-Spvr',
    4126: 'Data Domain Replication',
    4129: 'NuFW Daemon',
    4224: 'Xtell',
    4279: 'nvme-ofcp',
    4321: 'Remote WhoIs',
    4343: 'unicall',
    4443: 'HTTPS Alt Pharos',
    4550: 'unknown',
    4567: 'Menavigate',
    4590: 'RubyGems HTTP',
    4658: 'PlayStation SRSS',
    4662: 'eMule P2P',
    4900: 'HyperFileSQL',
    4998: 'maybe-veritas',
    5002: 'radio-status',
    5003: 'FileMaker',
    5004: 'AVSP',
    5009: 'Airport Admin',
    5030: 'surfpass',
    5033: 'xtream',
    5050: 'VIC',
    5051: 'ida-agent',
    5054: 'RLM License',
    5087: 'unknown',
    5102: 'ASSA ABLOY',
    5103: 'FileMaker iC',
    5200: 'Apple Push Notification',
    5214: 'unknown',
    5221: 'unknown',
    5222: 'XMPP Client',
    5225: 'HP Server Data',
    5226: 'HP Server Data Alt',
    5298: 'XMPP Link-Local',
    5405: 'PCDUO',
    5414: 'StatusD',
    5431: 'Park Agent',
    5440: 'unknown',
    5544: 'unknown',
    5566: 'Westec Connect',
    5631: 'pcANYWHERE data',
    5633: 'BE Business Integrated',
    5718: 'DPM Communications',
    5730: 'Steltor CLS',
    5801: 'VNC HTTP Alt 1',
    5802: 'VNC HTTP Alt 2',
    5810: 'unknown',
    5811: 'unknown',
    5815: 'unknown',
    5822: 'unknown',
    5859: 'WHEREHOO',
    5862: 'unknown',
    5877: 'unknown',
    5901: 'VNC-1',
    5902: 'VNC-2',
    5903: 'VNC-3',
    5904: 'VNC-4',
    5906: 'unknown',
    5907: 'unknown',
    5911: 'ContextSS',
    5922: 'unknown',
    5925: 'unknown',
    5950: 'WinFS',
    5952: 'unknown',
    5959: 'Windows Remote Mgmt',
    5960: 'Windows Remote Mgmt Alt',
    5961: 'Windows Remote Mgmt Alt',
    5962: 'Windows Remote Mgmt Alt',
    5987: 'WBEM HTTP',
    5988: 'WBEM CIM-XML',
    5989: 'WBEM CIM-XML HTTPS',
    5998: 'NIMS Daemon',
    5999: 'NCD Config',
    6009: 'Printer Manager',
    6059: 'unknown',
    6106: 'MPS Client',
    6112: 'DTSpcd',
    6123: 'Backup Express',
    6129: 'DameWare Remote',
    6156: 'EMCADS Server',
    6389: 'ClariionStatus',
    6502: 'Netop Solutions',
    6510: 'Mcer Port',
    6543: 'LDS Distrib',
    6547: 'ACRM',
    6565: 'unknown',
    6566: 'SigComp',
    6567: 'SigComp SCTP',
    6580: 'Parsec Master',
    6646: 'unknown',
    6689: 'Tsa',
    6692: 'LZ Zs',
    6699: 'Napster',
    6779: 'SIMS-DB',
    6788: 'SMC-HTTP',
    6789: 'App Config Protocol',
    6792: 'unknown',
    6839: 'Asap',
    6969: 'acmsoda',
    7004: 'AFS/Kerberos',
    7007: 'ARCP',
    7019: 'Doc Morph Server',
    7103: 'NetBackup Data',
    7106: 'unknown',
    7200: 'FODMS',
    7201: 'DLIP',
    7402: 'RTPS Discovery',
    7435: 'unknown',
    7496: 'Vermicelli',
    7512: 'unknown',
    7625: 'unknown',
    7702: 'GKTMP',
    7778: 'Interwise',
    7911: 'Rhapsody Interface',
    8002: 'HTTP Alt',
    8010: 'HTTP Alt',
    8011: 'HTTP Alt',
    8021: 'FTP Proxy',
    8022: 'HTTP Alt',
    8031: 'HTTP Alt',
    8043: 'ClearQuest CE',
    8044: 'HTTP Alt',
    8045: 'HTTP Alt',
    8089: 'Splunk Management',
    8093: 'HTTP Alt',
    8099: 'HTTP Alt',
    8180: 'HTTP Alt',
    8192: 'HTTP Alt',
    8193: 'HTTP Alt',
    8194: 'Ultraseek HTTP',
    8254: 'HTTP Alt',
    8290: 'HTTP Alt',
    8291: 'Mikrotik Winbox',
    8292: 'Bloomberg',
    8383: 'HTTP Alt',
    8649: 'Ganglia XML',
    8651: 'unknown',
    8652: 'unknown',
    8654: 'unknown',
    8701: 'HTTP Alt',
    8873: 'rsync SSH',
    8899: 'HTTP Alt',
    8994: 'HBSNA',
    9002: 'DronEBuddy',
    9040: 'Tor SOCKS',
    9050: 'Tor SOCKS Proxy',
    9071: 'unknown',
    9101: 'JetDirect',
    9102: 'JetDirect Alt',
    9110: 'unknown',
    9111: 'DragonWave',
    9220: 'HP Virtual',
    9290: 'unknown',
    9485: 'unknown',
    9500: 'ismserver',
    9535: 'mngsuite',
    9575: 'Scanstudio',
    9593: 'CAP-XML',
    9594: 'MSIMS',
    9618: 'unknown',
    9666: 'unknown',
    9876: 'SD Server',
    9877: 'SCM Proxy',
    9878: 'unknown',
    9898: 'Monkeycom',
    9900: 'IUA',
    9901: 'Enrp',
    9917: 'unknown',
    9929: 'Nping Echo',
    9943: 'unknown',
    9944: 'unknown',
    9968: 'unknown',
    10002: 'documentum-emc',
    10003: 'documentum-emc-ns',
    10004: 'emcrmirccd',
    10009: 'ELVIN Client',
    10012: 'unknown',
    10024: 'Postfix SMTP',
    10025: 'Postfix SMTP',
    10082: 'unknown',
    10180: 'UNKNOWN',
    10215: 'unknown',
    10243: 'WMPAS',
    10566: 'unknown',
    10616: 'NetMechanics',
    10617: 'unknown',
    10621: 'unknown',
    10626: 'unknown',
    10628: 'unknown',
    10629: 'unknown',
    10778: 'unknown',
    11110: 'Pcsync HTTPS',
    11111: 'RicochetHuh',
    11967: 'unknown',
    12174: 'HID Door Controller',
    12265: 'unknown',
    12345: 'NetBus Trojan',
    13456: 'unknown',
    14238: 'unknown',
    14441: 'unknown',
    14442: 'unknown',
    15002: 'unknown',
    15003: 'unknown',
    15004: 'unknown',
    15660: 'Bindview-srvpoll',
    15742: 'unknown',
    16000: 'HTTP Alt',
    16001: 'HTTP Alt',
    16012: 'unknown',
    16016: 'HeagNetSrv',
    16018: 'unknown',
    16080: 'HTTP Alt',
    16113: 'unknown',
    16992: 'Intel AMT HTTP',
    16993: 'Intel AMT HTTPS',
    17877: 'unknown',
    17988: 'unknown',
    18040: 'unknown',
    18101: 'HTTP Alt',
    18988: 'HTTP Alt',
    19101: 'unknown',
    19283: 'unknown',
    19315: 'unknown',
    19350: 'unknown',
    19780: 'unknown',
    19801: 'unknown',
    19842: 'unknown',
    20005: 'unknown',
    20031: 'unknown',
    20221: 'unknown',
    20222: 'unknown',
    20828: 'unknown',
    21571: 'unknown',
    22939: 'unknown',
    23502: 'unknown',
    24444: 'unknown',
    24800: 'Synergy',
    25734: 'unknown',
    25735: 'unknown',
    26214: 'unknown',
    27000: 'FlexLM',
    27352: 'unknown',
    27353: 'unknown',
    27355: 'unknown',
    27715: 'unknown',
    28201: 'unknown',
    30718: 'unknown',
    30951: 'unknown',
    31038: 'unknown',
    31337: 'Back Orifice Trojan',
    32768: 'Dynamic RPC',
    32771: 'Dynamic RPC',
    32772: 'Dynamic RPC',
    32773: 'Dynamic RPC',
    32774: 'Dynamic RPC',
    32775: 'Dynamic RPC',
    32776: 'Dynamic RPC',
    32779: 'Dynamic RPC',
    32780: 'Dynamic RPC',
    32783: 'Dynamic RPC',
    32785: 'Dynamic RPC',
    33354: 'unknown',
    33899: 'unknown',
    34571: 'unknown',
    34572: 'unknown',
    34573: 'unknown',
    35500: 'unknown',
    38292: 'HP OpenView',
    40193: 'unknown',
    40911: 'unknown',
    41511: 'unknown',
    42510: 'unknown',
    44176: 'unknown',
    44442: 'HTTPS Alt',
    44443: 'HTTPS Alt',
    44501: 'unknown',
    45100: 'unknown',
    48080: 'HTTP Alt',
    49153: 'Windows Dynamic',
    49154: 'Windows Dynamic',
    49155: 'Windows Dynamic',
    49156: 'Windows Dynamic',
    49157: 'Windows Dynamic',
    49158: 'Windows Dynamic',
    49159: 'Windows Dynamic',
    49160: 'Windows Dynamic',
    49161: 'Windows Dynamic',
    49163: 'Windows Dynamic',
    49165: 'Windows Dynamic',
    49167: 'Windows Dynamic',
    49175: 'Windows Dynamic',
    49176: 'Windows Dynamic',
    49400: 'Compaq Web Mgmt',
    49999: 'unknown',
    50001: 'unknown',
    50002: 'unknown',
    50003: 'unknown',
    50006: 'unknown',
    50300: 'GlobalSCAPE',
    50389: 'unknown',
    50500: 'unknown',
    50636: 'unknown',
    50800: 'unknown',
    51103: 'unknown',
    51493: 'unknown',
    52673: 'unknown',
    52822: 'unknown',
    52848: 'unknown',
    54045: 'unknown',
    54328: 'unknown',
    55055: 'unknown',
    55056: 'unknown',
    55555: 'HTTP Alt',
    55600: 'unknown',
    56737: 'unknown',
    56738: 'unknown',
    57294: 'unknown',
    57797: 'unknown',
    58080: 'HTTP Alt',
    60020: 'unknown',
    61532: 'unknown',
    61900: 'unknown',
    62078: 'iPhone USB Sync',
    63331: 'unknown',
    64623: 'unknown',
    64680: 'HTTP Alt',
    65129: 'unknown',
    65389: 'unknown',
}



def run_port_scan(target_url: str, depth: str = 'medium',
                  timeout: float = 1.5, max_workers: int = 20) -> dict:
    """
    Perform TCP port scanning on the target.

    Args:
        target_url: URL to scan
        depth: shallow (top 10), medium (common), deep (extended)
        timeout: Connection timeout per port in seconds
        max_workers: Number of concurrent scanning threads

    Returns dict with:
        - hostname, ip, open_ports, issues
        - findings, metadata, errors, stats (standardised)
    """
    start = time.time()
    result = create_result('port_scanner', target_url, depth)

    parsed = urlparse(target_url)
    hostname = parsed.hostname or ''

    # Legacy keys
    result['hostname'] = hostname
    result['ip'] = None
    result['open_ports'] = []
    result['closed_count'] = 0
    result['scan_type'] = depth

    if not hostname:
        return finalize_result(result, start)

    # Resolve hostname
    try:
        ip = socket.gethostbyname(hostname)
        result['ip'] = ip
    except socket.gaierror:
        result['issues'].append('Could not resolve hostname')
        result['errors'].append('Could not resolve hostname')
        return finalize_result(result, start)

    # Select port set based on depth
    if depth == 'shallow':
        ports = TOP_PORTS_SHALLOW
    elif depth == 'deep':
        ports = EXTENDED_PORTS
    else:
        ports = COMMON_PORTS

    result['stats']['total_checks'] = len(ports)

    # Scan ports concurrently
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_port, ip, port, timeout): (port, service)
            for port, service in ports.items()
        }

        for future in as_completed(futures):
            port, service = futures[future]
            try:
                is_open, banner_info = future.result()
                if is_open:
                    entry = {
                        'port': port,
                        'service': service,
                        'state': 'open',
                        'banner': None,
                        'service_version': None,
                        'ssl': False,
                    }
                    if isinstance(banner_info, dict):
                        entry['banner'] = banner_info.get('raw')
                        entry['service_version'] = banner_info.get('service_version')
                        entry['ssl'] = banner_info.get('ssl', False)
                    elif isinstance(banner_info, str):
                        entry['banner'] = banner_info
                    open_ports.append(entry)
                    result['stats']['successful_checks'] += 1
                else:
                    result['closed_count'] += 1
            except Exception:
                result['closed_count'] += 1
                result['stats']['failed_checks'] += 1

    # Sort by port number
    open_ports.sort(key=lambda x: x['port'])
    result['open_ports'] = open_ports

    # Analyze findings
    _analyze_ports(open_ports, result)

    # Service-level security checks (auth probing)
    _check_service_security(hostname, open_ports, result, timeout)

    # Add UDP service hints for commonly-audited UDP ports (TCP-colocated)
    open_port_nums = {p['port'] for p in open_ports}
    _add_udp_hints(open_port_nums, result)

    # Actual UDP scanning for critical services
    _scan_udp_services(ip, result, depth=depth, timeout=timeout)

    # Add structured findings
    for p in open_ports:
        add_finding(result, {
            'type': 'open_port',
            'port': p['port'],
            'service': p['service'],
            'banner': p.get('banner'),
        })

    for issue in result['issues']:
        add_finding(result, {
            'type': 'port_issue',
            'detail': issue,
            'severity': 'high' if 'RCE' in issue or 'RDP' in issue else 'medium',
        })

    # ── External port scanner augmentation (naabu) ──
    try:
        from apps.scanning.engine.tools.wrappers.naabu_wrapper import NaabuTool
        _naabu = NaabuTool()
        if _naabu.is_available():
            _existing_ports = {p['port'] for p in result.get('open_ports', [])}
            for _tr in _naabu.run(hostname):
                if _tr.port and _tr.port not in _existing_ports:
                    _existing_ports.add(_tr.port)
                    result['open_ports'].append({
                        'port': _tr.port,
                        'service': 'unknown',
                        'state': 'open',
                        'banner': None,
                        'service_version': None,
                        'ssl': False,
                    })
                    add_finding(result, {
                        'type': 'open_port',
                        'port': _tr.port,
                        'service': 'naabu',
                        'banner': None,
                    })
    except Exception:
        pass

    return finalize_result(result, start)


def _check_port(ip: str, port: int, timeout: float) -> tuple:
    """Check if a TCP port is open and grab service banner.

    Returns ``(is_open, banner_info)`` where banner_info is a dict with
    keys: ``raw``, ``service_version``, ``ssl``.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            banner_info = {'raw': None, 'service_version': None, 'ssl': False}

            # Try service-specific probes
            try:
                banner_info = _grab_banner(sock, ip, port)
            except Exception:
                pass

            sock.close()
            return True, banner_info

        sock.close()
        return False, None
    except Exception:
        return False, None


# ── Service-specific probe payloads ───────────────────────────────────────

_SERVICE_PROBES = {
    # HTTP ports
    80: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    443: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    8080: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    8443: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    8000: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    8888: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    3000: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    9090: b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n',
    # SMTP
    25: None,   # SMTP sends banner on connect
    587: None,
    # FTP
    21: None,   # FTP sends banner on connect
    # SSH
    22: None,   # SSH sends banner on connect
    # Redis
    6379: b'PING\r\n',
    # MySQL
    3306: None,  # MySQL sends greeting on connect
    # MongoDB
    27017: None,
    # Memcached
    11211: b'version\r\n',
    # Elasticsearch
    9200: b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
}

# Ports that commonly use SSL
_SSL_PORTS = {443, 8443, 993, 995, 636, 2083, 2087, 2376, 6443}

# Banner version extraction patterns
_VERSION_PATTERNS = [
    (r'SSH-[\d.]+-(\S+)', 'SSH'),
    (r'Server:\s*(\S+(?:/[\d.]+)?)', 'HTTP Server'),
    (r'220[- ].*?(\S+(?:/[\d.]+))\s', 'FTP/SMTP'),
    (r'MySQL.*?([\d.]+)', 'MySQL'),
    (r'\+PONG', 'Redis'),
    (r'Memcached.*?([\d.]+)', 'Memcached'),
    (r'"version"\s*:\s*"([^"]+)"', 'Elasticsearch'),
    (r'MongoDB.*?([\d.]+)', 'MongoDB'),
    (r'X-Powered-By:\s*(\S+)', 'Powered-By'),
    (r'OpenSSH[_ ]([\d.p]+)', 'OpenSSH'),
    (r'Apache/([\d.]+)', 'Apache'),
    (r'nginx/([\d.]+)', 'nginx'),
    (r'Microsoft-IIS/([\d.]+)', 'IIS'),
]


def _grab_banner(sock: socket.socket, ip: str, port: int) -> dict:
    """Grab a service banner using appropriate probe."""
    banner_info = {'raw': None, 'service_version': None, 'ssl': False}
    sock.settimeout(3.0)

    # Check if SSL port — try SSL handshake
    if port in _SSL_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=ip)
            banner_info['ssl'] = True
            banner_info['ssl_version'] = ssock.version()

            # Get cert info
            try:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    banner_info['cert_subject'] = str(cert.get('subject', ''))[:200]
            except Exception:
                pass

            # Send HTTP probe on SSL ports
            probe = _SERVICE_PROBES.get(port)
            if probe:
                ssock.sendall(probe.replace(b'{host}', ip.encode()))
                data = ssock.recv(2048)
                banner_info['raw'] = data.decode('utf-8', errors='ignore').strip()[:500]
            ssock.close()
        except (ssl.SSLError, OSError):
            # Not actually SSL, fall through to normal banner grab
            banner_info['ssl'] = False
            pass

    if not banner_info['raw']:
        probe = _SERVICE_PROBES.get(port)
        try:
            if probe:
                sock.sendall(probe.replace(b'{host}', ip.encode()))
            # Read response (some services send banner on connect)
            data = sock.recv(2048)
            banner_info['raw'] = data.decode('utf-8', errors='ignore').strip()[:500]
        except Exception:
            pass

    # Extract version info from banner
    if banner_info['raw']:
        for pattern, svc_name in _VERSION_PATTERNS:
            m = re.search(pattern, banner_info['raw'], re.IGNORECASE)
            if m:
                version_str = m.group(1) if m.lastindex else m.group(0)
                banner_info['service_version'] = f'{svc_name}/{version_str}'
                break

    return banner_info


def _analyze_ports(open_ports: list, results: dict):
    """Analyze open ports for security issues."""
    port_numbers = {p['port'] for p in open_ports}

    # Database ports exposed
    db_ports = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 9042, 6432,
                28015, 7474, 8529, 5984, 9600, 27018, 27019}
    exposed_dbs = port_numbers & db_ports
    if exposed_dbs:
        services = [p['service'] for p in open_ports if p['port'] in exposed_dbs]
        results['issues'].append(f'Database ports exposed: {", ".join(services)}')

    # Management/admin ports
    admin_ports = {2082, 2083, 2086, 2087, 8834, 10000, 9000, 5601, 15672,
                   4848, 9390, 9391, 8161, 7001, 8983, 9080, 9060, 9043}
    exposed_admin = port_numbers & admin_ports
    if exposed_admin:
        services = [p['service'] for p in open_ports if p['port'] in exposed_admin]
        results['issues'].append(f'Management interfaces exposed: {", ".join(services)}')

    # Docker/Kubernetes
    container_ports = {2375, 2376, 6443, 10250, 10255, 2379, 2380, 4194}
    exposed_container = port_numbers & container_ports
    if exposed_container:
        services = [p['service'] for p in open_ports if p['port'] in exposed_container]
        results['issues'].append(
            f'Container/orchestration ports exposed — potential RCE risk: {", ".join(services)}'
        )

    # Insecure protocols
    insecure = {21, 23, 110, 512, 513, 514, 69, 79, 111}
    exposed_insecure = port_numbers & insecure
    if exposed_insecure:
        services = [p['service'] for p in open_ports if p['port'] in exposed_insecure]
        results['issues'].append(f'Insecure protocols exposed: {", ".join(services)}')

    # RDP exposed
    if 3389 in port_numbers:
        results['issues'].append('RDP exposed to internet — brute-force and exploit risk')

    # VNC exposed
    vnc_ports = port_numbers & {5900, 5800, 5400, 5500, 5910, 5915}
    if vnc_ports:
        results['issues'].append('VNC exposed to internet — potential unauthorized access')

    # Industrial control / SCADA
    scada_ports = port_numbers & {502, 503, 44818, 47808, 20000, 102}
    if scada_ports:
        results['issues'].append(
            'Industrial/SCADA protocol ports exposed — critical infrastructure risk'
        )

    # C2 / malware-associated ports
    c2_ports = port_numbers & {4444, 1243, 6776, 50050, 55553}
    if c2_ports:
        results['issues'].append(
            f'Ports associated with malware/C2 frameworks open: {sorted(c2_ports)}'
        )

    # Remote code execution risk services
    rce_ports = port_numbers & {1099, 4848, 7001, 7002, 8983, 9200, 50000}
    if rce_ports:
        services = [p['service'] for p in open_ports if p['port'] in rce_ports]
        results['issues'].append(
            f'Services with historical RCE vulnerabilities exposed: {", ".join(services)}'
        )


def _check_service_security(host: str, open_ports: list, results: dict, timeout: float):
    """Probe open service ports for authentication weaknesses.

    Checks:
    - Anonymous FTP access
    - Unauthenticated Redis
    - Open MongoDB (no auth required)
    - Open Elasticsearch HTTP API
    - Open Memcached
    - Open Docker API (no TLS)
    - Chrome Remote Debugger
    - Node.js/Erlang debug ports
    """
    port_map = {p['port']: p for p in open_ports}

    # ── Anonymous FTP ─────────────────────────────────────────────────────
    if 21 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 21))
            s.recv(1024)  # banner
            s.sendall(b'USER anonymous\r\n')
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            if '331' in resp or '230' in resp:
                s.sendall(b'PASS anonymous@\r\n')
                resp2 = s.recv(1024).decode('utf-8', errors='ignore')
                if '230' in resp2:
                    results['issues'].append('FTP anonymous login ALLOWED — critical')
                    add_finding(results, {
                        'type': 'service_auth',
                        'service': 'FTP',
                        'port': 21,
                        'detail': 'Anonymous login allowed',
                        'severity': 'critical',
                    })
            s.close()
        except Exception:
            pass

    # ── Unauthenticated Redis ─────────────────────────────────────────────
    if 6379 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 6379))
            s.sendall(b'PING\r\n')
            resp = s.recv(128).decode('utf-8', errors='ignore')
            s.close()
            if '+PONG' in resp:
                results['issues'].append('Redis is accessible WITHOUT authentication — critical')
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'Redis',
                    'port': 6379,
                    'detail': 'No authentication required',
                    'severity': 'critical',
                })
            elif 'NOAUTH' in resp or 'WRONGPASS' in resp:
                # Auth required — good
                pass
        except Exception:
            pass

    # ── Open Memcached ────────────────────────────────────────────────────
    if 11211 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 11211))
            s.sendall(b'stats\r\n')
            resp = s.recv(512).decode('utf-8', errors='ignore')
            s.close()
            if 'STAT' in resp:
                results['issues'].append('Memcached is accessible without authentication — high risk')
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'Memcached',
                    'port': 11211,
                    'detail': 'No authentication, DDoS amplification risk',
                    'severity': 'high',
                })
        except Exception:
            pass

    # ── Open Elasticsearch ────────────────────────────────────────────────
    if 9200 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 9200))
            s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            if '"cluster_name"' in resp or '"tagline"' in resp:
                results['issues'].append('Elasticsearch accessible without authentication — data exposure risk')
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'Elasticsearch',
                    'port': 9200,
                    'detail': 'Unauthenticated HTTP API',
                    'severity': 'high',
                })
        except Exception:
            pass

    # ── Open MongoDB ──────────────────────────────────────────────────────
    for mongo_port in [p for p in (27017, 27018, 27019) if p in port_map]:
        try:
            # MongoDB wire protocol: OP_QUERY against admin.$cmd {isMaster:1}
            import struct
            msg_header = struct.pack('<iiii', 0, 1, 0, 2004)
            query = (
                b'\x00\x00\x00\x00'   # flags
                b'admin.$cmd\x00'      # collection
                b'\x00\x00\x00\x00'   # skip
                b'\xff\xff\xff\xff'    # return
                b'\x13\x00\x00\x00'   # doc len
                b'\x10isMaster\x00\x01\x00\x00\x00\x00'  # BSON {isMaster:1}
            )
            msg = msg_header + query
            full = struct.pack('<i', len(msg) + 4) + msg
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, mongo_port))
            s.sendall(full)
            resp = s.recv(512)
            s.close()
            if b'ismaster' in resp.lower() or b'isWritablePrimary' in resp:
                results['issues'].append(
                    f'MongoDB port {mongo_port} responds without authentication — data exposure risk'
                )
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'MongoDB',
                    'port': mongo_port,
                    'detail': 'Responds to unauthenticated wire protocol',
                    'severity': 'high',
                })
        except Exception:
            pass

    # ── Open Docker API (no TLS) ──────────────────────────────────────────
    if 2375 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 2375))
            s.sendall(b'GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n')
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            if '"ApiVersion"' in resp or '"Version"' in resp:
                results['issues'].append('Docker API port 2375 exposed WITHOUT TLS — critical RCE risk')
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'Docker API',
                    'port': 2375,
                    'detail': 'Unauthenticated, no TLS — full container/host compromise possible',
                    'severity': 'critical',
                })
        except Exception:
            pass

    # ── Chrome Remote Debugger ────────────────────────────────────────────
    if 9222 in port_map:
        try:
            s = socket.socket()
            s.settimeout(timeout + 2)
            s.connect((host, 9222))
            s.sendall(b'GET /json HTTP/1.0\r\nHost: localhost\r\n\r\n')
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            if '"webSocketDebuggerUrl"' in resp or '"type"' in resp:
                results['issues'].append('Chrome Remote Debugger exposed — code execution / data theft risk')
                add_finding(results, {
                    'type': 'service_auth',
                    'service': 'Chrome Debugger',
                    'port': 9222,
                    'detail': 'Remote debugging protocol unauthenticated',
                    'severity': 'critical',
                })
        except Exception:
            pass


def _add_udp_hints(open_tcp_ports: set, results: dict):
    """Add informational notes about UDP services that likely run alongside open TCP ports.

    We don't do actual UDP scanning (requires root/raw sockets), but we note
    the commonly co-located UDP services so analysts know to check manually.
    """
    udp_hints = []

    if 53 in open_tcp_ports:
        udp_hints.append({'port': 53, 'protocol': 'UDP', 'service': 'DNS',
                           'note': 'Also runs on UDP/53 — check for DNS amplification / recursion'})

    if 161 in open_tcp_ports or 162 in open_tcp_ports:
        udp_hints.append({'port': 161, 'protocol': 'UDP', 'service': 'SNMP',
                           'note': 'UDP/161 — check for default community strings (public/private)'})

    if 123 in open_tcp_ports:
        udp_hints.append({'port': 123, 'protocol': 'UDP', 'service': 'NTP',
                           'note': 'UDP/123 — check for NTP amplification (monlist)'})

    if 500 in open_tcp_ports or 4500 in open_tcp_ports:
        udp_hints.append({'port': 500, 'protocol': 'UDP', 'service': 'IKE/IPSec',
                           'note': 'UDP/500 + UDP/4500 — IKE negotiation (VPN)'})

    if 1900 in open_tcp_ports:
        udp_hints.append({'port': 1900, 'protocol': 'UDP', 'service': 'SSDP/UPnP',
                           'note': 'UDP/1900 — SSDP; check for UPnP amplification / SSRF'})

    if 11211 in open_tcp_ports:
        udp_hints.append({'port': 11211, 'protocol': 'UDP', 'service': 'Memcached',
                           'note': 'UDP/11211 — massive DDoS amplification potential'})

    if udp_hints:
        results['metadata']['udp_hints'] = udp_hints
        for hint in udp_hints:
            add_finding(results, {
                'type': 'udp_hint',
                'port': hint['port'],
                'service': hint['service'],
                'note': hint['note'],
            })


# ── UDP Probe Payloads ───────────────────────────────────────────────────
# Minimal valid probe packets for each critical UDP service

def _make_dns_query() -> bytes:
    """Build a minimal DNS query for 'version.bind' (chaos class)."""
    # Transaction ID: 0xaabb
    # Flags: standard query (0x0100)
    # Questions: 1, Answers/Authority/Additional: 0
    # Query: version.bind, type TXT, class CH
    header = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    # version.bind — encoded as 7:version, 4:bind, 0
    qname = b'\x07version\x04bind\x00'
    qtype_qclass = b'\x00\x10\x00\x03'  # TXT, CHAOS
    return header + qname + qtype_qclass


def _make_snmp_public_get() -> bytes:
    """Build a minimal SNMP v1 GetRequest with community 'public'."""
    # ASN.1 / BER encoded SNMPv1 GET — sysDescr (OID 1.3.6.1.2.1.1.1.0)
    return bytes([
        0x30, 0x26,               # SEQUENCE
        0x02, 0x01, 0x00,         # Integer: version=0 (SNMPv1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING: "public"
        0xa0, 0x19,               # GetRequest PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id
        0x02, 0x01, 0x00,         # error-status: 0
        0x02, 0x01, 0x00,         # error-index: 0
        0x30, 0x0b,               # VarBind list
        0x30, 0x09,               # VarBind
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID: sysDescr (partial)
        0x05, 0x00,               # NULL value
    ])


def _make_ntp_request() -> bytes:
    """Build a minimal NTP v3 client request."""
    # LI=0, VN=3, Mode=3 (client)
    pkt = bytearray(48)
    pkt[0] = 0x1b  # LI=0, VN=3 (011), Mode=3 (011)
    return bytes(pkt)


def _make_tftp_rrq() -> bytes:
    """Build a TFTP Read Request for a non-existent file."""
    # Opcode 1 (RRQ), filename, mode=octet
    return b'\x00\x01safeweb_probe.txt\x00octet\x00'


_UDP_PROBES: dict[int, tuple[str, bytes]] = {
    53:  ('DNS',  _make_dns_query()),
    123: ('NTP',  _make_ntp_request()),
    161: ('SNMP', _make_snmp_public_get()),
    69:  ('TFTP', _make_tftp_rrq()),
}


def _check_udp_port(ip: str, port: int, service: str, payload: bytes,
                    timeout: float = 2.0) -> dict:
    """Probe a single UDP port and return a result dict.

    Returns a dict with keys: port, service, state, protocol, response, note.
    State is one of: 'open', 'closed', 'open|filtered'.
    """
    result = {
        'port': port,
        'service': service,
        'protocol': 'UDP',
        'state': 'open|filtered',
        'response': None,
        'note': '',
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, port))
        try:
            data, _ = sock.recvfrom(512)
            # Got a response — port is open
            result['state'] = 'open'
            result['response'] = data[:64].hex() if data else None
            _annotate_udp_response(result, port, data)
        except socket.timeout:
            # No response — could be open|filtered, no way to tell without ICMP
            result['state'] = 'open|filtered'
            result['note'] = 'No response — may be open or filtered'
        except ConnectionRefusedError:
            # ICMP Port Unreachable (Windows maps this to ConnectionRefusedError)
            result['state'] = 'closed'
        finally:
            sock.close()
    except Exception as exc:
        result['note'] = f'Probe error: {exc}'
    return result


def _annotate_udp_response(result: dict, port: int, data: bytes) -> None:
    """Add service-specific annotations to a confirmed-open UDP port."""
    if port == 53 and len(data) >= 12:
        result['note'] = 'DNS is responding on UDP/53'
    elif port == 123 and len(data) >= 48:
        # NTP stratum is byte 1
        stratum = data[1] if len(data) > 1 else 0
        result['note'] = f'NTP responding — stratum {stratum}; check monlist amplification'
    elif port == 161 and data:
        # Check if community string "public" is visible
        if b'public' in data:
            result['note'] = 'SNMP responding with public community — immediate credential issue'
        else:
            result['note'] = 'SNMP responding on UDP/161 — community string unknown'
    elif port == 69 and data:
        result['note'] = 'TFTP responding on UDP/69 — may allow unauthenticated file read/write'


def _scan_udp_services(ip: str, results: dict, depth: str = 'medium',
                       timeout: float = 2.0) -> None:
    """Scan critical UDP services and record findings.

    Probes DNS/53, NTP/123, SNMP/161, and TFTP/69 using valid protocol payloads.
    Gracefully degrades when UDP is blocked by OS-level firewall or NAT.
    Results stored under results['udp_ports'] and as findings.
    """
    # Only probe UDP on medium/deep scans
    if depth == 'shallow':
        return

    udp_results = []
    for port, (service, payload) in _UDP_PROBES.items():
        try:
            port_result = _check_udp_port(ip, port, service, payload, timeout)
            udp_results.append(port_result)
            if port_result['state'] in ('open', 'open|filtered'):
                severity = 'high' if port_result['state'] == 'open' else 'info'
                add_finding(results, {
                    'type': 'udp_port',
                    'port': port,
                    'service': service,
                    'state': port_result['state'],
                    'protocol': 'UDP',
                    'note': port_result.get('note', ''),
                    'severity': severity,
                })
        except Exception as exc:
            logger.debug('UDP probe %s/%d failed: %s', service, port, exc)

    if udp_results:
        results['udp_ports'] = udp_results
        open_udp = [r for r in udp_results if r['state'] == 'open']
        if open_udp:
            results['issues'].append(
                'UDP ports confirmed open: '
                + ', '.join(f"{r['service']}/{r['port']}" for r in open_udp)
            )
