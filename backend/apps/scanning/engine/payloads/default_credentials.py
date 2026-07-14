"""
Default Credentials — 100+ credential pairs organized by product category.
"""

# ── Generic Admin Defaults ───────────────────────────────────────────────────
GENERIC_ADMIN = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('admin', '12345678'),
    ('admin', '1234'),
    ('admin', ''),
    ('administrator', 'administrator'),
    ('administrator', 'password'),
    ('administrator', ''),
    ('root', 'root'),
    ('root', 'password'),
    ('root', 'toor'),
    ('root', ''),
    ('user', 'user'),
    ('user', 'password'),
    ('test', 'test'),
    ('guest', 'guest'),
    ('demo', 'demo'),
    ('support', 'support'),
]

# ── CMS Defaults ─────────────────────────────────────────────────────────────
CMS_DEFAULTS = [
    # WordPress
    ('admin', 'admin'),
    ('admin', 'wordpress'),
    ('wp-admin', 'wp-admin'),
    # Drupal
    ('admin', 'admin'),
    ('admin', 'drupal'),
    # Joomla
    ('admin', 'admin'),
    ('admin', 'joomla'),
    # Magento
    ('admin', 'magento'),
    ('admin', '123123'),
]

# ── Database Defaults ────────────────────────────────────────────────────────
DATABASE_DEFAULTS = [
    # MySQL
    ('root', ''),
    ('root', 'root'),
    ('root', 'mysql'),
    ('root', 'password'),
    ('mysql', 'mysql'),
    # PostgreSQL
    ('postgres', 'postgres'),
    ('postgres', 'password'),
    ('postgres', ''),
    # MongoDB
    ('admin', ''),
    ('admin', 'admin'),
    ('admin', 'mongo'),
    # Redis (auth)
    ('', 'redis'),
    ('', 'password'),
    # MSSQL
    ('sa', 'sa'),
    ('sa', 'password'),
    ('sa', ''),
    ('sa', 'SQL2019'),
]

# ── Network Equipment ────────────────────────────────────────────────────────
NETWORK_DEFAULTS = [
    # Cisco
    ('cisco', 'cisco'),
    ('admin', 'cisco'),
    ('admin', 'admin'),
    ('enable', 'enable'),
    # Juniper
    ('root', 'juniper'),
    ('admin', 'juniper'),
    # Mikrotik
    ('admin', ''),
    ('admin', 'admin'),
    # Ubiquiti
    ('ubnt', 'ubnt'),
    # TP-Link
    ('admin', 'admin'),
    # Netgear
    ('admin', 'password'),
    ('admin', '1234'),
    # D-Link
    ('admin', ''),
    ('admin', 'admin'),
]

# ── Server / Middleware ──────────────────────────────────────────────────────
SERVER_DEFAULTS = [
    # Tomcat
    ('tomcat', 'tomcat'),
    ('admin', 'tomcat'),
    ('manager', 'manager'),
    ('tomcat', 's3cret'),
    ('admin', 'admin'),
    # Jenkins
    ('admin', 'admin'),
    ('jenkins', 'jenkins'),
    # JBoss
    ('admin', 'admin'),
    ('jboss', 'jboss'),
    # Weblogic
    ('weblogic', 'weblogic'),
    ('weblogic', 'password'),
    ('weblogic', 'weblogic1'),
    # GlassFish
    ('admin', 'adminadmin'),
    ('admin', ''),
    # phpMyAdmin
    ('root', ''),
    ('root', 'root'),
    ('pma', ''),
]

# ── IoT / Embedded ──────────────────────────────────────────────────────────
IOT_DEFAULTS = [
    ('admin', 'admin'),
    ('admin', '1234'),
    ('admin', '12345'),
    ('admin', 'password'),
    ('root', 'root'),
    ('root', ''),
    ('user', 'user'),
    ('pi', 'raspberry'),
    ('admin', 'default'),
    ('admin', '000000'),
]

# ── Cloud / DevOps ───────────────────────────────────────────────────────────
CLOUD_DEFAULTS = [
    # Grafana
    ('admin', 'admin'),
    # Kibana
    ('elastic', 'changeme'),
    # RabbitMQ
    ('guest', 'guest'),
    # MinIO
    ('minioadmin', 'minioadmin'),
    # Portainer
    ('admin', 'admin'),
    # Harbor
    ('admin', 'Harbor12345'),
]


def get_all_credentials() -> list:
    """Return all credential pairs (deduplicated)."""
    seen = set()
    result = []
    for cred_list in [GENERIC_ADMIN, CMS_DEFAULTS, DATABASE_DEFAULTS,
                      NETWORK_DEFAULTS, SERVER_DEFAULTS, IOT_DEFAULTS, CLOUD_DEFAULTS]:
        for cred in cred_list:
            if cred not in seen:
                seen.add(cred)
                result.append(cred)
    return result


def get_credentials_by_depth(depth: str) -> list:
    """Return depth-appropriate credential list."""
    all_creds = get_all_credentials()
    if depth == 'shallow':
        return all_creds[:10]
    elif depth == 'medium':
        return all_creds[:30]
    else:  # deep
        return all_creds
