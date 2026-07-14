"""
Sensitive Paths — 200+ paths categorized by type for misconfiguration detection.
"""

# ── Version Control ──────────────────────────────────────────────────────────
VCS_PATHS = [
    '/.git/config',
    '/.git/HEAD',
    '/.git/index',
    '/.git/logs/HEAD',
    '/.gitignore',
    '/.svn/entries',
    '/.svn/wc.db',
    '/.hg/store/00manifest.i',
    '/.hg/dirstate',
    '/.bzr/README',
    '/.cvs/Entries',
]

# ── Configuration Files ──────────────────────────────────────────────────────
CONFIG_PATHS = [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.staging',
    '/.env.development',
    '/.env.backup',
    '/config.php',
    '/config.yml',
    '/config.yaml',
    '/config.json',
    '/configuration.php',
    '/settings.py',
    '/settings.json',
    '/application.yml',
    '/application.properties',
    '/appsettings.json',
    '/web.config',
    '/wp-config.php',
    '/wp-config.php.bak',
    '/wp-config.php.old',
    '/wp-config.php.save',
    '/.htaccess',
    '/.htpasswd',
    '/nginx.conf',
    '/httpd.conf',
    '/php.ini',
    '/.npmrc',
    '/.yarnrc',
    '/composer.json',
    '/package.json',
    '/Gemfile',
    '/requirements.txt',
    '/Pipfile',
    '/docker-compose.yml',
    '/docker-compose.yaml',
    '/Dockerfile',
    '/Vagrantfile',
    '/.dockerignore',
    '/Makefile',
    '/Gruntfile.js',
    '/gulpfile.js',
    '/webpack.config.js',
    '/tsconfig.json',
]

# ── Admin Panels ─────────────────────────────────────────────────────────────
ADMIN_PATHS = [
    '/admin',
    '/admin/',
    '/admin/login',
    '/admin/dashboard',
    '/administrator',
    '/administrator/',
    '/admin-panel',
    '/backend',
    '/cp',
    '/controlpanel',
    '/dashboard',
    '/manage',
    '/management',
    '/wp-admin/',
    '/wp-admin/install.php',
    '/wp-login.php',
    '/admin.php',
    '/admincp',
    '/admin_area',
    '/panel-administracion',
    '/phpmyadmin',
    '/phpmyadmin/',
    '/pma',
    '/myadmin',
    '/adminer.php',
    '/adminer',
    '/_admin',
    '/siteadmin',
    '/webadmin',
    '/admin/config',
]

# ── Debug / Development ──────────────────────────────────────────────────────
DEBUG_PATHS = [
    '/debug',
    '/debug/',
    '/_debug',
    '/__debug__/',
    '/debug/default/view',
    '/elmah.axd',
    '/trace.axd',
    '/phpinfo.php',
    '/info.php',
    '/php_info.php',
    '/test.php',
    '/info',
    '/server-status',
    '/server-info',
    '/_profiler',
    '/__profiler',
    '/debug/pprof/',
    '/debug/vars',
    '/actuator',
    '/actuator/env',
    '/actuator/health',
    '/actuator/info',
    '/actuator/configprops',
    '/actuator/beans',
    '/actuator/mappings',
    '/actuator/metrics',
    '/actuator/trace',
    '/actuator/heapdump',
    '/actuator/threaddump',
    '/actuator/logfile',
    '/env',
    '/health',
    '/metrics',
    '/console/',
    '/h2-console/',
    '/diag',
    '/status',
    '/stats',
    '/_status',
]

# ── API Documentation ────────────────────────────────────────────────────────
API_DOC_PATHS = [
    '/swagger',
    '/swagger/',
    '/swagger-ui',
    '/swagger-ui/',
    '/swagger-ui.html',
    '/swagger/v1/swagger.json',
    '/swagger/v2/swagger.json',
    '/api-docs',
    '/api-docs/',
    '/api/docs',
    '/api/swagger',
    '/api/swagger.json',
    '/api/v1/swagger.json',
    '/v1/api-docs',
    '/v2/api-docs',
    '/v3/api-docs',
    '/openapi.json',
    '/openapi.yaml',
    '/graphql',
    '/graphiql',
    '/graphql/console',
    '/api/graphql',
    '/altair',
    '/playground',
    '/redoc',
    '/docs',
    '/docs/',
]

# ── Backup Files ─────────────────────────────────────────────────────────────
BACKUP_PATHS = [
    '/backup',
    '/backup/',
    '/backup.sql',
    '/backup.zip',
    '/backup.tar.gz',
    '/backup.tar',
    '/database.sql',
    '/db.sql',
    '/dump.sql',
    '/data.sql',
    '/site.sql',
    '/www.zip',
    '/www.tar.gz',
    '/site.zip',
    '/site.tar.gz',
    '/old/',
    '/temp/',
    '/tmp/',
    '/bak/',
    '/archive/',
    '/backup.bak',
]

# ── Cloud / Infrastructure ───────────────────────────────────────────────────
CLOUD_PATHS = [
    '/.aws/credentials',
    '/.aws/config',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/.well-known/security.txt',
    '/security.txt',
    '/robots.txt',
    '/sitemap.xml',
    '/humans.txt',
    '/firebase.json',
    '/storage.yml',
    '/.gcloud/credentials.db',
    '/.azure/accessTokens.json',
]

# ── Sensitive Data Files ─────────────────────────────────────────────────────
SENSITIVE_DATA_PATHS = [
    '/id_rsa',
    '/id_rsa.pub',
    '/.ssh/id_rsa',
    '/.ssh/authorized_keys',
    '/.ssh/known_hosts',
    '/private.key',
    '/server.key',
    '/ssl.key',
    '/cert.pem',
    '/fullchain.pem',
    '/.DS_Store',
    '/Thumbs.db',
    '/.bash_history',
    '/.zsh_history',
    '/access.log',
    '/error.log',
    '/debug.log',
    '/application.log',
]


def get_all_sensitive_paths() -> list:
    """Return all sensitive paths combined (deduplicated)."""
    seen = set()
    result = []
    for path_list in [VCS_PATHS, CONFIG_PATHS, ADMIN_PATHS, DEBUG_PATHS,
                      API_DOC_PATHS, BACKUP_PATHS, CLOUD_PATHS, SENSITIVE_DATA_PATHS]:
        for path in path_list:
            if path not in seen:
                seen.add(path)
                result.append(path)
    return result


# Pre-computed combined list for convenience
ALL_PATHS = get_all_sensitive_paths()


def get_sensitive_paths_by_depth(depth: str) -> list:
    """Return depth-appropriate sensitive paths."""
    if depth == 'shallow':
        return VCS_PATHS[:4] + CONFIG_PATHS[:5] + ADMIN_PATHS[:5] + DEBUG_PATHS[:5]
    elif depth == 'medium':
        return VCS_PATHS + CONFIG_PATHS[:15] + ADMIN_PATHS[:15] + DEBUG_PATHS[:15] + API_DOC_PATHS[:10]
    else:  # deep
        return get_all_sensitive_paths()
