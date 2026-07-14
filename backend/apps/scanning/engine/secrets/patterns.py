"""
Comprehensive secret-detection regex patterns.

200+ patterns organised by provider / category.  Each entry contains:
  - regex  : compiled re.Pattern (compiled at import time for speed)
  - severity: critical | high | medium | low | info
  - cwe    : closest CWE identifier
  - description: human-readable explanation
"""

import re

# ---------------------------------------------------------------------------
# Helper — compile all patterns once at import
# ---------------------------------------------------------------------------

def _p(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Pattern registry: list[dict] with keys name, regex, severity, cwe, description
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[dict] = []


def _add(name: str, pattern: str, severity: str = 'high',
         cwe: str = 'CWE-798', description: str = '', flags: int = 0):
    SECRET_PATTERNS.append({
        'name': name,
        'regex': _p(pattern, flags),
        'severity': severity,
        'cwe': cwe,
        'description': description or f'{name} detected in response body',
    })


# ══════════════════════════════════════════════════════════════════════════════
# 1. AWS  (12 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('AWS Access Key ID',
     r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
     'critical', 'CWE-798', 'AWS IAM access key found — gives API access to AWS services')
_add('AWS Secret Access Key',
     r'(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
     'critical', 'CWE-798', 'AWS secret key — full access to associated AWS account')
_add('AWS Session Token',
     r'(?i)(?:aws_session_token|aws_token)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
     'critical', 'CWE-798')
_add('AWS MWS Key',
     r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     'critical', 'CWE-798', 'Amazon MWS auth token')
_add('AWS ARN',
     r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_/:.]+',
     'medium', 'CWE-200', 'AWS resource ARN leaks account ID and region')
_add('AWS Account ID',
     r'(?i)(?:account[_-]?id)\s*[=:]\s*["\']?\d{12}["\']?',
     'low', 'CWE-200')
_add('AWS Cognito Pool ID',
     r'(?i)(?:cognito[_-]?(?:pool|identity)[_-]?id)\s*[=:]\s*["\']?[a-z]{2}-[a-z]+-\d:[0-9a-f-]{36}["\']?',
     'medium', 'CWE-200')
_add('AWS S3 Bucket URL',
     r'(?:https?://)?[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com',
     'info', 'CWE-200', 'S3 bucket URL — check for public access')
_add('AWS AppSync GraphQL',
     r'da2-[a-z0-9]{26}',
     'high', 'CWE-798', 'AWS AppSync API key')
_add('AWS RDS Connection String',
     r'(?i)(?:rds|aurora)\.amazonaws\.com:\d+/\w+',
     'high', 'CWE-798')
_add('AWS Lambda Function URL',
     r'https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws',
     'info', 'CWE-200')
_add('AWS CloudFront Signing Key',
     r'(?i)cloudfront[_-]?(?:private[_-]?key|key[_-]?pair[_-]?id)\s*[=:]\s*["\']?[A-Z0-9]{14}',
     'critical', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 2. GCP  (8 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('GCP API Key',
     r'AIza[0-9A-Za-z_-]{35}',
     'high', 'CWE-798', 'Google Cloud Platform API key')
_add('GCP Service Account JSON',
     r'"type"\s*:\s*"service_account"',
     'critical', 'CWE-798', 'GCP service account JSON credential file')
_add('GCP Service Account Email',
     r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com',
     'medium', 'CWE-200')
_add('GCP OAuth Client ID',
     r'\d+-[a-z0-9]+\.apps\.googleusercontent\.com',
     'medium', 'CWE-200')
_add('GCP OAuth Client Secret',
     r'(?i)(?:client_secret|google_secret)\s*[=:]\s*["\']?GOCSPX-[A-Za-z0-9_-]{28}',
     'high', 'CWE-798')
_add('GCP Firebase URL',
     r'https://[a-z0-9-]+\.firebaseio\.com',
     'medium', 'CWE-200')
_add('GCP Firebase API Key',
     r'(?i)(?:firebase|fire_base)[_-]?(?:api[_-]?key|key)\s*[=:]\s*["\']?AIza[0-9A-Za-z_-]{35}',
     'high', 'CWE-798')
_add('GCP Private Key ID',
     r'(?i)(?:private_key_id)\s*:\s*"[0-9a-f]{40}"',
     'high', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 3. Azure  (10 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Azure Tenant ID',
     r'(?i)(?:tenant[_-]?id|AZURE_TENANT)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
     'medium', 'CWE-200')
_add('Azure Client Secret',
     r'(?i)(?:client[_-]?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*["\']?[A-Za-z0-9~._-]{34,}["\']?',
     'critical', 'CWE-798')
_add('Azure Storage Connection String',
     r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};',
     'critical', 'CWE-798')
_add('Azure Storage Account Key',
     r'(?i)(?:account[_-]?key|storage[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9+/=]{88}["\']?',
     'critical', 'CWE-798')
_add('Azure SAS Token',
     r'\?sv=\d{4}-\d{2}-\d{2}&s[a-z]=[a-z]+&s[a-z]{2}=[a-z]+&[^"\'>\s]{10,}',
     'high', 'CWE-798')
_add('Azure SQL Connection String',
     r'Server=tcp:[^;]+;.*(?:Password|Pwd)=[^;]+',
     'critical', 'CWE-798', flags=re.IGNORECASE)
_add('Azure Cosmos DB Key',
     r'AccountEndpoint=https://[^;]+\.documents\.azure\.com[^;]*;AccountKey=[A-Za-z0-9+/=]{88}',
     'critical', 'CWE-798')
_add('Azure Service Bus Connection',
     r'Endpoint=sb://[^;]+\.servicebus\.windows\.net/;SharedAccessKey=[A-Za-z0-9+/=]{44}',
     'critical', 'CWE-798')
_add('Azure Function Key',
     r'(?i)(?:x-functions-key|function[_-]?key)\s*[=:]\s*["\']?[A-Za-z0-9_-]{40,}["\']?',
     'high', 'CWE-798')
_add('Azure Application Insights Key',
     r'(?i)(?:instrumentation[_-]?key|appinsights[_-]?key)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
     'medium', 'CWE-200')

# ══════════════════════════════════════════════════════════════════════════════
# 4. Payment Processors  (10 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Stripe Secret Key',
     r'sk_live_[0-9a-zA-Z]{24,}',
     'critical', 'CWE-798', 'Stripe live secret key — can charge cards and access account')
_add('Stripe Publishable Key',
     r'pk_live_[0-9a-zA-Z]{24,}',
     'low', 'CWE-200', 'Stripe publishable key — not a secret but reveals account info')
_add('Stripe Restricted Key',
     r'rk_live_[0-9a-zA-Z]{24,}',
     'high', 'CWE-798')
_add('Stripe Webhook Secret',
     r'whsec_[0-9a-zA-Z]{24,}',
     'high', 'CWE-798')
_add('Square Access Token',
     r'sq0atp-[0-9A-Za-z_-]{22}',
     'critical', 'CWE-798')
_add('Square OAuth Secret',
     r'sq0csp-[0-9A-Za-z_-]{43}',
     'critical', 'CWE-798')
_add('PayPal Braintree Access Token',
     r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
     'critical', 'CWE-798')
_add('PayPal Client Secret',
     r'(?i)(?:paypal[_-]?(?:client[_-]?)?secret)\s*[=:]\s*["\']?[A-Za-z0-9_-]{40,}["\']?',
     'critical', 'CWE-798')
_add('Adyen API Key',
     r'(?i)(?:adyen[_-]?api[_-]?key)\s*[=:]\s*["\']?AQE[a-z0-9]+\.[A-Za-z0-9_-]+',
     'critical', 'CWE-798')
_add('Razorpay Key',
     r'rzp_(?:live|test)_[A-Za-z0-9]{14,}',
     'high', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 5. Communication / SaaS  (20 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('GitHub Personal Access Token',
     r'ghp_[0-9a-zA-Z]{36}',
     'critical', 'CWE-798', 'GitHub PAT — repository access')
_add('GitHub OAuth Token',
     r'gho_[0-9a-zA-Z]{36}',
     'critical', 'CWE-798')
_add('GitHub App Token',
     r'(?:ghu|ghs|ghr)_[0-9a-zA-Z]{36}',
     'critical', 'CWE-798')
_add('GitHub Fine-Grained Token',
     r'github_pat_[0-9a-zA-Z_]{82}',
     'critical', 'CWE-798')
_add('GitLab Personal Access Token',
     r'glpat-[0-9a-zA-Z_-]{20}',
     'critical', 'CWE-798')
_add('GitLab Pipeline Token',
     r'glptt-[0-9a-f]{40}',
     'high', 'CWE-798')
_add('Bitbucket App Password',
     r'(?i)(?:bitbucket[_-]?(?:app[_-]?)?password)\s*[=:]\s*["\']?[A-Za-z0-9]{20,}',
     'high', 'CWE-798')
_add('Slack Bot Token',
     r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
     'critical', 'CWE-798', 'Slack bot token — can read/write messages')
_add('Slack User Token',
     r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
     'critical', 'CWE-798')
_add('Slack Webhook URL',
     r'https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[a-zA-Z0-9]+',
     'high', 'CWE-798', 'Slack incoming webhook — can post messages')
_add('Slack App Signing Secret',
     r'(?i)(?:slack[_-]?signing[_-]?secret)\s*[=:]\s*["\']?[0-9a-f]{32}["\']?',
     'high', 'CWE-798')
_add('Discord Bot Token',
     r'(?:N|M|O)[A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}',
     'critical', 'CWE-798')
_add('Discord Webhook URL',
     r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
     'high', 'CWE-798')
_add('Twilio Account SID',
     r'AC[0-9a-f]{32}',
     'medium', 'CWE-200')
_add('Twilio Auth Token',
     r'(?i)(?:twilio[_-]?auth[_-]?token|TWILIO_AUTH)\s*[=:]\s*["\']?[0-9a-f]{32}["\']?',
     'critical', 'CWE-798')
_add('SendGrid API Key',
     r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
     'critical', 'CWE-798', 'SendGrid API key — can send emails')
_add('Mailgun API Key',
     r'key-[0-9a-zA-Z]{32}',
     'high', 'CWE-798')
_add('Mailchimp API Key',
     r'[0-9a-f]{32}-us\d{1,2}',
     'high', 'CWE-798')
_add('Telegram Bot Token',
     r'\d{8,10}:[A-Za-z0-9_-]{35}',
     'high', 'CWE-798', 'Telegram bot API token')
_add('Postmark Server Token',
     r'(?i)(?:postmark[_-]?(?:server[_-]?)?token)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     'high', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 6. Google Services  (8 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Google Maps API Key',
     r'(?i)(?:google[_-]?maps[_-]?(?:api[_-]?)?key|maps[_-]?api[_-]?key)\s*[=:]\s*["\']?AIza[0-9A-Za-z_-]{35}',
     'medium', 'CWE-798', 'Google Maps API key — may incur charges')
_add('Google OAuth Client Secret',
     r'(?i)(?:google[_-]?(?:client[_-]?)?secret)\s*[=:]\s*["\']?GOCSPX-[A-Za-z0-9_-]{28}',
     'high', 'CWE-798')
_add('Google reCAPTCHA Secret',
     r'(?i)(?:recaptcha[_-]?(?:secret[_-]?)?key|captcha[_-]?secret)\s*[=:]\s*["\']?6L[A-Za-z0-9_-]{38}',
     'high', 'CWE-798', 'reCAPTCHA server-side secret key')
_add('Google Analytics ID',
     r'UA-\d{4,10}-\d{1,4}',
     'info', 'CWE-200', 'Google Analytics tracking ID')
_add('Google Tag Manager ID',
     r'GTM-[A-Z0-9]{6,8}',
     'info', 'CWE-200')
_add('Google Cloud Messaging Key',
     r'(?i)(?:gcm[_-]?(?:api[_-]?)?key|fcm[_-]?(?:server[_-]?)?key)\s*[=:]\s*["\']?[A-Za-z0-9_-]{40,}',
     'high', 'CWE-798')
_add('Google OAuth Access Token',
     r'ya29\.[0-9A-Za-z_-]+',
     'critical', 'CWE-798', 'Google OAuth access token')
_add('Firebase Cloud Messaging',
     r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
     'high', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 7. Cryptographic Material  (10 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('RSA Private Key',
     r'-----BEGIN RSA PRIVATE KEY-----',
     'critical', 'CWE-321', 'RSA private key exposed — full key compromise')
_add('EC Private Key',
     r'-----BEGIN EC PRIVATE KEY-----',
     'critical', 'CWE-321')
_add('DSA Private Key',
     r'-----BEGIN DSA PRIVATE KEY-----',
     'critical', 'CWE-321')
_add('Generic Private Key',
     r'-----BEGIN PRIVATE KEY-----',
     'critical', 'CWE-321')
_add('Encrypted Private Key',
     r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
     'high', 'CWE-321', 'Encrypted private key — still a significant exposure')
_add('PGP Private Key Block',
     r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
     'critical', 'CWE-321')
_add('SSH Private Key (OpenSSH)',
     r'-----BEGIN OPENSSH PRIVATE KEY-----',
     'critical', 'CWE-321')
_add('SSH RSA Private Key',
     r'-----BEGIN RSA PRIVATE KEY-----[\s\S]{50,}-----END RSA PRIVATE KEY-----',
     'critical', 'CWE-321', 'Full RSA private key found')
_add('PKCS#12 Certificate',
     r'(?i)(?:pkcs12|pfx)[_-]?(?:password|pass)\s*[=:]\s*["\']?[^\s"\']+',
     'high', 'CWE-321')
_add('X.509 Certificate',
     r'-----BEGIN CERTIFICATE-----',
     'info', 'CWE-295', 'X.509 certificate (check if private key is also exposed)')

# ══════════════════════════════════════════════════════════════════════════════
# 8. Database Connection Strings  (10 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('MongoDB Connection String',
     r'mongodb(?:\+srv)?://[^\s"\'<>]+',
     'critical', 'CWE-798', 'MongoDB connection string — may contain credentials')
_add('PostgreSQL Connection String',
     r'postgres(?:ql)?://[^\s"\'<>]+',
     'critical', 'CWE-798')
_add('MySQL Connection String',
     r'mysql://[^\s"\'<>]+',
     'critical', 'CWE-798')
_add('Redis Connection String',
     r'redis://[^\s"\'<>]+',
     'high', 'CWE-798')
_add('MSSQL Connection String',
     r'(?:Server|Data Source)=[^;]+;(?:.*?)(?:Password|Pwd)=[^;]+',
     'critical', 'CWE-798', flags=re.IGNORECASE)
_add('SQLite Database Path',
     r'(?i)(?:database|db[_-]?path|sqlite)\s*[=:]\s*["\']?[^\s"\']+\.(?:db|sqlite3?)["\']?',
     'medium', 'CWE-200')
_add('JDBC Connection String',
     r'jdbc:[a-z]+://[^\s"\'<>]+',
     'high', 'CWE-798')
_add('ODBC Connection String',
     r'(?i)(?:dsn|odbc|connection[_-]?string)\s*[=:]\s*["\']?[Dd]river=[^"\']+',
     'high', 'CWE-798')
_add('Elasticsearch URL',
     r'(?:https?://)?[^\s"\'<>]*(?:elastic|es)[^\s"\'<>]*:\d{4,5}',
     'medium', 'CWE-200')
_add('CouchDB URL',
     r'https?://[^:]+:[^@]+@[^\s"\'<>]*couchdb[^\s"\'<>]*',
     'critical', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 9. JWT & Session Tokens  (6 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('JWT Token',
     r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
     'medium', 'CWE-200', 'JWT found — decode to check claims and expiry')
_add('JWT Secret Key',
     r'(?i)(?:jwt[_-]?secret|JWT_SECRET_KEY)\s*[=:]\s*["\']?[^\s"\']{16,}["\']?',
     'critical', 'CWE-798', 'JWT signing secret — can forge tokens')
_add('Bearer Token',
     r'(?i)(?:bearer|authorization)\s*[=:]\s*["\']?Bearer\s+[A-Za-z0-9_-]{20,}',
     'high', 'CWE-798')
_add('Session Secret',
     r'(?i)(?:session[_-]?secret|secret[_-]?key|app[_-]?secret)\s*[=:]\s*["\']?[^\s"\']{16,}["\']?',
     'high', 'CWE-798')
_add('Django Secret Key',
     r'(?i)(?:SECRET_KEY|DJANGO_SECRET)\s*[=:]\s*["\'][^\s"\']{20,}["\']',
     'critical', 'CWE-798', 'Django SECRET_KEY — enables session forgery and RCE')
_add('Flask Secret Key',
     r'(?i)app\.secret_key\s*=\s*["\'][^\s"\']{8,}["\']',
     'critical', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 10. CI/CD & DevOps  (12 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('NPM Access Token',
     r'npm_[A-Za-z0-9]{36}',
     'critical', 'CWE-798', 'npm publish token')
_add('PyPI API Token',
     r'pypi-[A-Za-z0-9_-]{50,}',
     'critical', 'CWE-798')
_add('NuGet API Key',
     r'oy2[a-z0-9]{43}',
     'high', 'CWE-798')
_add('Docker Hub Token',
     r'dckr_pat_[A-Za-z0-9_-]{27}',
     'critical', 'CWE-798')
_add('CircleCI Token',
     r'(?i)(?:circle[_-]?ci[_-]?token|CIRCLECI_TOKEN)\s*[=:]\s*["\']?[0-9a-f]{40}["\']?',
     'high', 'CWE-798')
_add('Travis CI Token',
     r'(?i)(?:travis[_-]?(?:ci[_-]?)?token|TRAVIS_TOKEN)\s*[=:]\s*["\']?[A-Za-z0-9]{22}["\']?',
     'high', 'CWE-798')
_add('Jenkins API Token',
     r'(?i)(?:jenkins[_-]?(?:api[_-]?)?token|JENKINS_TOKEN)\s*[=:]\s*["\']?[0-9a-f]{32,34}["\']?',
     'high', 'CWE-798')
_add('Heroku API Key',
     r'(?i)(?:heroku[_-]?api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
     'high', 'CWE-798')
_add('Vercel Token',
     r'(?i)(?:vercel[_-]?token|VERCEL_TOKEN)\s*[=:]\s*["\']?[A-Za-z0-9]{24}["\']?',
     'high', 'CWE-798')
_add('Netlify Access Token',
     r'(?i)(?:netlify[_-]?(?:access[_-]?)?token)\s*[=:]\s*["\']?[A-Za-z0-9_-]{40,}["\']?',
     'high', 'CWE-798')
_add('SonarQube Token',
     r'squ_[0-9a-f]{40}',
     'high', 'CWE-798')
_add('Sentry DSN',
     r'https://[0-9a-f]{32}@[a-z0-9.]+\.sentry\.io/\d+',
     'medium', 'CWE-200')

# ══════════════════════════════════════════════════════════════════════════════
# 11. Miscellaneous SaaS  (16 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Shopify Access Token',
     r'shpat_[a-fA-F0-9]{32}',
     'critical', 'CWE-798')
_add('Shopify Custom App Token',
     r'shpca_[a-fA-F0-9]{32}',
     'high', 'CWE-798')
_add('Shopify Private App Token',
     r'shppa_[a-fA-F0-9]{32}',
     'high', 'CWE-798')
_add('Shopify Shared Secret',
     r'shpss_[a-fA-F0-9]{32}',
     'critical', 'CWE-798')
_add('Algolia API Key',
     r'(?i)(?:algolia[_-]?(?:api[_-]?)?key|ALGOLIA_API_KEY)\s*[=:]\s*["\']?[a-f0-9]{32}["\']?',
     'high', 'CWE-798')
_add('Algolia Admin Key',
     r'(?i)(?:algolia[_-]?admin[_-]?key)\s*[=:]\s*["\']?[a-f0-9]{32}["\']?',
     'critical', 'CWE-798')
_add('Mapbox Access Token',
     r'pk\.[a-zA-Z0-9]{60,}',
     'medium', 'CWE-200')
_add('Mapbox Secret Token',
     r'sk\.[a-zA-Z0-9]{60,}',
     'high', 'CWE-798')
_add('Datadog API Key',
     r'(?i)(?:datadog|dd)[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']?[a-f0-9]{32}["\']?',
     'high', 'CWE-798')
_add('New Relic License Key',
     r'(?i)(?:new[_-]?relic[_-]?(?:license[_-]?)?key)\s*[=:]\s*["\']?[a-f0-9]{40}["\']?',
     'high', 'CWE-798')
_add('PagerDuty API Key',
     r'(?i)(?:pagerduty[_-]?(?:api[_-]?)?key)\s*[=:]\s*["\']?[A-Za-z0-9+/=]{20}["\']?',
     'high', 'CWE-798')
_add('Zendesk API Token',
     r'(?i)(?:zendesk[_-]?(?:api[_-]?)?token)\s*[=:]\s*["\']?[A-Za-z0-9]{40}["\']?',
     'high', 'CWE-798')
_add('Hubspot API Key',
     r'(?i)(?:hubspot[_-]?(?:api[_-]?)?key|HAPI_KEY)\s*[=:]\s*["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
     'high', 'CWE-798')
_add('Okta API Token',
     r'(?i)(?:okta[_-]?(?:api[_-]?)?token|OKTA_TOKEN)\s*[=:]\s*["\']?00[A-Za-z0-9_-]{40}["\']?',
     'critical', 'CWE-798')
_add('Auth0 Client Secret',
     r'(?i)(?:auth0[_-]?(?:client[_-]?)?secret)\s*[=:]\s*["\']?[A-Za-z0-9_-]{40,}["\']?',
     'high', 'CWE-798')
_add('Intercom Access Token',
     r'(?i)(?:intercom[_-]?(?:access[_-]?)?token)\s*[=:]\s*["\']?dG9r[A-Za-z0-9+/=]+',
     'high', 'CWE-798')

# ══════════════════════════════════════════════════════════════════════════════
# 12. Infrastructure & Passwords  (14 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Password in URL',
     r'[a-zA-Z]{3,10}://[^:]+:[^@\s]{3,}@[^\s"\'<>]+',
     'critical', 'CWE-798', 'Credentials embedded in URL')
_add('Password Assignment',
     r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^\s"\']{4,}["\']',
     'high', 'CWE-798', 'Hardcoded password')
_add('Basic Auth Header',
     r'(?i)(?:authorization|auth)\s*[=:]\s*["\']?Basic\s+[A-Za-z0-9+/=]{10,}',
     'high', 'CWE-798', 'Base64-encoded Basic auth credentials')
_add('Internal IP Address',
     r'(?:^|[\s"\'=])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3})(?:[\s"\':]|$)',
     'low', 'CWE-200', 'Internal/private IP address leak')
_add('Internal Hostname',
     r'(?i)(?:https?://)?(?:localhost|internal|intranet|staging|dev|test|uat|preprod)[a-z0-9.-]*(?::\d+)?(?:/[^\s"\'<>]*)?',
     'low', 'CWE-200')
_add('Environment Variable Dump',
     r'(?i)(?:PATH|HOME|SHELL|USER)=[^\s]+(?:\n(?:PATH|HOME|SHELL|USER)=[^\s]+){2,}',
     'high', 'CWE-200', 'Environment variables exposed in output')
_add('PHP Info Page',
     r'<title>phpinfo\(\)</title>',
     'medium', 'CWE-200', 'phpinfo() page exposed — reveals server configuration')
_add('Debug Mode Enabled',
     r'(?i)(?:DEBUG|debug_mode|DJANGO_DEBUG|APP_DEBUG)\s*[=:]\s*["\']?(?:true|1|yes|on)["\']?',
     'medium', 'CWE-200')
_add('Stack Trace',
     r'(?:Traceback \(most recent call last\)|at [a-zA-Z0-9$_.]+\([A-Za-z0-9_.]+:\d+\))',
     'medium', 'CWE-209', 'Application stack trace exposed')
_add('Server Path Disclosure',
     r'(?:(?:/home/|/var/www/|/opt/|/srv/|/usr/|C:\\\\(?:Users|inetpub|www)\\\\)[^\s"\'<>]{5,})',
     'low', 'CWE-200')
_add('Backup File Reference',
     r'(?i)(?:href|src|action)\s*=\s*["\'][^"\']*\.(?:bak|backup|old|orig|sql|dump|tar\.gz|log)["\']',
     'medium', 'CWE-530')
_add('.env File Reference',
     r'(?i)(?:href|src|action|include|require)\s*[=(]\s*["\']?\.env["\']?',
     'high', 'CWE-538')
_add('SMTP Credentials',
     r'(?i)(?:smtp[_-]?(?:password|pass|auth|user))\s*[=:]\s*["\']?[^\s"\']{4,}["\']?',
     'high', 'CWE-798')
_add('SSH Known Host',
     r'(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{40,}',
     'info', 'CWE-200')

# ══════════════════════════════════════════════════════════════════════════════
# 13. Source Map & Webpack  (4 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Source Map Reference',
     r'//[#@]\s*sourceMappingURL\s*=\s*[^\s"\']+\.map',
     'medium', 'CWE-540', 'JavaScript source map exposes original source code')
_add('Webpack Chunk',
     r'(?:webpackChunk|__webpack_require__|webpackJsonp)',
     'info', 'CWE-200', 'Webpack bundle detected — may contain embedded secrets')
_add('Source Map File URL',
     r'["\'][^"\']+\.js\.map["\']',
     'medium', 'CWE-540')
_add('Inline Source Map',
     r'sourceMappingURL=data:application/json;(?:charset=utf-8;)?base64,[A-Za-z0-9+/=]{50,}',
     'medium', 'CWE-540', 'Inline source map may reveal original code and secrets')

# ══════════════════════════════════════════════════════════════════════════════
# 14. API & Webhook Endpoints  (6 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('Generic API Key Assignment',
     r'(?i)(?:api[_-]?key|apikey|api_secret|api_token)\s*[=:]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
     'high', 'CWE-798')
_add('Generic Secret Assignment',
     r'(?i)(?:secret|private[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_/+=-]{20,}["\']?',
     'high', 'CWE-798')
_add('OAuth Token in URL',
     r'(?:access_token|token)=[A-Za-z0-9_.-]{20,}',
     'high', 'CWE-598', 'OAuth token in URL query parameter')
_add('Webhook URL Pattern',
     r'https://[^\s"\'<>]+/(?:webhook|hook|callback|notify)[^\s"\'<>]*',
     'low', 'CWE-200')
_add('GraphQL Introspection Enabled',
     r'"__schema"\s*:\s*\{',
     'medium', 'CWE-200', 'GraphQL introspection is enabled — reveals full API schema')
_add('Swagger/OpenAPI Spec',
     r'"(?:swagger|openapi)"\s*:\s*"[23]\.',
     'info', 'CWE-200', 'Swagger/OpenAPI specification exposed')

# ══════════════════════════════════════════════════════════════════════════════
# 15. Cloud Metadata  (4 patterns)
# ══════════════════════════════════════════════════════════════════════════════
_add('AWS Metadata Endpoint',
     r'169\.254\.169\.254',
     'info', 'CWE-918', 'Cloud metadata IP referenced')
_add('GCP Metadata Endpoint',
     r'metadata\.google\.internal',
     'info', 'CWE-918')
_add('Azure Metadata Endpoint',
     r'169\.254\.169\.254.*?Metadata:\s*true',
     'info', 'CWE-918', flags=re.IGNORECASE)
_add('DigitalOcean Metadata',
     r'169\.254\.169\.254/metadata',
     'info', 'CWE-918')


# ══════════════════════════════════════════════════════════════════════════════
# Convenience lookup
# ══════════════════════════════════════════════════════════════════════════════
PATTERN_COUNT = len(SECRET_PATTERNS)

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def get_patterns_by_severity(severity: str) -> list[dict]:
    """Return patterns filtered by severity level."""
    return [p for p in SECRET_PATTERNS if p['severity'] == severity]


def get_critical_patterns() -> list[dict]:
    """Return only critical-severity patterns."""
    return get_patterns_by_severity('critical')
