"""
Technology Fingerprinting Module — Detect web technologies.

Identifies: CMS, frameworks, JS libraries, server software,
CDNs, analytics, security products, e-commerce platforms,
CI/CD tools, databases, PaaS indicators, and AI/ML stacks
from headers, HTML patterns, cookies, JavaScript globals,
URL path patterns, and script filename version extraction.

Loads 728+ technology signatures from ``data/tech_signatures.json``
(3000+ individual detection patterns) and falls back to the built-in
tuples if the data file is absent.
"""
import re
import logging
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    load_json_data,
)

logger = logging.getLogger(__name__)

# ── Built-in signatures (legacy fallback) ──────────────────────────────────

# Header-based fingerprints: (header, pattern, tech_name, category)
HEADER_FINGERPRINTS = [
    ('Server', r'Apache', 'Apache', 'Web Server'),
    ('Server', r'nginx', 'Nginx', 'Web Server'),
    ('Server', r'Microsoft-IIS', 'IIS', 'Web Server'),
    ('Server', r'LiteSpeed', 'LiteSpeed', 'Web Server'),
    ('Server', r'Caddy', 'Caddy', 'Web Server'),
    ('Server', r'Cloudflare', 'Cloudflare', 'CDN/WAF'),
    ('X-Powered-By', r'PHP', 'PHP', 'Language'),
    ('X-Powered-By', r'ASP\.NET', 'ASP.NET', 'Framework'),
    ('X-Powered-By', r'Express', 'Express.js', 'Framework'),
    ('X-Powered-By', r'Next\.js', 'Next.js', 'Framework'),
    ('X-Powered-By', r'Phusion Passenger', 'Passenger', 'App Server'),
    ('X-AspNet-Version', r'.+', 'ASP.NET', 'Framework'),
    ('X-AspNetMvc-Version', r'.+', 'ASP.NET MVC', 'Framework'),
    ('X-Drupal-Cache', r'.+', 'Drupal', 'CMS'),
    ('X-Generator', r'Drupal', 'Drupal', 'CMS'),
    ('X-Generator', r'WordPress', 'WordPress', 'CMS'),
    ('X-Powered-CMS', r'.+', None, 'CMS'),
    ('X-Varnish', r'.+', 'Varnish', 'Cache'),
    ('X-Cache', r'HIT|MISS', None, 'Cache'),
    ('CF-Cache-Status', r'.+', 'Cloudflare', 'CDN'),
    ('X-CDN', r'.+', None, 'CDN'),
    ('X-Fastly-Request-ID', r'.+', 'Fastly', 'CDN'),
    ('X-Served-By', r'cache-', 'Fastly', 'CDN'),
    ('X-Amz-Cf-Id', r'.+', 'CloudFront', 'CDN'),
    ('X-Azure-Ref', r'.+', 'Azure CDN', 'CDN'),

    # Additional Web Servers & Proxies
    ('Server', r'Tengine', 'Tengine', 'Web Server'),
    ('Server', r'openresty', 'OpenResty', 'Web Server'),
    ('Server', r'Cowboy', 'Cowboy (Erlang)', 'Web Server'),
    ('Server', r'Kestrel', 'Kestrel', 'Web Server'),
    ('Server', r'gunicorn', 'Gunicorn', 'Web Server'),
    ('Server', r'Werkzeug', 'Werkzeug', 'Web Server'),
    ('Server', r'Jetty', 'Jetty', 'Web Server'),
    ('Server', r'WildFly', 'WildFly', 'App Server'),
    ('Server', r'GlassFish', 'GlassFish', 'App Server'),
    ('Server', r'Tomcat', 'Apache Tomcat', 'App Server'),

    # Frameworks
    ('X-Powered-By', r'Nuxt', 'Nuxt.js', 'Framework'),
    ('X-Powered-By', r'Remix', 'Remix', 'Framework'),
    ('X-Powered-By', r'Hapi', 'Hapi.js', 'Framework'),
    ('X-Powered-By', r'Koa', 'Koa.js', 'Framework'),
    ('X-Powered-By', r'Sails', 'Sails.js', 'Framework'),
    ('X-Powered-By', r'AdonisJS', 'AdonisJS', 'Framework'),
    ('X-Runtime', r'.+', 'Ruby on Rails', 'Framework'),
    ('X-Request-Id', r'.+', None, 'Framework'),
    ('X-Rack-Cache', r'.+', 'Rack (Ruby)', 'Framework'),
    ('X-Django-Request-Id', r'.+', 'Django', 'Framework'),
    ('X-Turbo-Charged-By', r'.+', 'LiteSpeed', 'Web Server'),

    # CMS (extra)
    ('X-Shopify-Stage', r'.+', 'Shopify', 'E-commerce'),
    ('X-WP-Total', r'.+', 'WordPress REST API', 'CMS'),
    ('X-Craft-Powered-By', r'.+', 'Craft CMS', 'CMS'),
    ('X-Ghost-Cache-Status', r'.+', 'Ghost', 'CMS'),
    ('X-Wix-Request-Id', r'.+', 'Wix', 'CMS'),
    ('X-Squarespace-', r'.+', 'Squarespace', 'CMS'),

    # Hosting / PaaS
    ('X-Render-Origin-Server', r'.+', 'Render', 'PaaS'),
    ('Fly-Request-Id', r'.+', 'Fly.io', 'PaaS'),
    ('X-Railway-Request-Id', r'.+', 'Railway', 'PaaS'),
    ('X-Heroku-Request-Id', r'.+', 'Heroku', 'PaaS'),
    ('X-Now-Id', r'.+', 'Vercel', 'PaaS'),

    # Security headers
    ('X-XSS-Protection', r'.+', None, 'Security Header'),
    ('X-Content-Type-Options', r'nosniff', None, 'Security Header'),
    ('Strict-Transport-Security', r'.+', None, 'Security Header'),
    ('Content-Security-Policy', r'.+', None, 'Security Header'),
    ('X-Frame-Options', r'.+', None, 'Security Header'),
    ('Permissions-Policy', r'.+', None, 'Security Header'),
    ('X-Sucuri-ID', r'.+', 'Sucuri WAF', 'WAF'),
    ('X-SiteGround-Optimizer', r'.+', 'SiteGround', 'Hosting'),

    # AI/ML Framework Headers
    ('X-OpenAI-Model', r'.+', 'OpenAI', 'AI Framework'),
    ('X-OpenAI-Version', r'.+', 'OpenAI', 'AI Framework'),
    ('Openai-Organization', r'.+', 'OpenAI', 'AI Framework'),
    ('X-Ratelimit-Limit-Tokens', r'.+', 'OpenAI-style API', 'AI Framework'),
    ('X-Request-Id', r'chatcmpl-|cmpl-', 'OpenAI', 'AI Framework'),
    ('Ollama-Version', r'.+', 'Ollama', 'AI Framework'),
    ('X-Inference-Time', r'.+', None, 'AI/ML'),
    ('X-Model-Version', r'.+', None, 'AI/ML'),
    ('X-Prediction-Time', r'.+', None, 'AI/ML'),
    ('X-LiteLLM-Version', r'.+', 'LiteLLM', 'AI Framework'),
    ('Server', r'uvicorn|starlette|fastapi', 'FastAPI/Starlette', 'AI Framework'),
    ('Server', r'TorchServe', 'TorchServe', 'AI/ML'),
    ('Server', r'triton', 'Triton Inference Server', 'AI/ML'),
    ('X-Gradio-Version', r'.+', 'Gradio', 'AI Framework'),
    ('X-Streamlit-Version', r'.+', 'Streamlit', 'AI Framework'),
]

# HTML meta/content patterns: (pattern, tech_name, category)
HTML_FINGERPRINTS = [
    # CMS
    (r'<meta\s+name="generator"\s+content="WordPress\s*([\d.]*)"', 'WordPress', 'CMS'),
    (r'<meta\s+name="generator"\s+content="Drupal\s*([\d.]*)"', 'Drupal', 'CMS'),
    (r'<meta\s+name="generator"\s+content="Joomla!\s*([\d.]*)"', 'Joomla', 'CMS'),
    (r'wp-content/', 'WordPress', 'CMS'),
    (r'wp-includes/', 'WordPress', 'CMS'),
    (r'/sites/default/files/', 'Drupal', 'CMS'),
    (r'Powered by <a[^>]*>Shopify</a>', 'Shopify', 'E-commerce'),
    (r'/cdn\.shopify\.com/', 'Shopify', 'E-commerce'),
    (r'WooCommerce', 'WooCommerce', 'E-commerce'),
    (r'Magento', 'Magento', 'E-commerce'),

    # JavaScript frameworks
    (r'react(?:\.production|\.development|DOM)', 'React', 'JS Framework'),
    (r'__NEXT_DATA__', 'Next.js', 'JS Framework'),
    (r'__NUXT__', 'Nuxt.js', 'JS Framework'),
    (r'ng-app|ng-controller|angular', 'Angular', 'JS Framework'),
    (r'Vue\.js|v-app|v-bind', 'Vue.js', 'JS Framework'),
    (r'svelte', 'Svelte', 'JS Framework'),
    (r'ember', 'Ember.js', 'JS Framework'),
    (r'backbone', 'Backbone.js', 'JS Library'),

    # JS Libraries
    (r'jquery[.-](\d+\.\d+)', 'jQuery', 'JS Library'),
    (r'bootstrap[.-](\d+\.\d+)', 'Bootstrap', 'CSS Framework'),
    (r'tailwindcss|tailwind\.', 'Tailwind CSS', 'CSS Framework'),

    # Analytics & Marketing
    (r'google-analytics\.com|gtag|ga\.js|analytics\.js', 'Google Analytics', 'Analytics'),
    (r'googletagmanager\.com', 'Google Tag Manager', 'Analytics'),
    (r'hotjar\.com|_hjSettings', 'Hotjar', 'Analytics'),
    (r'segment\.com|analytics\.min\.js', 'Segment', 'Analytics'),
    (r'facebook\.net/|fbevents\.js', 'Facebook Pixel', 'Analytics'),
    (r'intercom', 'Intercom', 'Customer Support'),
    (r'zendesk', 'Zendesk', 'Customer Support'),
    (r'crisp\.chat', 'Crisp', 'Customer Support'),

    # Security
    (r'recaptcha', 'reCAPTCHA', 'Security'),
    (r'hcaptcha', 'hCaptcha', 'Security'),
    (r'cloudflare', 'Cloudflare', 'CDN/WAF'),

    # Build tools
    (r'webpack', 'Webpack', 'Build Tool'),
    (r'vite', 'Vite', 'Build Tool'),

    # AI/ML Framework HTML Patterns
    (r'gradio|gr\.Interface|gr\.Blocks|gradio-app', 'Gradio', 'AI Framework'),
    (r'streamlit|st\.write|stApp|_stcore', 'Streamlit', 'AI Framework'),
    (r'chainlit|cl\.on_message', 'Chainlit', 'AI Framework'),
    (r'langserve|langchain|/invoke|/stream', 'LangChain/LangServe', 'AI Framework'),
    (r'openai|chatgpt|gpt-[34]|chat/completions', 'OpenAI Integration', 'AI Framework'),
    (r'huggingface|transformers|hf\.space|spaces\.huggingface', 'Hugging Face', 'AI Framework'),
    (r'ollama|llama\.cpp', 'Ollama/llama.cpp', 'AI Framework'),
    (r'llamaindex|llama_index', 'LlamaIndex', 'AI Framework'),
    (r'tensorflow\.js|tf\.js|tfjs', 'TensorFlow.js', 'AI/ML'),
    (r'onnxruntime|onnx\.js', 'ONNX Runtime', 'AI/ML'),
    (r'ml5\.js|ml5', 'ml5.js', 'AI/ML'),
    (r'brain\.js', 'Brain.js', 'AI/ML'),
    (r'FastAPI|fastapi', 'FastAPI', 'AI Framework'),
    (r'swagger.*openapi|/docs#|/redoc', 'API Documentation', 'API'),
    (r'/v1/models|/v1/chat|/api/generate', 'LLM API Endpoint', 'AI Framework'),

    # Additional CMS
    (r'ghost|/ghost/api', 'Ghost', 'CMS'),
    (r'squarespace|sqsp', 'Squarespace', 'CMS'),
    (r'wix\.com|wixstatic', 'Wix', 'CMS'),
    (r'weebly\.com', 'Weebly', 'CMS'),
    (r'webflow\.com', 'Webflow', 'CMS'),
    (r'hubspot|hs-scripts', 'HubSpot', 'CMS'),
    (r'contentful', 'Contentful', 'Headless CMS'),
    (r'prismic', 'Prismic', 'Headless CMS'),
    (r'strapi', 'Strapi', 'Headless CMS'),
    (r'sanity\.io|sanity-', 'Sanity', 'Headless CMS'),
    (r'typo3', 'TYPO3', 'CMS'),
    (r'craft\-cms|craftcms', 'Craft CMS', 'CMS'),
    (r'kentico', 'Kentico', 'CMS'),
    (r'sitecore', 'Sitecore', 'CMS'),

    # Additional E-commerce
    (r'bigcommerce', 'BigCommerce', 'E-commerce'),
    (r'prestashop', 'PrestaShop', 'E-commerce'),
    (r'opencart', 'OpenCart', 'E-commerce'),
    (r'nopcommerce', 'nopCommerce', 'E-commerce'),
    (r'medusa-js|medusajs', 'Medusa', 'E-commerce'),
    (r'saleor', 'Saleor', 'E-commerce'),

    # Frontend frameworks (extra)
    (r'remix-run|__remix', 'Remix', 'JS Framework'),
    (r'astro', 'Astro', 'JS Framework'),
    (r'solid-js|solidjs', 'Solid.js', 'JS Framework'),
    (r'qwik|qwik-city', 'Qwik', 'JS Framework'),
    (r'preact', 'Preact', 'JS Framework'),
    (r'alpinejs|x-data', 'Alpine.js', 'JS Framework'),
    (r'htmx', 'HTMX', 'JS Library'),
    (r'stimulus|data-controller', 'Stimulus', 'JS Library'),
    (r'turbo-frame|turbolinks', 'Hotwire Turbo', 'JS Library'),
    (r'lit-element|lit-html', 'Lit', 'JS Library'),

    # CSS Frameworks (extra)
    (r'bulma', 'Bulma', 'CSS Framework'),
    (r'foundation[-.]', 'Foundation', 'CSS Framework'),
    (r'materialize', 'Materialize', 'CSS Framework'),
    (r'chakra-ui', 'Chakra UI', 'CSS Framework'),
    (r'ant-design|antd', 'Ant Design', 'CSS Framework'),
    (r'mantine', 'Mantine', 'CSS Framework'),

    # Analytics (extra)
    (r'plausible\.io', 'Plausible Analytics', 'Analytics'),
    (r'matomo|piwik', 'Matomo', 'Analytics'),
    (r'fathom', 'Fathom Analytics', 'Analytics'),
    (r'mixpanel', 'Mixpanel', 'Analytics'),
    (r'amplitude', 'Amplitude', 'Analytics'),
    (r'heap\.io|heap-', 'Heap', 'Analytics'),
    (r'posthog', 'PostHog', 'Analytics'),
    (r'clarity\.ms', 'Microsoft Clarity', 'Analytics'),
    (r'sentry\.io|sentry-', 'Sentry', 'Error Tracking'),
    (r'datadog', 'Datadog', 'Observability'),
    (r'newrelic|new-relic', 'New Relic', 'Observability'),
    (r'logrocket', 'LogRocket', 'Observability'),

    # Security (extra)
    (r'turnstile\.cloudflare', 'Cloudflare Turnstile', 'Security'),
    (r'datadome', 'DataDome', 'Bot Protection'),
    (r'perimeterx|px-captcha', 'PerimeterX', 'Bot Protection'),
    (r'akamai-bm', 'Akamai Bot Manager', 'Bot Protection'),

    # Payment
    (r'stripe\.js|js\.stripe', 'Stripe', 'Payment'),
    (r'paypal\.com/sdk', 'PayPal', 'Payment'),
    (r'braintree', 'Braintree', 'Payment'),
    (r'adyen', 'Adyen', 'Payment'),
    (r'square.*web-sdk', 'Square', 'Payment'),

    # Maps / Media
    (r'maps\.googleapis|google\.maps', 'Google Maps', 'Maps'),
    (r'mapbox', 'Mapbox', 'Maps'),
    (r'leaflet', 'Leaflet', 'Maps'),
    (r'youtube\.com/embed|youtube-nocookie', 'YouTube Embed', 'Media'),
    (r'player\.vimeo', 'Vimeo Embed', 'Media'),
]

# Cookie-based fingerprints: (cookie_name_pattern, tech, category)
COOKIE_FINGERPRINTS = [
    (r'PHPSESSID', 'PHP', 'Language'),
    (r'JSESSIONID', 'Java', 'Language'),
    (r'ASP\.NET_SessionId', 'ASP.NET', 'Framework'),
    (r'csrftoken', 'Django', 'Framework'),
    (r'_rails_session', 'Ruby on Rails', 'Framework'),
    (r'ci_session', 'CodeIgniter', 'Framework'),
    (r'laravel_session', 'Laravel', 'Framework'),
    (r'connect\.sid', 'Express.js', 'Framework'),
    (r'__cfduid|__cf_bm', 'Cloudflare', 'CDN/WAF'),
    (r'wp-settings', 'WordPress', 'CMS'),
    (r'_shopify', 'Shopify', 'E-commerce'),

    # AI/ML Sessions
    (r'gradio_session', 'Gradio', 'AI Framework'),
    (r'streamlit', 'Streamlit', 'AI Framework'),
    (r'chainlit', 'Chainlit', 'AI Framework'),
    (r'openai_session|oai-', 'OpenAI', 'AI Framework'),
    (r'hf_session|huggingface', 'Hugging Face', 'AI Framework'),

    # E-commerce sessions
    (r'Magento', 'Magento', 'E-commerce'),
    (r'PrestaShop', 'PrestaShop', 'E-commerce'),
    (r'wc_session|woocommerce', 'WooCommerce', 'E-commerce'),
    (r'bigcommerce', 'BigCommerce', 'E-commerce'),

    # Platform sessions
    (r'_vercel_no_cache', 'Vercel', 'PaaS'),
    (r'_netlify', 'Netlify', 'PaaS'),
    (r'heroku-session', 'Heroku', 'PaaS'),

    # Auth
    (r'auth0', 'Auth0', 'Authentication'),
    (r'cognito', 'AWS Cognito', 'Authentication'),
    (r'_clerk_', 'Clerk', 'Authentication'),
    (r'supabase', 'Supabase', 'BaaS'),
    (r'appwrite', 'Appwrite', 'BaaS'),
]

# JavaScript global variable fingerprints: (js_global_regex, tech, category)
# Matched against HTML body for window.X or globalThis.X patterns
JS_GLOBAL_FINGERPRINTS = [
    # Frontend Frameworks
    (r'window\.React\b|ReactDOM\.render|React\.createElement', 'React', 'JS Framework'),
    (r'window\.__vue__|window\.Vue\b|new Vue\(', 'Vue.js', 'JS Framework'),
    (r'window\.angular\b|window\.ng\b|angular\.module\(', 'Angular', 'JS Framework'),
    (r'window\.svelte\b|SvelteComponent', 'Svelte', 'JS Framework'),
    (r'window\.Ember\b|window\.Em\b|Ember\.Application', 'Ember.js', 'JS Framework'),
    (r'window\.__NEXT_DATA__\b|window\.next\b|__NEXT_REDUX_STORE__', 'Next.js', 'JS Framework'),
    (r'window\.__NUXT__\b|__nuxt_', 'Nuxt.js', 'JS Framework'),
    (r'window\.___gatsby\b|window\.gatsby\b|__gatsby', 'Gatsby', 'JS Framework'),
    (r'window\.__REMIX_MANIFEST__\b|window\.__remixContext', 'Remix', 'JS Framework'),
    (r'window\.__sveltekit\b|sveltekit:data', 'SvelteKit', 'JS Framework'),
    (r'window\.__astro\b|AstroIslands', 'Astro', 'JS Framework'),
    (r'window\.__blitz', 'Blitz.js', 'JS Framework'),
    (r'window\.__REDWOOD__\b', 'RedwoodJS', 'JS Framework'),
    (r'window\.Alpine\b|Alpine\.start\(', 'Alpine.js', 'JS Framework'),
    (r'window\.htmx\b|htmx\.process\(', 'HTMX', 'JS Library'),
    (r'window\.Stimulus\b|Stimulus\.Application', 'Stimulus', 'JS Library'),
    (r'window\.Turbo\b|Turbo\.visit\(', 'Hotwire Turbo', 'JS Library'),
    # JS Libraries
    (r'window\.jQuery\b|window\.\$\.fn\.jquery\b', 'jQuery', 'JS Library'),
    (r'window\._\b.*underscore|window\.Underscore\b', 'Underscore.js', 'JS Library'),
    (r'window\._\b.*lodash|_\.VERSION\s*=', 'Lodash', 'JS Library'),
    (r'window\.Backbone\b|Backbone\.View\.extend', 'Backbone.js', 'JS Library'),
    (r'window\.moment\b|moment\.version\b', 'Moment.js', 'JS Library'),
    (r'window\.dayjs\b|dayjs\.extend\(', 'Day.js', 'JS Library'),
    (r'window\.axios\b|axios\.get\(', 'Axios', 'JS Library'),
    (r'window\.d3\b|d3\.version\b', 'D3.js', 'JS Library'),
    (r'window\.Chart\b|Chart\.defaults\b', 'Chart.js', 'JS Library'),
    (r'window\.Highcharts\b|Highcharts\.chart\(', 'Highcharts', 'JS Library'),
    (r'window\.ApexCharts\b|ApexCharts\.exec\(', 'ApexCharts', 'JS Library'),
    (r'window\.echarts\b|echarts\.init\(', 'ECharts', 'JS Library'),
    (r'window\.THREE\b|THREE\.Scene\b', 'Three.js', 'JS Library'),
    (r'window\.gsap\b|gsap\.to\(|gsap\.timeline\(', 'GSAP', 'JS Library'),
    (r'window\.Lottie\b|lottie\.loadAnimation\(', 'Lottie', 'JS Library'),
    (r'window\.Swiper\b|new Swiper\(', 'Swiper', 'JS Library'),
    (r'window\.Splide\b|new Splide\(', 'Splide', 'JS Library'),
    (r'window\.PhotoSwipe\b|new PhotoSwipe\(', 'PhotoSwipe', 'JS Library'),
    (r'window\.Sortable\b|Sortable\.create\(', 'Sortable.js', 'JS Library'),
    (r'window\.Masonry\b|new Masonry\(', 'Masonry', 'JS Library'),
    (r'window\.Isotope\b|new Isotope\(', 'Isotope', 'JS Library'),
    (r'window\.DataTable\b|\.DataTable\(\)', 'DataTables', 'JS Library'),
    (r'window\.agGrid\b|AgGrid\.createGrid', 'AG Grid', 'JS Library'),
    (r'window\.Quill\b|new Quill\(', 'Quill', 'JS Library'),
    (r'window\.tinymce\b|tinymce\.init\(', 'TinyMCE', 'JS Library'),
    (r'window\.CKEDITOR\b|ClassicEditor\.create\(', 'CKEditor', 'JS Library'),
    (r'window\.CodeMirror\b|CodeMirror\.fromTextArea\(', 'CodeMirror', 'JS Library'),
    (r'window\.monaco\b|monaco\.editor\.create\(', 'Monaco Editor', 'JS Library'),
    (r'window\.flatpickr\b|flatpickr\(', 'Flatpickr', 'JS Library'),
    (r'window\.Hammer\b|new Hammer\(', 'Hammer.js', 'JS Library'),
    (r'window\.Howler\b|new Howl\(', 'Howler.js', 'JS Library'),
    (r'window\.Tone\b|Tone\.start\(\)', 'Tone.js', 'JS Library'),
    (r'window\.jsPDF\b|new jsPDF\(', 'jsPDF', 'JS Library'),
    (r'window\.XLSX\b|XLSX\.read\(', 'SheetJS', 'JS Library'),
    (r'window\.pdfjsLib\b|pdfjsLib\.getDocument\(', 'pdf.js', 'JS Library'),
    (r'window\.Fuse\b|new Fuse\(', 'Fuse.js', 'JS Library'),
    (r'window\.lunr\b|lunr\.Index', 'Lunr', 'JS Library'),
    (r'window\.tippy\b|tippy\(\[', 'Tippy.js', 'JS Library'),
    (r'window\.SweetAlert\b|Swal\.fire\(', 'SweetAlert2', 'JS Library'),
    (r'window\.Shepherd\b|new Shepherd\.Tour', 'Shepherd.js', 'JS Library'),
    (r'window\.introJs\b|introJs\(\)', 'Intro.js', 'JS Library'),
    # State Management
    (r'window\.__REDUX_DEVTOOLS_EXTENSION__\b', 'Redux', 'JS Library'),
    (r'window\.__mobxDidRunLazyInitializersForWrappers\b|mobx\.observable', 'MobX', 'JS Library'),
    (r'window\.__APOLLO_CLIENT__\b|window\.__APOLLO_STATE__\b', 'Apollo GraphQL', 'API'),
    # CMS-specific globals
    (r'window\._wpemojiSettings\b|window\.wp\b|wpApiSettings', 'WordPress', 'CMS'),
    (r'window\.woocommerce_params\b|window\.wc\b', 'WooCommerce', 'E-commerce'),
    (r'window\.drupalSettings\b|window\.Drupal\b', 'Drupal', 'CMS'),
    (r'window\.Shopify\b|window\.theme\b.*myshopify|ShopifyBuy\.buildClient', 'Shopify', 'E-commerce'),
    (r'window\.mage\b|window\.require.*Magento|window\.Mage\b', 'Magento', 'E-commerce'),
    (r'window\.prestashop\b|window\.PSModales', 'PrestaShop', 'E-commerce'),
    (r'window\.Ecwid\b|Ecwid\.init\(', 'Ecwid', 'E-commerce'),
    # Analytics globals
    (r'window\.ga\b|window\.gtag\b|window\.dataLayer\b', 'Google Analytics', 'Analytics'),
    (r'window\.mixpanel\b|mixpanel\.track\(', 'Mixpanel', 'Analytics'),
    (r'window\.amplitude\b|amplitude\.getInstance\(', 'Amplitude', 'Analytics'),
    (r'window\.posthog\b|posthog\.capture\(', 'PostHog', 'Analytics'),
    (r'window\.heap\b|heap\.track\(', 'Heap', 'Analytics'),
    (r'window\.hj\b|window\.hjSiteSettings\b', 'Hotjar', 'Analytics'),
    (r'window\._paq\b|Matomo', 'Matomo', 'Analytics'),
    (r'window\.fbq\b|fbq\(\'track\'', 'Facebook Pixel', 'Analytics'),
    (r'window\.ttq\b|ttq\.track\(', 'TikTok Pixel', 'Analytics'),
    (r'window\.pintrk\b|pintrk\(\'track\'', 'Pinterest Pixel', 'Analytics'),
    (r'window\.twq\b|twq\(\'track\'', 'Twitter Pixel', 'Analytics'),
    (r'window\.FS\b|FS\.identify\(', 'FullStory', 'Analytics'),
    (r'window\._lr\b|LogRocket\.init\(', 'LogRocket', 'Analytics'),
    (r'window\.DD_RUM\b|datadogRum\.init\(', 'Datadog RUM', 'Analytics'),
    (r'window\.newrelic\b|newrelic\.noticeError\(', 'New Relic', 'Analytics'),
    (r'window\.Sentry\b|Sentry\.init\(', 'Sentry', 'Error Tracking'),
    (r'window\.Bugsnag\b|Bugsnag\.notify\(', 'Bugsnag', 'Error Tracking'),
    (r'window\.Rollbar\b|Rollbar\.error\(', 'Rollbar', 'Error Tracking'),
    # Support widget globals
    (r'window\.Intercom\b|Intercom\(\'boot\'', 'Intercom', 'Customer Support'),
    (r'window\.HubSpotConversations\b|HubSpotConversations\.openHandler', 'HubSpot', 'CMS'),
    (r'window\.zE\b|zE\(\'messenger\'', 'Zendesk', 'Customer Support'),
    (r'window\.Drift\b|drift\.load\(', 'Drift', 'Customer Support'),
    (r'window\.\$crisp\b|CRISP_WEBSITE_ID', 'Crisp', 'Customer Support'),
    (r'window\.Tawk_API\b|Tawk_LoadStart', 'Tawk.to', 'Customer Support'),
    (r'window\.LiveChatWidget\b|LC_API\b', 'LiveChat', 'Customer Support'),
    (r'window\.FreshworksWidget\b|FreshChat', 'Freshchat', 'Customer Support'),
    # Auth globals
    (r'window\.google\b.*accounts|google\.accounts\.id\.initialize', 'Google OAuth', 'Authentication'),
    (r'window\.FB\b.*FB\.getLoginStatus|FB\.init\(', 'Facebook Login', 'Authentication'),
    (r'window\.msalInstance\b|Msal\.UserAgentApplication', 'Microsoft OAuth', 'Authentication'),
    (r'window\.auth0\b|new auth0\.WebAuth\(', 'Auth0', 'Authentication'),
    # Payment globals
    (r'window\.Stripe\b|Stripe\(\'pk_', 'Stripe', 'Payment'),
    (r'window\.braintree\b|braintree\.dropin\.create\(', 'Braintree', 'Payment'),
    (r'window\.AdyenCheckout\b|new AdyenCheckout\(', 'Adyen', 'Payment'),
    (r'window\.Paddle\b|Paddle\.Setup\(', 'Paddle', 'Payment'),
    (r'window\.paypal\b|paypal\.Buttons\(\)', 'PayPal', 'Payment'),
    # AI framework globals
    (r'window\.gradio_config\b|gradio_client', 'Gradio', 'AI Framework'),
    (r'window\.streamlit_config\b|_stcore', 'Streamlit', 'AI Framework'),
    (r'window\.openai\b|openai\.chat\.completions', 'OpenAI Integration', 'AI Framework'),
    # Cookie consent globals
    (r'window\.OneTrust\b|OneTrust\.LoadBanner\(', 'OneTrust', 'Cookie Consent'),
    (r'window\.Cookiebot\b|CookieConsent\.accept\(', 'Cookiebot', 'Cookie Consent'),
    # Feature flag globals
    (r'window\.ldclient\b|LDClient\.init\(|LaunchDarkly', 'LaunchDarkly', 'Feature Flags'),
    (r'window\.Statsig\b|Statsig\.initialize\(', 'Statsig', 'Feature Flags'),
]

# URL path patterns: (path_regex, tech, category)
# Matched against the target URL path/query
URL_PATH_FINGERPRINTS = [
    # WordPress
    (r'/wp-admin/', 'WordPress', 'CMS'),
    (r'/wp-login\.php', 'WordPress', 'CMS'),
    (r'/wp-content/', 'WordPress', 'CMS'),
    (r'/wp-includes/', 'WordPress', 'CMS'),
    (r'/wp-json/', 'WordPress REST API', 'CMS'),
    (r'\?rest_route=', 'WordPress REST API', 'CMS'),
    # Joomla
    (r'/administrator/', 'Joomla', 'CMS'),
    (r'/index\.php\?option=com_', 'Joomla', 'CMS'),
    (r'/components/com_', 'Joomla', 'CMS'),
    # Drupal
    (r'/sites/default/files/', 'Drupal', 'CMS'),
    (r'/core/misc/', 'Drupal', 'CMS'),
    (r'/core/themes/', 'Drupal', 'CMS'),
    (r'/node/\d+', 'Drupal', 'CMS'),
    (r'\?q=node/', 'Drupal', 'CMS'),
    # TYPO3
    (r'/typo3/', 'TYPO3', 'CMS'),
    (r'/typo3temp/', 'TYPO3', 'CMS'),
    (r'/fileadmin/', 'TYPO3', 'CMS'),
    # Umbraco
    (r'/umbraco/', 'Umbraco', 'CMS'),
    (r'/umbraco/api/', 'Umbraco', 'CMS'),
    # Sitecore
    (r'/sitecore/', 'Sitecore', 'CMS'),
    (r'/sitecore/login', 'Sitecore', 'CMS'),
    # DNN
    (r'/portals/\d+/', 'DNN / DotNetNuke', 'CMS'),
    # Ghost
    (r'/ghost/', 'Ghost', 'CMS'),
    (r'/ghost/api/', 'Ghost', 'CMS'),
    # Magento
    (r'/index\.php/catalog/', 'Magento', 'E-commerce'),
    (r'/media/catalog/', 'Magento', 'E-commerce'),
    (r'/skin/frontend/', 'Magento', 'E-commerce'),
    (r'/pub/static/', 'Magento', 'E-commerce'),
    # PrestaShop
    (r'/modules/bankwire/', 'PrestaShop', 'E-commerce'),
    (r'/modules/cheque/', 'PrestaShop', 'E-commerce'),
    (r'/themes/default-bootstrap/', 'PrestaShop', 'E-commerce'),
    # OpenCart
    (r'/catalog/view/theme/', 'OpenCart', 'E-commerce'),
    (r'/system/storage/', 'OpenCart', 'E-commerce'),
    # Laravel
    (r'/storage/framework/', 'Laravel', 'Framework'),
    (r'/vendor/autoload\.php', 'PHP/Laravel', 'Framework'),
    # Ruby on Rails
    (r'/rails/info/', 'Ruby on Rails', 'Framework'),
    (r'/rails/mailers/', 'Ruby on Rails', 'Framework'),
    # Django
    (r'/admin/', 'Django', 'Framework'),
    (r'/api/v1/', None, 'API'),
    (r'/api/v2/', None, 'API'),
    (r'/api/v3/', None, 'API'),
    # Next.js
    (r'/_next/static/', 'Next.js', 'JS Framework'),
    (r'/_next/image', 'Next.js', 'JS Framework'),
    (r'/api/auth/', 'NextAuth.js', 'Authentication'),
    # Nuxt.js
    (r'/_nuxt/', 'Nuxt.js', 'JS Framework'),
    # SvelteKit
    (r'/_app/immutable/', 'SvelteKit', 'JS Framework'),
    # Gatsby
    (r'/page-data/', 'Gatsby', 'JS Framework'),
    # Spring Boot Actuator
    (r'/actuator/', 'Spring Boot', 'Framework'),
    (r'/actuator/health', 'Spring Boot', 'Framework'),
    (r'/actuator/info', 'Spring Boot', 'Framework'),
    (r'/actuator/metrics', 'Spring Boot', 'Framework'),
    (r'/actuator/env', 'Spring Boot', 'Framework'),
    (r'/actuator/beans', 'Spring Boot', 'Framework'),
    (r'/actuator/configprops', 'Spring Boot', 'Framework'),
    (r'/h2-console', 'H2 Database', 'Database'),
    (r'/jolokia/', 'Jolokia', 'Framework'),
    # Debugging endpoints
    (r'/debug/pprof/', 'Go (pprof)', 'Language'),
    (r'/debug/vars', 'Go', 'Language'),
    (r'/debug/requests', 'Go', 'Language'),
    # API / GraphQL
    (r'/graphql', 'GraphQL', 'API'),
    (r'/v1/graphql', 'Hasura', 'API'),
    (r'/__graphql', 'GraphQL Playground', 'API'),
    (r'/swagger-ui\.html', 'Swagger/OpenAPI', 'API'),
    (r'/swagger-ui/', 'Swagger/OpenAPI', 'API'),
    (r'/api-docs', 'Swagger/OpenAPI', 'API'),
    (r'/redoc', 'ReDoc/OpenAPI', 'API'),
    (r'/openapi\.json', 'OpenAPI', 'API'),
    (r'/openapi\.yaml', 'OpenAPI', 'API'),
    # Python Frameworks
    (r'/__debug__/', 'Django Debug Toolbar', 'Framework'),
    (r'/docs#/', 'FastAPI', 'Framework'),
    (r'/redoc#/', 'FastAPI', 'Framework'),
    (r'/openapi\.json', 'FastAPI', 'Framework'),
    # Healthcheck (cloud-native)
    (r'^/health$', 'Cloud Native App', 'Cloud'),
    (r'^/ready$', 'Cloud Native App', 'Cloud'),
    (r'^/live$', 'Cloud Native App', 'Cloud'),
    (r'^/healthz$', 'Kubernetes App', 'Cloud'),
    (r'^/readyz$', 'Kubernetes App', 'Cloud'),
    (r'^/livez$', 'Kubernetes App', 'Cloud'),
    # PHPMyAdmin / database UIs
    (r'/phpmyadmin/', 'phpMyAdmin', 'Database'),
    (r'/phppgadmin/', 'phpPgAdmin', 'Database'),
    (r'/adminer\.php', 'Adminer', 'Database'),
    (r'/pgadmin/', 'pgAdmin', 'Database'),
    # AI / LLM endpoints
    (r'/v1/chat/completions', 'OpenAI-compatible API', 'AI Framework'),
    (r'/v1/completions', 'OpenAI-compatible API', 'AI Framework'),
    (r'/v1/embeddings', 'OpenAI-compatible API', 'AI Framework'),
    (r'/v1/models', 'OpenAI-compatible API', 'AI Framework'),
    (r'/api/generate', 'Ollama', 'AI Framework'),
    (r'/api/chat', 'Ollama', 'AI Framework'),
    (r'/api/tags', 'Ollama', 'AI Framework'),
    (r'/api/pull', 'Ollama', 'AI Framework'),
    (r'/invoke', 'LangChain/LangServe', 'AI Framework'),
    (r'/stream_events', 'LangChain/LangServe', 'AI Framework'),
    (r'/batch', 'LangChain/LangServe', 'AI Framework'),
    (r'/v1/collections', 'Chroma/Vector DB', 'AI Framework'),
    (r'/api/v1/collections', 'Chroma', 'AI Framework'),
    (r'/v1/schema', 'Weaviate', 'AI Framework'),
    (r'/v1/objects', 'Weaviate', 'AI Framework'),
    (r'/collections', 'Qdrant', 'AI Framework'),
    (r'/points', 'Qdrant', 'AI Framework'),
    (r'/mcp', 'MCP Server', 'AI Framework'),
    # Version control
    (r'/\.git/HEAD', 'Git Repository Exposed', 'Security'),
    (r'/\.env', 'Exposed .env File', 'Security'),
    (r'/\.git/config', 'Git Repository Exposed', 'Security'),
    # Well-known
    (r'/robots\.txt', None, 'Meta'),
    (r'/sitemap\.xml', None, 'Meta'),
    (r'/\.well-known/security\.txt', None, 'Security'),
    (r'/\.well-known/openid-configuration', 'OpenID Connect', 'Authentication'),
    # cPanel / Plesk
    (r':2082|:2083|/cpanel', 'cPanel', 'Hosting'),
    (r':8443|:8880|/plesk', 'Plesk', 'Hosting'),
    # Jenkins / CI
    (r'/jenkins/', 'Jenkins', 'CI/CD'),
    (r'/job/.*build', 'Jenkins', 'CI/CD'),
    # Sonar / monitoring
    (r'/sonarqube/', 'SonarQube', 'Dev Tool'),
    (r'/prometheus/metrics', 'Prometheus', 'Monitoring'),
    (r'/metrics', 'Prometheus', 'Monitoring'),
    (r'/grafana/', 'Grafana', 'Monitoring'),
]

# Script filename version extraction: (url_pattern_with_group, tech, category)
# Version is extracted from the first capture group
SCRIPT_VERSION_PATTERNS = [
    (r'jquery[.-](\d+\.\d+(?:\.\d+)?)', 'jQuery', 'JS Library'),
    (r'jquery\.min\.js\?ver=(\d+\.\d+(?:\.\d+)?)', 'jQuery', 'JS Library'),
    (r'bootstrap[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)', 'Bootstrap', 'CSS Framework'),
    (r'react[.-](\d+\.\d+(?:\.\d+)?)\.(?:development|production)\.min\.js', 'React', 'JS Framework'),
    (r'react-dom[.-](\d+\.\d+(?:\.\d+)?)\.', 'React', 'JS Framework'),
    (r'vue[.-](\d+\.\d+(?:\.\d+)?)(?:\.esm)?(?:\.min)?\.js', 'Vue.js', 'JS Framework'),
    (r'angular(?:\.min)?\.js\?v=(\d+\.\d+(?:\.\d+)?)', 'AngularJS', 'JS Framework'),
    (r'@angular/core@(\d+\.\d+(?:\.\d+)?)', 'Angular', 'JS Framework'),
    (r'lodash[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Lodash', 'JS Library'),
    (r'moment[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Moment.js', 'JS Library'),
    (r'axios[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Axios', 'JS Library'),
    (r'd3[.-]v?(\d+)(?:\.\d+(?:\.\d+)?)?(?:\.min)?\.js', 'D3.js', 'JS Library'),
    (r'chart\.js@(\d+\.\d+(?:\.\d+)?)', 'Chart.js', 'JS Library'),
    (r'three[.-]r?(\d+)(?:\.\d+)?(?:\.min)?\.js', 'Three.js', 'JS Library'),
    (r'gsap[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'GSAP', 'JS Library'),
    (r'swiper[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?(?:\.js|\.css)', 'Swiper', 'JS Library'),
    (r'tailwindcss@(\d+\.\d+(?:\.\d+)?)', 'Tailwind CSS', 'CSS Framework'),
    (r'alpinejs@(\d+\.\d+(?:\.\d+)?)', 'Alpine.js', 'JS Framework'),
    (r'htmx@(\d+\.\d+(?:\.\d+)?)', 'HTMX', 'JS Library'),
    (r'lit[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Lit', 'JS Library'),
    (r'ember[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Ember.js', 'JS Framework'),
    (r'backbone[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Backbone.js', 'JS Library'),
    (r'knockout-(\d+\.\d+(?:\.\d+)?)(?:\.debug|\.min)?\.js', 'Knockout.js', 'JS Framework'),
    (r'mithril@(\d+\.\d+(?:\.\d+)?)', 'Mithril', 'JS Framework'),
    (r'solid-js@(\d+\.\d+(?:\.\d+)?)', 'Solid.js', 'JS Framework'),
    (r'svelte@(\d+\.\d+(?:\.\d+)?)', 'Svelte', 'JS Framework'),
    (r'framer-motion@(\d+\.\d+(?:\.\d+)?)', 'Framer Motion', 'JS Library'),
    (r'rxjs@(\d+\.\d+(?:\.\d+)?)', 'RxJS', 'JS Library'),
    (r'redux@(\d+\.\d+(?:\.\d+)?)', 'Redux', 'JS Library'),
    (r'mobx@(\d+\.\d+(?:\.\d+)?)', 'MobX', 'JS Library'),
    (r'zustand@(\d+\.\d+(?:\.\d+)?)', 'Zustand', 'JS Library'),
    (r'@tanstack/query-core@(\d+\.\d+(?:\.\d+)?)', 'TanStack Query', 'JS Library'),
    (r'socket\.io[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Socket.IO', 'JS Library'),
    (r'leaflet[.-](\d+\.\d+(?:\.\d+)?)(?:\.js|\.css)', 'Leaflet', 'Maps'),
    (r'mapbox-gl@(\d+\.\d+(?:\.\d+)?)', 'Mapbox', 'Maps'),
    (r'slick@(\d+\.\d+(?:\.\d+)?)', 'Slick', 'JS Library'),
    (r'select2[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Select2', 'JS Library'),
    (r'flatpickr[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Flatpickr', 'JS Library'),
    (r'quill[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Quill', 'JS Library'),
    (r'tinymce[.-]?(\d+(?:\.\d+)*)/?', 'TinyMCE', 'JS Library'),
    (r'sweetalert2@(\d+\.\d+(?:\.\d+)?)', 'SweetAlert2', 'JS Library'),
    (r'popper\.js@(\d+\.\d+(?:\.\d+)?)', 'Popper.js', 'JS Library'),
    (r'animate\.css@(\d+\.\d+(?:\.\d+)?)', 'Animate.css', 'CSS Framework'),
    (r'font-awesome@(\d+\.\d+(?:\.\d+)?)', 'Font Awesome', 'UI'),
    (r'bulma@(\d+\.\d+(?:\.\d+)?)', 'Bulma', 'CSS Framework'),
    (r'foundation@(\d+\.\d+(?:\.\d+)?)', 'Foundation', 'CSS Framework'),
    (r'materialize[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js', 'Materialize', 'CSS Framework'),
    (r'dexie@(\d+\.\d+(?:\.\d+)?)', 'Dexie.js', 'JS Library'),
    (r'workbox-sw@(\d+\.\d+(?:\.\d+)?)', 'Workbox', 'PWA'),
    (r'pwa-utils[.-](\d+)', 'PWA Library', 'PWA'),
]


# ── JSON signature loader ──────────────────────────────────────────────────

def _load_tech_json_signatures() -> list:
    """Return list of tech signature dicts from tech_signatures.json."""
    data = load_json_data('tech_signatures.json')
    if isinstance(data, dict) and 'technologies' in data:
        return data['technologies']
    return []


# ── Public API ─────────────────────────────────────────────────────────────

def run_tech_fingerprint(target_url: str, response_headers: dict = None,
                         response_body: str = '', cookies: dict = None) -> dict:
    """
    Perform technology fingerprinting.

    Args:
        target_url: The URL being analyzed
        response_headers: HTTP response headers (dict)
        response_body: HTML body content
        cookies: Response cookies dict

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        technologies, summary
    """
    start = time.time()
    result = create_result('tech_fingerprint', target_url)

    # ── Legacy keys ──
    result['technologies'] = []
    result['summary'] = {}

    seen: set = set()  # de-duplicate by "name:category"

    # Try JSON signatures first, fall back to built-in tuples
    json_sigs = _load_tech_json_signatures()

    if json_sigs:
        _match_json_signatures(json_sigs, response_headers or {},
                               response_body, cookies or {}, seen, result)
    else:
        _match_builtin_signatures(response_headers or {},
                                  response_body, cookies or {}, seen, result)

    # Additional detection passes (always run)
    if response_body:
        _match_js_globals(response_body, seen, result)
        _extract_script_versions(response_body, seen, result)
    _match_url_patterns(target_url or '', seen, result)

    # Build summary
    for tech in result['technologies']:
        cat = tech['category']
        if cat not in result['summary']:
            result['summary'][cat] = []
        entry = tech['name']
        if tech.get('version'):
            entry += f' {tech["version"]}'
        result['summary'][cat].append(entry)

    # Add findings
    for tech in result['technologies']:
        add_finding(result, {
            'type': 'technology_detected',
            'name': tech['name'],
            'category': tech['category'],
            'version': tech.get('version'),
            'confidence': tech['confidence'],
            'source': tech.get('source', ''),
        })

    return finalize_result(result, start)


# ── Matching engines ───────────────────────────────────────────────────────

def _match_json_signatures(sigs: list, headers: dict, body: str,
                           cookies: dict, seen: set, result: dict):
    """Match against the rich JSON-format signatures."""
    for sig in sigs:
        name = sig.get('name', 'Unknown')
        category = sig.get('category', 'Other')
        key = f'{name}:{category}'
        if key in seen:
            continue
        result['stats']['total_checks'] += 1

        detected = False
        confidence = 'low'
        source = ''
        version = None

        # 1. Header checks  {header_name: regex}
        for hdr_name, pattern in (sig.get('headers') or {}).items():
            for rh, rv in headers.items():
                if hdr_name.lower() == rh.lower():
                    m = re.search(pattern, rv, re.IGNORECASE)
                    if m:
                        detected = True
                        confidence = 'high'
                        source = f'Header: {rh}'
                        version = m.group(1) if m.lastindex else None

        # 2. Cookie checks  {cookie_name_substr: bool}
        for ck_name in (sig.get('cookies') or {}):
            for real_ck in cookies:
                if ck_name.lower() in real_ck.lower():
                    detected = True
                    confidence = 'high'
                    source = source or f'Cookie: {real_ck}'

        # 3. Meta tag checks  {name_attr: content_regex}
        for meta_name, meta_pat in (sig.get('meta') or {}).items():
            pat = rf'<meta\s+[^>]*name\s*=\s*["\']?{re.escape(meta_name)}["\']?\s+[^>]*content\s*=\s*["\']([^"\']*)["\']'
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                if re.search(meta_pat, m.group(1), re.IGNORECASE):
                    detected = True
                    confidence = 'high'
                    source = source or f'Meta: {meta_name}'
                    version = version or (m.group(1) if m.lastindex else None)

        # 4. Body pattern checks  [plain_string, ...]
        for bp in (sig.get('body') or []):
            if bp.lower() in body.lower():
                detected = True
                confidence = max(confidence, 'medium', key=_conf_rank)
                source = source or 'HTML content'

        # 5. Script src checks  [substring, ...]
        for sp in (sig.get('scripts') or []):
            if sp.lower() in body.lower():
                detected = True
                confidence = max(confidence, 'medium', key=_conf_rank)
                source = source or 'Script src'

        if detected:
            seen.add(key)
            result['technologies'].append({
                'name': name,
                'category': category,
                'version': version,
                'confidence': confidence,
                'source': source,
            })
            result['stats']['successful_checks'] += 1


def _match_builtin_signatures(headers: dict, body: str, cookies: dict,
                              seen: set, result: dict):
    """Match against the built-in tuples (legacy path)."""
    # 1. Header analysis
    if headers:
        for header_name, pattern, tech_name, category in HEADER_FINGERPRINTS:
            value = headers.get(header_name, '')
            if value:
                result['stats']['total_checks'] += 1
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    name = tech_name or value
                    version = match.group(1) if match.lastindex else None
                    key = f'{name}:{category}'
                    if key not in seen:
                        seen.add(key)
                        result['technologies'].append({
                            'name': name,
                            'category': category,
                            'version': version,
                            'confidence': 'high',
                            'source': f'Header: {header_name}',
                        })
                        result['stats']['successful_checks'] += 1

    # 2. HTML/body analysis
    if body:
        for pattern, tech_name, category in HTML_FINGERPRINTS:
            result['stats']['total_checks'] += 1
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                key = f'{tech_name}:{category}'
                if key not in seen:
                    seen.add(key)
                    result['technologies'].append({
                        'name': tech_name,
                        'category': category,
                        'version': version,
                        'confidence': 'medium',
                        'source': 'HTML content',
                    })
                    result['stats']['successful_checks'] += 1

    # 3. Cookie analysis
    if cookies:
        cookie_names = list(cookies.keys()) if isinstance(cookies, dict) else []
        for cookie_pattern, tech_name, category in COOKIE_FINGERPRINTS:
            result['stats']['total_checks'] += 1
            for name in cookie_names:
                if re.search(cookie_pattern, name, re.IGNORECASE):
                    key = f'{tech_name}:{category}'
                    if key not in seen:
                        seen.add(key)
                        result['technologies'].append({
                            'name': tech_name,
                            'category': category,
                            'version': None,
                            'confidence': 'high',
                            'source': f'Cookie: {name}',
                        })
                        result['stats']['successful_checks'] += 1


def _match_js_globals(body: str, seen: set, result: dict):
    """Detect technologies by JavaScript global variable patterns in body."""
    for pattern, tech_name, category in JS_GLOBAL_FINGERPRINTS:
        result['stats']['total_checks'] += 1
        if re.search(pattern, body, re.IGNORECASE):
            key = f'{tech_name}:{category}'
            if key not in seen:
                seen.add(key)
                result['technologies'].append({
                    'name': tech_name,
                    'category': category,
                    'version': None,
                    'confidence': 'medium',
                    'source': 'JS globals',
                })
                result['stats']['successful_checks'] += 1


def _match_url_patterns(url: str, seen: set, result: dict):
    """Detect technologies or paths of interest from the URL."""
    for pattern, tech_name, category in URL_PATH_FINGERPRINTS:
        if tech_name is None:
            continue  # informational-only entries
        result['stats']['total_checks'] += 1
        if re.search(pattern, url, re.IGNORECASE):
            key = f'{tech_name}:{category}'
            if key not in seen:
                seen.add(key)
                result['technologies'].append({
                    'name': tech_name,
                    'category': category,
                    'version': None,
                    'confidence': 'medium',
                    'source': 'URL path',
                })
                result['stats']['successful_checks'] += 1


def _extract_script_versions(body: str, seen: set, result: dict):
    """Extract version numbers from <script src> and <link href> attributes."""
    # Collect all src/href values from script and link tags
    src_pattern = r'(?:src|href)\s*=\s*["\']([^"\']+)["\']'
    srcs = re.findall(src_pattern, body, re.IGNORECASE)

    for src in srcs:
        for pattern, tech_name, category in SCRIPT_VERSION_PATTERNS:
            result['stats']['total_checks'] += 1
            m = re.search(pattern, src, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else None
                key = f'{tech_name}:{category}'
                existing = next(
                    (t for t in result['technologies']
                     if f"{t['name']}:{t['category']}" == key),
                    None
                )
                if existing:
                    # Upgrade version if missing
                    if not existing.get('version') and version:
                        existing['version'] = version
                        existing['confidence'] = 'high'
                else:
                    if key not in seen:
                        seen.add(key)
                        result['technologies'].append({
                            'name': tech_name,
                            'category': category,
                            'version': version,
                            'confidence': 'high',
                            'source': 'Script src',
                        })
                        result['stats']['successful_checks'] += 1
                break  # first matching pattern wins for this src


def _conf_rank(c: str) -> int:
    """Numeric rank for confidence comparison."""
    return {'low': 0, 'medium': 1, 'high': 2}.get(c, 0)
