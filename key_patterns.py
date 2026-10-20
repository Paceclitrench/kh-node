"""Shared key patterns — generated from eternal_v10 PROVIDERS registry (34 providers)."""
import base64
import re

PATTERNS = [
    # v6.5 (2026-10-06): merged high-value rules from gitleaks v8 config and
    # trufflehog detectors (xai/openaiadmin/langsmith). Distinctive prefixes —
    # placed FIRST so first-wins dedup labels them before generic families.
    ('OPENAI_ADMIN', re.compile(r'\bsk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}\b')),
    # XAI: covered by GROK above (xai- shape, registry knows GROK; a separate
    # XAI label would stall validation — one label per key shape).
    ('LANGSMITH', re.compile(r'\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b')),
    ('DATABRICKS', re.compile(r'\bdapi[a-f0-9]{32}(?:-\d)?\b')),
    ('DOPPLER', re.compile(r'\bdp\.pt\.[a-z0-9]{43}\b')),
    ('ARTIFACTORY', re.compile(r'\bAKCp[A-Za-z0-9]{69}\b')),
    ('ALIBABA_LTAI', re.compile(r'\bLTAI[a-z0-9]{12,22}\b')),
    ('AGE_KEY', re.compile(r'\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b')),
    ('ONEPASSWORD', re.compile(r'\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b')),
    ('AZURE_AD', re.compile(r'\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}\b')),
    # batch-2 (2026-10-06): HEROKU + SUPABASE — anchored, unclaimed shapes,
    # allowlisted in eternal_v10 structural list (WORKING/unvalidated).
    # REJECTED: CLERK sk_(live|test)_ — shape owned by STRIPE (:80), second
    # label = mislabel race (one label per key shape doctrine). BAIDU
    # bce-v3/ALTAK-{id}/{sig} — per-request HMAC signature, not a credential.
    # heroku = gitleaks v2 форма (v1 uuid contextual — не flatten).
    ('HEROKU', re.compile(r'\bHRKU-AA[0-9a-zA-Z_-]{58}')),
    ('SUPABASE', re.compile(r'\bsbp-[a-f0-9]{40}')),
    ('ZAI', re.compile(r'[a-f0-9]{32}\.[A-Za-z0-9]{10,30}')),
    ('SAKANA', re.compile(r'fish_[a-f0-9]{64}')),
    ('OPENROUTER', re.compile(r'sk-or-v1-[0-9a-f]{48,70}')),
    ('DASHSCOPE', re.compile(r'sk-sp-[A-Za-z0-9_\-]{20,64}|sk-[a-f0-9]{32}')),
    ('MINIMAX', re.compile(r'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}')),
    # NOTE: this regex is identical to DASHSCOPE's sk-<32hex> alternative above,
    # so DASHSCOPE always matches first and scan_text's value-dedup drops this
    # label for bare values. It is kept because _smoke_patterns.py requires
    # DEEPSEEK to be present in PATTERNS and other consumers filter on the label.
    # Mislabelling is fixed where it matters: validate_key writes the provider
    # that the live probe proved, not the one the regex guessed.
    ('DEEPSEEK', re.compile(r'sk-[a-f0-9]{32}')),
    ('TWOCAPTCHA', re.compile(r'(?:2captcha|rucaptcha|twocaptcha|two_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})', re.IGNORECASE)),
    ('CAPSOLVER', re.compile(r'(?:capsolver|cap_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(CAP-[A-Za-z0-9_-]{20,45})', re.IGNORECASE)),
    ('ANTICAPTCHA', re.compile(r'(?:anticaptcha|anti_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', re.IGNORECASE)),
    ('CAPMONSTER', re.compile(r'(?:capmonster|cap_monster)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', re.IGNORECASE)),
    ('EZSOLVER', re.compile(r'(?:ezsolver|ez_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})', re.IGNORECASE)),
    ('NOPECHA', re.compile(r'(?:nopecha|nope_cha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,64})', re.IGNORECASE)),
    ('AZCAPTCHA', re.compile(r'(?:azcaptcha|az_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})', re.IGNORECASE)),
    ('YESSOLVER', re.compile(r'(?:yessolver|yes_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32,64})', re.IGNORECASE)),
    # URL-format captcha keys: 2captcha.com/in.php?key=...
    ('TWOCAPTCHA_URL', re.compile(r'2captcha\.com/in\.\w+\?key=([a-f0-9]{32})')),
    ('SOAX', re.compile(r'(?:soax|SOAX)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,50})(?![A-Za-z0-9])')),
    ('PROXY_SOCKS5', re.compile(r'socks5://(?:[^:@]+:[^@]+@)?[^\s"\'<>]+:\d{2,5}')),
    ('PROXY_HTTP', re.compile(r'https?://(?:[^:@]+:[^@]+@)?[^\s"\'<>]+:\d{2,5}')),
    ('DAYTONA', re.compile(r'dtn_[a-f0-9]{64}')),
    ('WEBSHARE', re.compile(r'(?:webshare)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)),
    ('IPROYAL', re.compile(r'(?:iproyal|ip_royal)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,50})', re.IGNORECASE)),
    ('BRIGHTDATA', re.compile(r'(?:brightdata|luminati|brd)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', re.IGNORECASE)),
    ('TELEGRAM', re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b')),
    ('DISCORD', re.compile(r'mfa\.[A-Za-z0-9_\-]{24,120}(?![A-Za-z0-9_-])')),  # v7.1 bare revert (DEAD!=FP)
    ('OPENAI', re.compile(r'sk-proj-[A-Za-z0-9_-]{60,200}'
                     r'|sk-svcacct-[A-Za-z0-9_-]{60,200}'
                     r'|sk-None-[A-Za-z0-9_-]{20,200}'
                     r'|"sk-[A-Za-z0-9]{20}iv|"sk-[A-Za-z0-9]{20}proj')),
    ('ANTHROPIC', re.compile(r'sk-ant-api03-[A-Za-z0-9_-]{20,120}')),
    ('ANTHROPIC_OAT', re.compile(r'sk-ant-oat01-(?=[A-Za-z0-9_-]{40,120}$)(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{40,120}')),
    ('GOOGLE', re.compile(r'(?:GOOGLE|google|GCP|gcp)[_ ]?(?:API|APPLICATION_CREDENTIALS|AI)[_ ]?(?:KEY|TOKEN|CREDENTIALS|FILE)?[\'"]?\s*[=:]\s*[\'"]?(AIza[A-Za-z0-9_-]{35})')),
    ('GOOGLE', re.compile(r'AIza[A-Za-z0-9_-]{35}')),  # v7.1 bare restore (frontend ?key= / apiKey JSON)
    ('MISTRAL', re.compile(r'(?:mistral|MISTRAL)[_a-zA-Z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{32})(?![A-Za-z0-9])')),
    ('TOGETHER', re.compile(r'tgp_[A-Za-z0-9\-]{40,60}')),
    ('REPLICATE', re.compile(r'r8_[A-Za-z0-9]{37}')),
    ('SILICONFLOW', re.compile(r'sk-[a-zA-Z0-9]{48}')),
    # v6.3: KIMI after SILICONFLOW so specific sk- formats win first
    ('KIMI', re.compile(r'sk-[A-Za-z0-9]{48}')),
    # v6.3: video-gen (Seedance 2.5 on Volcengine ARK + fal.ai)
    ('FAL', re.compile(r'\b[0-9a-f]{32}:[0-9a-f]{64}\b')),
    ('ARK', re.compile(r'(?:ARK|VOLCENGINE|DOUBAO|SEEDANCE|BYTEDANCE)_?API_KEY["\']?\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,64})', re.IGNORECASE)),
    ('FIREWORKS', re.compile(r'(?:fireworks|FIREWORKS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{48,52})', re.IGNORECASE)),
    ('FIREWORKS', re.compile(r'fw_[A-Za-z0-9]{40,60}')),
    ('GROQ', re.compile(r'gsk_[A-Za-z0-9]{40,60}')),
    ('COHERE', re.compile(r'(?:cohere|COHERE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{40})', re.IGNORECASE)),
    ('NOVITA', re.compile(r'(?:novita|NOVITA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{32,40})', re.IGNORECASE)),
    ('PERPLEXITY', re.compile(r'pplx-[a-z0-9]{56}')),
    ('ELEVENLABS', re.compile(r'(?:elevenlabs|ELEVENLABS|xi)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', re.IGNORECASE)),
    ('STABILITY', re.compile(r'sk-[A-Za-z0-9]{99}')),
    ('ALIYUN', re.compile(r'LTAI[A-Za-z0-9]{12,20}')),
    # Measured against 275 nvapi- rows in data/keys.db: 263 real keys are
    # prefix+64 (70 total); the 4 run-ons are prefix+95..112. The old {80,120}
    # bound matched 0/263 real keys and 4/4 run-ons - it only ever caught junk.
    # Upper bound + negative lookahead stop greedy runs; \b alone does not.
    ('NVIDIA', re.compile(r'\bnvapi-[A-Za-z0-9_\-]{40,80}(?![A-Za-z0-9_\-])')),
    ('HUGGINGFACE', re.compile(r'hf_[A-Za-z0-9]{34}')),
    ('GROK', re.compile(r'xai-[A-Za-z0-9_]{40,100}')),
    # v6.5: video-gen + zhipu bare
    ('MESHY', re.compile(r'\bmsh_[A-Za-z0-9]{30,40}\b')),
    ('LUMA', re.compile(r'\bluma-[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}\b')),
    # v4 traffic & infra patterns
    ('AWS', re.compile(r'AKIA[A-Z0-9]{16}')),
    ('CLOUDFLARE', re.compile(r'(?:cf_|CF_)[A-Za-z0-9_-]{40,50}')),
    ('DISCORD', re.compile(r'(?<![A-Za-z0-9])[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}(?![\w-])')),  # v7.6 exact-tail + bounds; snowflake gate in scan_text
    ('STRIPE', re.compile(r'sk_live_[A-Za-z0-9]{24,}')),
    ('GITHUB_PAT', re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ('GITHUB_OAUTH', re.compile(r'gho_[A-Za-z0-9]{36}')),
    # v5: fine-grained & SaaS prefixes (2026-09-28 wave)
    ('GITHUB_USER', re.compile(r'ghu_[A-Za-z0-9]{36,45}')),
    ('GITHUB_SERVER', re.compile(r'ghs_[A-Za-z0-9]{36,45}')),
    ('GITHUB_REFRESH', re.compile(r'ghr_[A-Za-z0-9]{76,90}')),
    ('GITHUB_FINE', re.compile(r'github_pat_[A-Za-z0-9_]{82}')),
    ('SLACK_BOT', re.compile(r'xoxb-[0-9]{8,12}-[0-9]{8,12}-[A-Za-z0-9]{20,24}')),
    ('SLACK_USER', re.compile(r'xoxp-[0-9]{8,12}-[0-9]{8,12}-[0-9]{8,12}-[A-Za-z0-9]{20,30}')),
    ('SLACK_APP', re.compile(r'xapp-[0-9]-[A-Za-z0-9-]{20,}')),
    ('LINEAR', re.compile(r'lin_api_[A-Za-z0-9]{40}')),
    ('CEREBRAS', re.compile(r'csk-[a-z0-9]{60}')),
    ('SENTRY', re.compile(r'sntrys_[A-Za-z0-9_\-]{60,}')),
    ('FIGMA', re.compile(r'figd_[A-Za-z0-9]{40}')),
    ('POSTMAN', re.compile(r'PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{43}')),
    ('NOTION_BARE', re.compile(r'secret_[A-Za-z0-9]{43}')),
    ('UPSTASH', re.compile(r'upstash_[A-Za-z0-9]{30,40}')),
    ('NPM', re.compile(r'npm_[A-Za-z0-9]{36}')),
    ('PYPI', re.compile(r'pypi-[A-Za-z0-9_-]{50,}')),
    ('SENDGRID', re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}')),
    ('TWILIO', re.compile(r'(?:twilio|TWILIO)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})', re.IGNORECASE)),
    ('NOTION', re.compile(r'(?:notion|NOTION)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(secret_[A-Za-z0-9]{43})', re.IGNORECASE)),
    ('PINECONE', re.compile(r'(?:pinecone|PINECONE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.IGNORECASE)),
    ('WANDB', re.compile(r'(?:wandb|WANDB)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{40})', re.IGNORECASE)),
    ('RUNPOD', re.compile(r'(?:runpod|RUNPOD)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,50})', re.IGNORECASE)),
    ('TWILIO_SK', re.compile('SK[0-9a-f]{32}')),
    ('GITLAB_PAT', re.compile('glpat-[0-9a-zA-Z_-]{20,}')),
    ('PG_URI', re.compile('postgres(?:ql)?://[^\\s\\"\'<>]{1,64}:[^\\s\\"\'@<>]{4,}@[^\\s\\"\'<>]+')),
    ('MYSQL_URI', re.compile('mysql://[^\\s\\"\'<>]{1,64}:[^\\s\\"\'@<>]{4,}@[^\\s\\"\'<>]+')),
    ('MONGO_URI', re.compile('mongodb(?:\\+srv)?://[^\\s\\"\'<>]{1,64}:[^\\s\\"\'@<>]{4,}@[^\\s\\"\'<>]+')),
    ('REDIS_URI', re.compile('rediss?://:[^\\s\\"\'@<>]{4,}@[^\\s\\"\'<>]+')),
    ('HTTPS_AUTH', re.compile('https://[^\\s\\"\'/:@<>]{1,64}:[^\\s\\"\'@/<>]{4,}@[^\\s\\"\'<>]+')),
    ('AZURE_STORAGE', re.compile(r'DefaultEndpointsProtocol=https;AccountName=[a-z0-9][a-z0-9-]{1,22}[a-z0-9];AccountKey=[A-Za-z0-9+/]{86}==')),
    # v6: full-stack wave (2026-09-29): cloud/dev-tool/SaaS prefixes + PEM
    ('NEON', re.compile(r'napi_[A-Za-z0-9]{30,60}')),
    ('DROPBOX', re.compile(r'sl\.[A-Za-z0-9_-]{100,150}')),
    ('TWITTER', re.compile(r'AAAAAAAAA[A-Za-z0-9%]{50,90}')),
    ('BREVO', re.compile(r'xkeysib-[A-Za-z0-9]{16,64}-[A-Za-z0-9]{16,64}')),
    ('RESEND', re.compile(r're_[A-Za-z0-9]{28,50}')),
    ('MAILGUN', re.compile(r'\bkey-[a-f0-9]{32}\b')),
    ('SHOPIFY', re.compile(r'shp(?:at|ca|ss|pa|ua)_[a-fA-F0-9]{32}')),
    ('SQUARE', re.compile(r'sq0atp-[A-Za-z0-9_-]{22,60}')),
    ('SQUARE_SECRET', re.compile(r'sq0csp-[A-Za-z0-9_-]{40,60}')),
    ('STRIPE_WEBHOOK', re.compile(r'whsec_[A-Za-z0-9]{32,64}')),
    ('STRIPE_RESTRICTED', re.compile(r'rk_live_[A-Za-z0-9]{24,99}')),
    ('DIGITALOCEAN', re.compile(r'do[po]_v1_[a-f0-9]{64}')),
    ('DOCKER', re.compile(r'dckr_pat_[A-Za-z0-9_-]{30,}')),
    ('KAKAO', re.compile(r'KakaoAK [0-9a-f]{32}')),
    ('RUBYGEMS_PAT', re.compile(r'rubygems_[A-Za-z0-9]{30,}')),
    ('SONARQUBE', re.compile(r'squ_[A-Za-z0-9]{40,}')),
    ('GRAFANA', re.compile(r'glc_[A-Za-z0-9_-]{40,}')),
    ('LANGSMITH', re.compile(r'lsv2_(?:pt|sk)_[A-Za-z0-9]{40,}')),
    ('TAVILY', re.compile(r'tvly-[A-Za-z0-9]{26,48}')),
    ('FIRECRAWL', re.compile(r'fc-[a-f0-9]{32}')),
    ('NETLIFY', re.compile(r'nfp_[A-Za-z0-9]{40,46}')),
    ('RENDER', re.compile(r'rnd_[A-Za-z0-9]{32,}')),
    ('MAPBOX_SECRET', re.compile(r'sk\.eyJ[A-Za-z0-9_\-]{50,}')),
    ('HUBSPOT', re.compile(r'pat-(?:na|eu)\d-[A-Za-z0-9]{30,}')),
    ('AIRTABLE', re.compile(r'pat[A-Za-z0-9]{8,20}\.[A-Za-z0-9]{40,}')),
    ('SENTRY_DSN', re.compile(r'https://[a-f0-9]{32}@[a-z0-9.-]*sentry\.io/\d+')),
    ('PRIVATE_KEY', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,6000}?-----END [A-Z ]*PRIVATE KEY-----')),
    ('MAILCHIMP', re.compile(r'\b[a-f0-9]{32}-us\d{1,2}\b')),
    ('ACCTOKEN', re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}')),
    # v7: 2026-10-02 PatternForge wave — high-signal standalone prefixes
    ('JINA', re.compile(r'(?<![A-Za-z0-9_])jina_[A-Fa-f0-9]{20,50}(?![A-Za-z0-9])')),
    ('VOYAGE', re.compile(r'(?<![A-Za-z0-9_-])pa-[A-Za-z0-9_-]{20,60}(?![A-Za-z0-9_-])')),
    ('BRAVE_SEARCH', re.compile(r'(?<![A-Za-z0-9])BSA[A-Za-z0-9_-]{20,80}(?![A-Za-z0-9_-])')),
    ('BFL', re.compile(r'(?<![A-Za-z0-9_])bfl_[A-Za-z0-9_-]{20,60}(?![A-Za-z0-9_-])')),
    ('DEEPINFRA', re.compile(r'(?<![A-Za-z0-9_])di_[A-Za-z0-9]{30,80}(?![A-Za-z0-9])')),
    ('LANGFUSE', re.compile(r'(?<![A-Za-z0-9_-])(?:pk-lf-|sk-lf-)[A-Za-z0-9_-]{20,80}(?![A-Za-z0-9_-])')),
    ('PINECONE_V2', re.compile(r'(?<![A-Za-z0-9_])pcsk_[A-Za-z0-9_-]{30,80}(?![A-Za-z0-9_-])')),
    # v7 env-context-gated patterns (no public known prefix)
    ('BASETEN', re.compile(r'(?:BASETEN|baseten)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('SERPER', re.compile(r'(?:SERPER|serper)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sp_[A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('SERPAPI', re.compile(r'(?:SERPAPI|serpapi)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{30,80})', re.IGNORECASE)),
    ('EXA', re.compile(r'(?:EXA|exa)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('RUNWAY', re.compile(r'(?:RUNWAY|runway|RUNWAYML)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('PIKA', re.compile(r'(?:PIKA|pika)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('SUNO', re.compile(r'(?:SUNO|suno)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sk-[A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('FLYIO', re.compile(r'(?:FLY|fly)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,80})', re.IGNORECASE)),
    ('TENCENT', re.compile(r'(?:TENCENT|tencent|HUNYUAN|hunyuan)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('SAMBANOVA', re.compile(r'(?:SAMBANOVA|sambanova)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('UPSTAGE', re.compile(r'(?:UPSTAGE|upstage)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('LEPTON', re.compile(r'(?:LEPTON|lepton)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('NEARAI', re.compile(r'(?:NEARAI|nearai|NEAR_AI)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('ALEPH_ALPHA', re.compile(r'(?:ALEPH_ALPHA|aleph_alpha|ALEPHALPHA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
    ('AI21', re.compile(r'(?:AI21|ai21)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})', re.IGNORECASE)),
]

# ENV assignment patterns: VAR=value -> provider (from v10 registry vars)
_ENV_VARS = [
    ('DEEPSEEK_REASONER_API_KEY', 'DEEPSEEK'),
    ('ALIYUN_DASHSCOPE_API_KEY', 'DASHSCOPE'),
    ('CLAUDE_CODE_ACCESS_TOKEN', 'ANTHROPIC_OAT'),
    ('STABLE_DIFFUSION_API_KEY', 'STABILITY'),
    ('CLAUDE_CODE_OAUTH_TOKEN', 'ANTHROPIC_OAT'),
    ('QWEN_DASHSCOPE_API_KEY', 'DASHSCOPE'),
    ('TONGYI_QIANWEN_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_CODER_API_KEY', 'DEEPSEEK'),
    ('ALIBABA_CLOUD_API_KEY', 'DASHSCOPE'),
    ('DASHSCOPE_LLM_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_ACCESS_TOKEN', 'DEEPSEEK'),
    ('DEEPSEEK_CHAT_API_KEY', 'DEEPSEEK'),
    ('ANTHROPIC_OAUTH_TOKEN', 'ANTHROPIC_OAT'),
    ('HUGGINGFACE_API_TOKEN', 'HUGGINGFACE'),
    ('ALIBABACLOUD_API_KEY', 'DASHSCOPE'),
    ('ALIYUN_CLOUD_API_KEY', 'DASHSCOPE'),
    ('ALIBABA_QWEN_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_PRO_API_KEY', 'DEEPSEEK'),
    ('NVIDIA_BUILD_API_KEY', 'NVIDIA'),
    ('OPEN_ROUTER_API_KEY', 'OPENROUTER'),
    ('ALIBABA_LLM_API_KEY', 'DASHSCOPE'),
    ('DASHSCOPE_API_TOKEN', 'DASHSCOPE'),
    ('ALIYUN_QWEN_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_API_SECRET', 'DEEPSEEK'),
    ('DEEPSEEK_V3_API_KEY', 'DEEPSEEK'),
    ('DEEPSEEK_V4_API_KEY', 'DEEPSEEK'),
    ('DEEPSEEK_R1_API_KEY', 'DEEPSEEK'),
    ('TWO_CAPTCHA_API_KEY', 'TWOCAPTCHA'),
    ('TOGETHER_AI_API_KEY', 'TOGETHER'),
    ('REPLICATE_API_TOKEN', 'REPLICATE'),
    ('FIREWORKS_API_TOKEN', 'FIREWORKS'),
    ('OPENROUTER_API_KEY', 'OPENROUTER'),
    ('ALIYUN_LLM_API_KEY', 'DASHSCOPE'),
    ('MODELSCOPE_API_KEY', 'DASHSCOPE'),
    ('TWOCAPTCHA_API_KEY', 'TWOCAPTCHA'),
    ('OPENAI_PROJECT_KEY', 'OPENAI'),
    ('CLAUDE_OAUTH_TOKEN', 'ANTHROPIC_OAT'),
    ('MISTRAL_AI_API_KEY', 'MISTRAL'),
    ('PERPLEXITY_API_KEY', 'PERPLEXITY'),
    ('SAKANA_AI_API_KEY', 'SAKANA'),
    ('DASHSCOPE_API_KEY', 'DASHSCOPE'),
    ('BAILIAN_API_TOKEN', 'DASHSCOPE'),
    ('RUCAPTCHA_API_KEY', 'TWOCAPTCHA'),
    ('OPENAI_SECRET_KEY', 'OPENAI'),
    ('ANTHROPIC_API_KEY', 'ANTHROPIC'),
    ('GOOGLE_AI_API_KEY', 'GOOGLE'),
    ('MISTRALAI_API_KEY', 'MISTRAL'),
    ('REPLICATE_API_KEY', 'REPLICATE'),
    ('FIREWORKS_API_KEY', 'FIREWORKS'),
    ('STABILITY_API_KEY', 'STABILITY'),
    ('HUGGINGFACE_TOKEN', 'HUGGINGFACE'),
    ('BIGMODEL_API_KEY', 'ZAI'),
    ('MOONSHOT_API_KEY', 'KIMI'),
    ('OPENROUTER_TOKEN', 'OPENROUTER'),
    ('ALICLOUD_API_KEY', 'DASHSCOPE'),
    ('MODELSCOPE_TOKEN', 'DASHSCOPE'),
    ('DEEPSEEK_API_KEY', 'DEEPSEEK'),
    ('2CAPTCHA_API_KEY', 'TWOCAPTCHA'),
    ('ANTHROPIC_APIKEY', 'ANTHROPIC'),
    ('GOOGLE_API_TOKEN', 'GOOGLE'),
    ('TOGETHER_API_KEY', 'TOGETHER'),
    ('PERPLEXITY_TOKEN', 'PERPLEXITY'),
    ('ZHIPUAI_API_KEY', 'ZAI'),
    ('CHATGLM_API_KEY', 'ZAI'),
    ('OPEN_ROUTER_KEY', 'OPENROUTER'),
    ('ALIBABA_API_KEY', 'DASHSCOPE'),
    ('DASHSCOPE_TOKEN', 'DASHSCOPE'),
    ('BAILIAN_API_KEY', 'DASHSCOPE'),
    ('QIANWEN_API_KEY', 'DASHSCOPE'),
    ('SEEDANCE_API_KEY', 'ARK'),
    ('ARK_API_KEY', 'ARK'),
    ('VOLCENGINE_API_KEY', 'ARK'),
    ('ARK_API_TOKEN', 'ARK'),
    ('DOUBAO_API_KEY', 'ARK'),
    ('BYTEDANCE_API_KEY', 'ARK'),
    ('FAL_KEY', 'FAL'),
    ('FAL_API_KEY', 'FAL'),
    ('FAL_AI_API_KEY', 'FAL'),
    ('QWEN2_5_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_SECRET', 'DEEPSEEK'),
    ('CAPTCHA_API_KEY', 'TWOCAPTCHA'),
    ('TWO_CAPTCHA_KEY', 'TWOCAPTCHA'),
    ('ANTHROPIC_TOKEN', 'ANTHROPIC'),
    ('MISTRAL_API_KEY', 'MISTRAL'),
    ('TOGETHER_AI_KEY', 'TOGETHER'),
    ('REPLICATE_TOKEN', 'REPLICATE'),
    ('FIREWORKS_TOKEN', 'FIREWORKS'),
    ('STABILITY_TOKEN', 'STABILITY'),
    ('BIGMODEL_TOKEN', 'ZAI'),
    ('SAKANA_API_KEY', 'SAKANA'),
    ('OPENROUTER_KEY', 'OPENROUTER'),
    ('ALIYUN_API_KEY', 'DASHSCOPE'),
    ('TONGYI_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_TOKEN', 'DEEPSEEK'),
    ('2CAPTCHA_TOKEN', 'TWOCAPTCHA'),
    ('OPENAI_API_KEY', 'OPENAI'),
    ('CLAUDE_API_KEY', 'ANTHROPIC'),
    ('GOOGLE_API_KEY', 'GOOGLE'),
    ('GEMINI_API_KEY', 'GOOGLE'),
    ('PERPLEXITY_KEY', 'PERPLEXITY'),
    ('NVIDIA_API_KEY', 'NVIDIA'),
    ('ZHIPU_API_KEY', 'ZAI'),
    ('DASHSCOPE_KEY', 'DASHSCOPE'),
    ('QWEN2_API_KEY', 'DASHSCOPE'),
    ('RUCAPTCHA_KEY', 'TWOCAPTCHA'),
    ('CAPTCHA_TOKEN', 'TWOCAPTCHA'),
    ('ANTHROPIC_KEY', 'ANTHROPIC'),
    ('MISTRAL_TOKEN', 'MISTRAL'),
    ('REPLICATE_KEY', 'REPLICATE'),
    ('FIREWORKS_KEY', 'FIREWORKS'),
    ('STABILITY_KEY', 'STABILITY'),
    ('Z_AI_API_KEY', 'ZAI'),
    ('GLM4_API_KEY', 'ZAI'),
    ('GLM5_API_KEY', 'ZAI'),
    ('BIGMODEL_KEY', 'ZAI'),
    ('KIMI_API_KEY', 'KIMI'),
    ('FUGU_API_KEY', 'SAKANA'),
    ('FISH_API_KEY', 'SAKANA'),
    ('QWEN_API_KEY', 'DASHSCOPE'),
    ('DEEPSEEK_KEY', 'DEEPSEEK'),
    ('2CAPTCHA_KEY', 'TWOCAPTCHA'),
    ('OPENAI_TOKEN', 'OPENAI'),
    ('TOGETHER_KEY', 'TOGETHER'),
    ('PPLX_API_KEY', 'PERPLEXITY'),
    ('HF_API_TOKEN', 'HUGGINGFACE'),
    ('ZAI_API_KEY', 'ZAI'),
    ('GLM_API_KEY', 'ZAI'),
    ('ZHIPUAI_KEY', 'ZAI'),
    ('CHATGLM_KEY', 'ZAI'),
    ('ALI_API_KEY', 'DASHSCOPE'),
    ('CAPTCHA_KEY', 'TWOCAPTCHA'),
    ('GCP_API_KEY', 'GOOGLE'),
    ('MISTRAL_KEY', 'MISTRAL'),
    ('NIM_API_KEY', 'NVIDIA'),
    ('SAKANA_KEY', 'SAKANA'),
    ('OR_API_KEY', 'OPENROUTER'),
    ('OPENROUTER', 'OPENROUTER'),
    ('QWEN_TOKEN', 'DASHSCOPE'),
    ('DS_API_KEY', 'DEEPSEEK'),
    ('OPENAI_KEY', 'OPENAI'),
    ('CLAUDE_KEY', 'ANTHROPIC'),
    ('NVIDIA_KEY', 'NVIDIA'),
    ('ZHIPU_KEY', 'ZAI'),
    ('Z_AI_KEY', 'ZAI'),
    ('OR_TOKEN', 'OPENROUTER'),
    ('QWEN_KEY', 'DASHSCOPE'),
    ('PPLX_KEY', 'PERPLEXITY'),
    ('HF_TOKEN', 'HUGGINGFACE'),
    ('ZAI_KEY', 'ZAI'),
    ('HUGGINGFACEHUB_API_TOKEN', 'HUGGINGFACE'),
    ('FIREWORKS_AI_API_KEY', 'FIREWORKS'),
    ('NVIDIA_NIM_API_KEY', 'NVIDIA'),
    ('MINIMAX_API_KEY', 'MINIMAX'),
    ('GROQ_LLM_API_KEY', 'GROQ'),
    ('NOVITA_API_KEY', 'NOVITA'),
    ('COHERE_API_KEY', 'COHERE'),
    ('ELEVENLABS_API_KEY', 'ELEVENLABS'),
    ('GROQ_API_KEY', 'GROQ'),
    ('XI_API_KEY', 'ELEVENLABS'),
    ('XAI_API_KEY', 'GROK'),
    ('GROQ_TOKEN', 'GROQ'),
    ('NVIDIA_NIM', 'NVIDIA'),
    ('CAPMONSTER_API_KEY', 'CAPMONSTER'),
    ('CAPMONSTER_KEY', 'CAPMONSTER'),
    ('EZSOLVER_API_KEY', 'EZSOLVER'),
    ('NOPECHA_API_KEY', 'NOPECHA'),
    ('AZCAPTCHA_API_KEY', 'AZCAPTCHA'),
    ('YESSOLVER_API_KEY', 'YESSOLVER'),
    ('SOAX_API_KEY', 'SOAX'),
    ('SOAX_TOKEN', 'SOAX'),
    ('WEBSHARE_API_KEY', 'WEBSHARE'),
    ('BRIGHTDATA_API_KEY', 'BRIGHTDATA'),
    ('DAYTONA_API_KEY', 'DAYTONA'),
    # v4 traffic & infra ENV vars
    ('AWS_ACCESS_KEY_ID', 'AWS'),
    ('AWS_SECRET_ACCESS_KEY', 'AWS'),
    ('AZURE_CLIENT_SECRET', 'AZURE'),
    ('CLOUDFLARE_API_TOKEN', 'CLOUDFLARE'),
    ('CF_API_TOKEN', 'CLOUDFLARE'),
    ('DIGITALOCEAN_TOKEN', 'DIGITALOCEAN'),
    ('DO_TOKEN', 'DIGITALOCEAN'),
    ('VULTR_API_KEY', 'VULTR'),
    ('LINODE_TOKEN', 'LINODE'),
    ('HEROKU_API_KEY', 'HEROKU'),
    ('VERCEL_TOKEN', 'VERCEL'),
    ('NETLIFY_AUTH_TOKEN', 'NETLIFY'),
    ('RUNPOD_API_KEY', 'RUNPOD'),
    ('MODAL_TOKEN', 'MODAL'),
    ('LAMBDA_API_KEY', 'LAMBDA'),
    ('PINECONE_API_KEY', 'PINECONE'),
    ('WEAVIATE_API_KEY', 'WEAVIATE'),
    ('QDRANT_API_KEY', 'QDRANT'),
    ('WANDB_API_KEY', 'WANDB'),
    ('LANGCHAIN_API_KEY', 'LANGCHAIN'),
    ('LANGSMITH_API_KEY', 'LANGCHAIN'),
    ('DISCORD_BOT_TOKEN', 'DISCORD'),
    ('DISCORD_TOKEN', 'DISCORD'),
    ('SLACK_BOT_TOKEN', 'SLACK'),
    ('NOTION_API_KEY', 'NOTION'),
    ('NOTION_TOKEN', 'NOTION'),
    ('SENDGRID_API_KEY', 'SENDGRID'),
    ('MAILGUN_API_KEY', 'MAILGUN'),
    ('TWILIO_AUTH_TOKEN', 'TWILIO'),
    ('STRIPE_SECRET_KEY', 'STRIPE'),
    ('NPM_TOKEN', 'NPM'),
    ('PYPI_TOKEN', 'PYPI'),
    ('GITHUB_TOKEN', 'GITHUB'),
    ('JWT_SECRET', 'GENERIC_SECRET'),
    ('SESSION_SECRET', 'GENERIC_SECRET'),
    # v6 env vars: new SaaS/dev-tool providers
    ('TAVILY_API_KEY', 'TAVILY'),
    ('FIRECRAWL_API_KEY', 'FIRECRAWL'),
    ('RESEND_API_KEY', 'RESEND'),
    ('BREVO_API_KEY', 'BREVO'),
    ('SENDINBLUE_API_KEY', 'BREVO'),
    ('SHOPIFY_ACCESS_TOKEN', 'SHOPIFY'),
    ('SHOPIFY_ADMIN_ACCESS_TOKEN', 'SHOPIFY'),
    ('SONAR_TOKEN', 'SONARQUBE'),
    ('SONARQUBE_TOKEN', 'SONARQUBE'),
    ('GRAFANA_TOKEN', 'GRAFANA'),
    ('GRAFANA_API_TOKEN', 'GRAFANA'),
    ('RUBYGEMS_AUTH_TOKEN', 'RUBYGEMS_PAT'),
    ('NEON_API_KEY', 'NEON'),
    ('TWITTER_BEARER_TOKEN', 'TWITTER'),
    ('MAPBOX_ACCESS_TOKEN', 'MAPBOX_SECRET'),
    ('MAPBOX_TOKEN', 'MAPBOX_SECRET'),
    ('DOCKER_HUB_TOKEN', 'DOCKER'),
    ('MAILCHIMP_API_KEY', 'MAILCHIMP'),
    ('MAILCHIMP_KEY', 'MAILCHIMP'),
    ('NETLIFY_TOKEN', 'NETLIFY'),
    # v7 env vars: 2026-10-02 PatternForge wave
    ('BASETEN_API_KEY', 'BASETEN'),
    ('DEEPINFRA_API_KEY', 'DEEPINFRA'),
    ('DEEPINFRA_TOKEN', 'DEEPINFRA'),
    ('MODAL_TOKEN_ID', 'MODAL'),
    ('MODAL_TOKEN_SECRET', 'MODAL'),
    ('FLY_API_TOKEN', 'FLYIO'),
    ('FLYIO_API_TOKEN', 'FLYIO'),
    ('SERPER_API_KEY', 'SERPER'),
    ('SERPAPI_API_KEY', 'SERPAPI'),
    ('SERPAPI_KEY', 'SERPAPI'),
    ('JINA_API_KEY', 'JINA'),
    ('VOYAGE_API_KEY', 'VOYAGE'),
    ('VOYAGEAI_API_KEY', 'VOYAGE'),
    ('BRAVE_SEARCH_API_KEY', 'BRAVE_SEARCH'),
    ('BRAVE_API_KEY', 'BRAVE_SEARCH'),
    ('EXA_API_KEY', 'EXA'),
    ('RUNWAYML_API_SECRET', 'RUNWAY'),
    ('RUNWAY_API_KEY', 'RUNWAY'),
    ('PIKA_API_KEY', 'PIKA'),
    ('SUNO_API_KEY', 'SUNO'),
    ('BFL_API_KEY', 'BFL'),
    ('BLACK_FOREST_LABS_API_KEY', 'BFL'),
    ('TENCENT_API_KEY', 'TENCENT'),
    ('HUNYUAN_API_KEY', 'TENCENT'),
    ('SAMBANOVA_API_KEY', 'SAMBANOVA'),
    ('UPSTAGE_API_KEY', 'UPSTAGE'),
    ('LEPTON_API_TOKEN', 'LEPTON'),
    ('LEPTON_API_KEY', 'LEPTON'),
    ('NEARAI_API_KEY', 'NEARAI'),
    ('NEAR_AI_API_KEY', 'NEARAI'),
    ('LANGFUSE_PUBLIC_KEY', 'LANGFUSE'),
    ('LANGFUSE_SECRET_KEY', 'LANGFUSE'),
    ('LANGFUSE_API_KEY', 'LANGFUSE'),
    ('PINECONE_API_KEY', 'PINECONE'),
    ('UPSTAGE_API_KEY', 'UPSTAGE'),
    ('ALEPH_ALPHA_API_KEY', 'ALEPH_ALPHA'),
    ('AI21_API_KEY', 'AI21'),
    ('STEPIFUN_API_KEY', 'STEPIFUN'),
    ('BAICHUAN_API_KEY', 'BAICHUAN'),
    ('ZEROONE_API_KEY', 'LEADERS'),
    ('LEADERS_API_KEY', 'LEADERS'),
]

_VAR2PROV = dict(_ENV_VARS)
_ALT = '|'.join(dict(_ENV_VARS))
ENV_RE = re.compile(
    '\\b(' + _ALT + ')\\b\\s*[=:]\\s*[\'"]?([A-Za-z0-9_\\-.]{20,200})',
    re.IGNORECASE)


def _is_template(key):
    """v6.3: template junk that survives _is_junk — paired duplicates
    (aabbccddeeff…) and monotone ramps (abcdef…, 12345678). Calibrated on
    6000 real DB keys: 0 legit keys flagged, 77 placeholders caught. Global
    Shannon entropy was rejected: sk-<32hex> tops out at 4 bits/char while
    some templates reach 5.0, so no threshold separates the classes."""
    if len(key) > 160:
        return False  # long blobs (JWTs etc) are not template material
    body = key
    for pfx in ("sk-sp-", "sk-or-v1-", "sk-ant-api03-", "sk-", "pk-lf-",
                "sk-lf-", "csk-", "nvapi-", "r8_", "fish_"):
        if key.startswith(pfx):
            body = key[len(pfx):]
            break
    if len(body) < 8:
        return False
    if len(body) % 2 == 0 and all(body[i] == body[i + 1]
                                  for i in range(0, len(body), 2)):
        return True
    run = 1
    for i in range(1, len(body)):
        if ord(body[i]) - ord(body[i - 1]) in (1, -1):
            run += 1
            if run >= 8:
                return True
        else:
            run = 1
    return False


def _is_junk(key):
    """v6.4: reject placeholder/template keys (paired, ramps, repeats, stubs)."""
    if not key:
        return True
    if len(set(key)) < 4:
        return True
    if all(c in "_-.*xX0" for c in key):
        return True
    for blk in (2, 3, 4):
        if len(key) % blk == 0 and key[:blk] * (len(key) // blk) == key:
            return True
    if _is_template(key):
        return True
    # v6.4: case-insensitive placeholder stubs
    low = key.lower()
    if "xxxx" in low or "yyyy" in low:
        return True
    if "insert_your" in low or "your_token" in low or "your_api_key" in low:
        return True
    if "placeholder" in low:
        return True
    if "<" in low and ">" in low:
        return True
    if "npm_" in low and low.count("x") > len(low) * 0.3:
        return True
    # v10.2: reject template interpolation placeholders like $$VARNAME:S$$
    if "$$" in key:
        return True
    return False


GARBAGE = ("xxxx", "xxx", "your", "YOUR", "EXAMPLE", "example", "n0tr3al",
           "placeholder", "CHANGEME", "changeme", "dummy", "DUMMY",
           "abcdefghijklmnopqrst", "1234567890abcdef", "test-key",
           "sample", "SAMPLE", "insert", "replace", "aaaaaa", "redacted",
           "masked", "censored", "your_api_key", "replace_with",
           "fill_in", "undefined", "mock_", "stub_", "todo", "fixme")


def _is_discord_jwt(t):
    """Discord bot token first segment = base64(numeric snowflake user id).
    Gates the structurally loose [MN]... pattern: real tokens decode to 15-25
    digits; random base64 blobs do not. Zero recall loss, kills blob FPs
    (which would otherwise become junk probes at Discord's API from the
    shared VPS IP)."""
    head = t.split(".", 1)[0]
    try:
        d = base64.b64decode(head + "=" * (-len(head) % 4), validate=False)
    except Exception:
        return False
    return d.isdigit() and 15 <= len(d) <= 25


def _is_https_auth_junk(val):
    """batch-3: HTTPS_AUTH anchoring — diff-probe of 68 targets found 0 real
    creds; mined corpus is mostly doc/placeholder URLs. Reject dead shapes at
    parse time: template interpolation, placeholder cred pairs, non-routable
    and documentation hosts."""
    if not val.startswith("https://"):
        return True
    rest = val[8:]
    if "@" not in rest:
        return True
    cred, _, host = rest.partition("@")
    user, _, pw = cred.partition(":")
    ul, pl = user.lower(), pw.lower()
    if "$" in cred or "{" in cred or "}" in cred or "<" in cred:
        return True
    PH_USER = {"admin", "user", "test", "root", "guest", "foo", "bar", "baz",
               "username", "login", "demo", "sample", "nobody", "user1"}
    PH_PW = {"admin", "password", "pass", "passwd", "secret", "test", "guest",
             "123456", "1234", "12345", "123", "changeme", "user", "root",
             "demo", "sample", "pwd", "hunter2", "letmein", "welcome",
             "qwerty", "abc123", "password1", "admin123", "token"}
    if ul in PH_USER and pl in PH_PW:
        return True
    if ul == pl and len(ul) < 24:
        return True
    if pl in PH_PW:
        return True
    hl = host.lower().split("/")[0].split(":")[0]
    if hl in ("localhost", "localhost.localdomain", "hostname", "your-host",
              "myserver", "server", "host", "foo.com", "bar.com", "baz.com"):
        return True
    if hl.endswith((".local", ".internal", ".invalid", ".test", ".localhost")):
        return True
    if hl.startswith(("127.", "10.", "192.168.", "0.")):
        return True
    if hl.startswith("172."):
        try:
            if 16 <= int(hl.split(".")[1]) <= 31:
                return True
        except (IndexError, ValueError):
            pass
    if hl in ("example.com", "example.org", "example.net") or hl.endswith(
            (".example.com", ".example.org", ".example.net")):
        return True
    if "." not in hl:
        return True
    return False


def _is_pem_junk(val):
    """batch-3: PRIVATE_KEY structural validation, stdlib only (GCP-SA
    lesson: broken PEM fragments -> ValueError at probe time; openssh_key
    <0.0.6 has CVE-2022-31124 so no dep). Body must base64-decode and carry
    plausible structure: openssh-key-v1 magic for OPENSSH, ASN.1 SEQUENCE
    (0x30) for classic PEM types."""
    head = val.split("-----")[1].upper() if val.count("-----") >= 2 else ""
    if "ENCRYPTED" in head:
        return True  # encrypted PEM unusable without passphrase
    if "Proc-Type:" in val or "DEK-Info:" in val:
        return True
    try:
        body = val.split("-----", 2)[2] if val.count("-----") >= 2 else ""
        body = body.split("-----")[0]
        raw = base64.b64decode("".join(body.split()), validate=True)
    except Exception:
        return True
    if len(raw) < 24:
        return True
    if "OPENSSH" in val:
        return not raw.startswith(b"openssh-key-v1\x00")
    return raw[0] != 0x30


def scan_text(text):
    """Yield (prov, key) from text via PATTERNS + ENV assignments."""
    out = []
    for prov, rx in PATTERNS:
        for m in rx.findall(text or ""):
            val = _flat(m)
            if prov == "DISCORD" and not val.startswith("mfa.") \
                    and not _is_discord_jwt(val):
                continue  # snowflake gate on the loose [MN] form
            if prov == "HTTPS_AUTH" and _is_https_auth_junk(val):
                continue  # batch-3: placeholder/doc-shape anchoring
            if prov == "PRIVATE_KEY" and _is_pem_junk(val):
                continue  # batch-3: structural base64/magic validation
            out.append((prov, val))
    for m in ENV_RE.finditer(text or ""):
        out.append((_VAR2PROV.get(m.group(1).upper(), "ENV"), m.group(2)))
    for _name, _rx in EXTRA_PATTERNS.items():
        try:
            for _m in _rx.findall(text or ""):
                out.append((str(_name).upper()[:32], _flat(_m)))
        except Exception:
            continue
    seen_vals = set()
    res = []
    for p, k in out:
        k = k.strip().strip("\"'`,;")
        if not k or len(k) < 20 or k in seen_vals:
            continue
        if any(g in k for g in GARBAGE) or _is_junk(k):
            continue
        seen_vals.add(k)
        res.append((p, k))   # first provider wins: PATTERNS is specific-first
    return res


# ── compat layer ──────────────────────────────────────────────────────────
# Legacy src/key_patterns.py exported KEY_PATTERNS / KIMI_PATTERN / ENV_RE /
# extract_all_keys; root lanes import PATTERNS / scan_text. One file now serves
# both so no module in either tree ImportErrors.

def _flat(m):
    """findall yields str, or a tuple when the pattern has groups."""
    if isinstance(m, (tuple, list)):
        for part in m:
            if isinstance(part, str) and len(part) >= 20:
                return part
        return ""
    return m


def _merge_alts(rxs):
    """One regex per provider: all its alternatives, flags preserved inline."""
    parts = []
    for rx in rxs:
        p = rx.pattern
        if rx.flags & re.IGNORECASE:
            p = "(?i:%s)" % p
        parts.append("(?:%s)" % p)
    return re.compile("|".join(parts))


_by_prov = {}
for _prov, _rx in PATTERNS:
    _by_prov.setdefault(_prov, []).append(_rx)
KEY_PATTERNS = {p: (rs[0] if len(rs) == 1 else _merge_alts(rs))
                for p, rs in _by_prov.items()}

KIMI_PATTERN = re.compile(r'sk-[A-Za-z0-9]{48}')

EXTRA_PATTERNS = {}
try:
    from patterns_extra import EXTRA_PATTERNS as _EP
    EXTRA_PATTERNS = dict(_EP)
except Exception:
    EXTRA_PATTERNS = {}

_PLACEHOLDER_WORDS = (
    'your_', 'your-', 'xxxxx', 'placeholder', 'example', 'dummy',
    'fake_', 'fake-', 'test_key', 'testkey', 'sample', 'demo_',
    'replace', 'insert', 'paste', 'todo', 'changeme', 'change_me',
    'put_here', 'add_here', 'fill_', 'enter_', 'set_', 'get_',
    'api_key_here', '_here', 'key_here', 'token_here',
    'none', 'null', 'undefined', 'secret_key', 'my_api_key',
    'actualkey', 'apikey', 'sk-xxx', 'sk-your', 'xxxxxxxx',
)


def _is_placeholder(val):
    low = val.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    if low.count('x') > len(val) * 0.4:
        return True
    if len(set(low)) <= 2:
        return True
    if val.isupper() and '_' in val and len(val) < 40:
        return True
    return False


def extract_all_keys(text):
    """[(provider, key)] via ENV context + prefix patterns + KIMI + mined.

    ENV_RE here is the 258-name table: group(1) = var name, group(2) = value.
    """
    keys = []
    seen = set()

    def add(prov, val):
        val = _flat(val)
        val = (val or "").strip().strip("\"'`,;")
        if len(val) < 20 or val in seen or _is_placeholder(val):
            return
        if any(g in val for g in GARBAGE) or _is_junk(val):
            return
        seen.add(val)
        keys.append((prov, val))

    for m in ENV_RE.finditer(text or ""):
        add(_VAR2PROV.get(m.group(1).upper(), "ENV"), m.group(2))
    for prov, rx in PATTERNS:
        for m in rx.findall(text or ""):
            add(prov, m)
    for m in KIMI_PATTERN.finditer(text or ""):
        add("KIMI", m.group(0))
    for name, rx in EXTRA_PATTERNS.items():
        try:
            for m in rx.findall(text or ""):
                add(str(name).upper()[:32], m)
        except Exception:
            continue
    return keys
