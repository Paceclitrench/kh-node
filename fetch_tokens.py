import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
node = os.environ.get("KF_NODE") or os.environ.get("RAILWAY_SERVICE_ID") or os.uname().nodename
_f = os.path.join(HERE, ".farm_" + "secret")
sec = open(_f).read().strip() if os.path.exists(_f) else "2a767309a6b10f5264e0ecf460181310"
url = os.environ.get("KF_TOKENS_URL", "http://144.31.34.147:8765/tokens")
req = urllib.request.Request(url + "?node=" + node, headers={"X-Farm-Secret": sec})
data = urllib.request.urlopen(req, timeout=15).read()
if data.strip():
    open(os.path.join(HERE, "gh_tokens.txt"), "wb").write(data)
    print("tokens fetched:", len(data.splitlines()), flush=True)
