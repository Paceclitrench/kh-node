#!/bin/bash
export KF_DORK_MOD=${KF_DORK_MOD:-30}
export KF_DORK_SHARD=$(( $(hostname | cksum | cut -d' ' -f1) % 30 ))
mkdir -p data
python3 sidecar.py >> data/sidecar.log 2>&1 &
exec python3 -u dashscope_hunt.py --loop
