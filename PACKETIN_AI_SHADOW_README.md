# PacketIn AI Shadow Mode (local VM)

This isolated add-on reuses the existing model at `New_Datasets/models/packetin_ryu_flow_v1/model.joblib`. It contains two files:

- `packetin_ai_shadow_server.py`: Python 3.10 service under `dataset_env`, bound only to `127.0.0.1:8765`; accepts exactly the 22 model features and rejects labels/extra metadata.
- `packetin_ai_shadow.py`: Python 3.8 Ryu app; independently aggregates live IPv4 PacketIn events into 10-second windows, queues inference asynchronously, and logs predictions only.

It does not modify existing files, write CSVs or labels, send PacketOut, install/delete flows, block hosts, reroute traffic, or call Security/Network API actions. The 160-run holdout is not accessed. The service is loopback-only, so Mininet host namespaces cannot reach it directly.

## Install without overwriting files

From the repository root, after copying the two downloaded files there:

```bash
cd ~/Graduation_Project/IoT-devices || exit 1

for f in packetin_ai_shadow_server.py packetin_ai_shadow.py; do
  test ! -e "$f" || { echo "Refusing to overwrite existing $f"; exit 1; }
done

cp /path/to/packetin_ai_shadow_server.py .
cp /path/to/packetin_ai_shadow.py .
```

Replace `/path/to/` with the actual download locations. Do not stage or commit the current working tree; it contains pre-existing user changes.

## 1. Start the local inference service

In terminal 1, from the repository root:

```bash
cd ~/Graduation_Project/IoT-devices || exit 1
PYTHONDONTWRITEBYTECODE=1 dataset_env/bin/python packetin_ai_shadow_server.py
```

It should print that it is ready at `127.0.0.1:8765`. In a second terminal, verify health:

```bash
curl -fsS --max-time 2 http://127.0.0.1:8765/health
```

Keep terminal 1 running. Stop it later with `Ctrl+C`.

## 2. Syntax-check the Ryu app before starting Ryu

```bash
cd ~/Graduation_Project/IoT-devices || exit 1
PYTHONDONTWRITEBYTECODE=1 ryu_env/bin/python3 - <<'PY'
from pathlib import Path
source = Path("packetin_ai_shadow.py").read_text(encoding="utf-8")
compile(source, "packetin_ai_shadow.py", "exec")
print("Ryu shadow app syntax: PASS")
PY
```

## 3. Start Ryu in shadow mode

Only after the inference health check passes, start the same Ryu applications you normally use and append the new app. Example, from the repository root:

```bash
cd ~/Graduation_Project/IoT-devices || exit 1
sudo -E ./ryu_env/bin/ryu-manager --wsapi-port 8080 \
  topology_monitor.py traffic_monitor_merged.py resilience_engine.py \
  packetin_ai_shadow.py
```

Use the repository's normal `sudo -E`/permissions practice. Do not start a second Ryu instance if one is already running. The new app validates that the inference URL stays on loopback. It logs lines prefixed `AI_SHADOW_PREDICTION`; all actions remain disabled.

## 4. Verify live PacketIn events

After Ryu is ready, launch the existing Mininet topology in its usual separate terminal. Generate only ordinary, low-rate lab traffic for the first check. In Ryu logs, look for `AI_SHADOW_PREDICTION` and confirm `source=packetin_window`, `feature_count=22`, and `actions=disabled`. No model ground-truth label is sent. Do not test block/reroute yet.

If Ryu or Mininet is not yet configured, do not guess its launch command; keep the service health check as the only test and ask for the normal topology start command first.

## Stop / rollback

Press `Ctrl+C` in the Ryu terminal and the service terminal. Rollback is just removing the two added files if desired; the existing topology, collector, datasets, and model are unchanged.

## Important limitation

The Ryu plugin independently constructs the 10-second features with the same formulas as the dataset collector. This first stage is a shadow-mode engineering check, not a new accuracy estimate or the final 160-run evaluation. Before production use, compare live feature records against the collector's `packetin_window` output on a few controlled normal runs and verify the deployment model/contract and Ryu logging. No enforcement should be enabled based only on this shadow test.
