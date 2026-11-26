# Lab targets
* **Simulated targets**: any asset whose hostname ends in `.lab.sentinel.local` is answered from `backend/app/lab.py`
  (never resolved or contacted). `python -m app.seed` builds a six-asset demo network from them.
* **Real local target**: `docker compose --profile lab up -d lab-target` starts OWASP Juice Shop on the isolated `scan` network.
  Add `lab-target` as an asset, approve it, then run discovery + nmap + nuclei from the Scan center.
Only ever add systems you own or have written permission to test.
