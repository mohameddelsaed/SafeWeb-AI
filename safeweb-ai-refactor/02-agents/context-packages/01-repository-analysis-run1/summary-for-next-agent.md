# Summary for Next Agent

The `safeweb-ai` repository is structurally divided between a React frontend (`src/`) and a Django backend (`backend/`). The Django backend acts as the control plane for a scanning engine located in `backend/apps/scanning/engine/`. 
Communication between frontend and backend is handled via REST and SSE. Communication between backend and external scanners is handled via subprocess wrappers in `engine/tools/base.py`.
Some legacy or experimental code exists, notably the `ml` app for phishing and malware detection, and various loose test/output files at the root level.
