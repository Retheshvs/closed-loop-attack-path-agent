# 🎬 DEMO.md: 3-Minute Video Script & Backup Plan
## Project: Closed-Loop Attack-Path Agent (FalkorDB Graph Hacks, Track 1)

---

### Segment 1: Lab & Graph Overview [0:00 – 0:15]
- **Visual**: Camera starts on the interactive Cytoscape web UI at `http://localhost:8000`. The network topology is displayed with glowing dark aesthetics. The red hexagon represents the external `Attacker`, services (`web`, `api`, `admin`) are in the DMZ and internal networks, and the golden diamonds mark the crown jewels (`db` and `fileshare`).
- **Speaker Narration**:
  > *"Welcome! In modern container environments, attackers don't just exploit single servers—they traverse multi-hop paths across segmented networks to reach crown jewel databases. Here, we have a Docker lab with three isolated networks: Internet, DMZ, and Internal. At the perimeter sits `web`, bridged to `api`, which connects to `admin`, `fileshare`, and our crown jewel `db`. Let's see how our AI agent uses FalkorDB to autonomously protect this connected infrastructure."*

---

### Segment 2: Agent Detects Multi-Hop Attack Paths [0:15 – 0:45]
- **Visual**: The presenter clicks the pulsing gradient **"▶ Run Agent"** button. The right-hand panel immediately streams real-time SSE events. Red dashed lines light up across the Cytoscape graph tracing the paths from `Attacker` to `db` and `fileshare`. The top counter displays **"Attack Paths: 3"** in pulsing red.
- **Speaker Narration**:
  > *"When we trigger the agent, it calls `scan_lab` to map Docker container networks and query service vulnerability postures into FalkorDB. Executing a multi-hop Cypher traversal, FalkorDB discovers three distinct paths to our crown jewels: through `web` and `api` straight to `db`, through `api` and `admin` to `db`, and from `api` to `fileshare`. Three different exploitation chains, all threatening customer data."*

---

### Segment 3: Choke Point Discovery & Safe Simulation [0:45 – 1:15]
- **Visual**: The agent activity feed displays the `find_choke_points` card, followed by three `simulate_fix` cards. On the graph, the `api` node pulses with a vibrant purple halo. The event log shows `simulate_fix(service='api', fix='patch_service')` yielding a reduction of 3 paths (leaving 0).
- **Speaker Narration**:
  > *"Rather than trying to patch every single CVE across the lab, the agent asks FalkorDB: 'Where is the architectural choke point?' FalkorDB computes betweenness centrality and path intersection frequencies, revealing that `api` intersects 100% of all attack paths. Before touching production, the agent calls `simulate_fix`. Behind the scenes, FalkorDB executes `GRAPH.COPY lab lab_sim`, simulates patching `api` in the copy, and proves that all three attack paths drop to zero. The live lab remains completely untouched during simulation."*

---

### Segment 4: Live Whitelisted Remediation [1:15 – 1:45]
- **Visual**: The UI displays the `apply_fix` card with green status: `patch_service` applied to `api`. The version bumps from `1.2.0` to `1.2.1`, CVE-2023-22515 is marked unexploitable, and credentials are hardened.
- **Speaker Narration**:
  > *"With simulation proof in hand, the agent executes `apply_fix`. Under our defensive safety design, the agent cannot execute arbitrary shell commands—it can only apply strictly whitelisted actions validated against the lab inventory. It patches the API gateway's critical remote code execution vulnerability and bumps the container version to 1.2.1."*

---

### Segment 5: Re-scan, Verification & Paths Drop to Zero [1:45 – 2:15]
- **Visual**: The agent calls `rescan_and_verify`. The live graph updates: all red dashed attack lines disappear, replaced by clean dark slate edges. The top metric counter animates from **"3"** to **"0"** and turns vibrant emerald green, while the Lab State updates to **"PROTECTED"**. A complete markdown **Remediation Report** renders in the right panel.
- **Speaker Narration**:
  > *"Now comes the closed-loop verification: the agent calls `rescan_and_verify`. It re-probes the Docker network and queries FalkorDB to verify the new state. Look at the counter: verified by re-scan: attack paths dropped from 3 to 0! Every exploit path to the crown jewels has been severed. FalkorDB provides mathematical proof of complete remediation."*

---

### Segment 6: Explain View & Hop-by-Hop Evidence [2:15 – 2:45]
- **Visual**: The presenter clicks **"🔍 Explain Path"**. A modal pops up displaying the detailed hop-by-hop breakdown of the primary path, highlighting the CISA KEV vulnerability details (CVE-2023-38606 on `web` and CVE-2023-22515 on `api`), severity ratings, and network zones. The presenter then clicks **"↺ Reset Lab"** to show the counter restoring to 3 for instant repeatability.
- **Speaker Narration**:
  > *"Every decision is 100% explainable. Clicking 'Explain Path' shows the exact CVE evidence, severity ratings, and network transit mechanisms behind every hop. And when security auditors or demo judges want to test it again, clicking 'Reset Lab' instantly restores the vulnerable baseline."*

---

### Segment 7: Closing Statement [2:45 – 3:00]
- **Visual**: Camera pans back over the full dashboard showing the secured Cytoscape graph, the MCP server terminal, and the automated report.
- **Speaker Narration**:
  > *"This is the power of Track 1: an autonomous AI agent that doesn't just read data—it reasons over connected graphs, safely simulates actions, and closes the loop to guarantee infrastructure security using FalkorDB. Thank you!"*

---

## 🛟 Backup Plan & Contingency Procedures

If unexpected issues occur during live demonstration or video recording:

### 1. Docker Daemon Slow or Not Available
- **Symptom**: Docker is stopped or takes too long to initialize containers.
- **Remedy**: Run the standalone FastAPI app directly via Python:
  ```powershell
  python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
  ```
  The app connects to FalkorDB Cloud / local server and scans local JSON service configs seamlessly without requiring active Docker container daemons.

### 2. Anthropic API Rate-Limiting or Network Hiccup
- **Symptom**: `ANTHROPIC_API_KEY` hits credit limits, 429 rate limit, or network disconnection.
- **Remedy**: No action required! The agent has built-in auto-recovery: it detects the API failure and seamlessly falls back to the deterministic autonomous graph policy, executing all 7 tools without interruption.

### 3. Lab Posture Out of Sync During Recording
- **Symptom**: Attack paths show 0 before starting the demo.
- **Remedy**: Click the **"↺ Reset Lab"** button in the UI header, or run:
  ```powershell
  .\scripts\demo_reset.ps1
  ```
  or via curl:
  ```bash
  curl -X POST http://localhost:8000/reset
  ```
  This immediately reloads the clean baseline templates and restores the 3 vulnerable paths.

### 4. Port Conflict on 8000
- **Symptom**: `address already in use` error when starting FastAPI.
- **Remedy**: Launch on port 8088:
  ```powershell
  python -m uvicorn app.main:app --port 8088
  ```
  and navigate to `http://localhost:8088`.
