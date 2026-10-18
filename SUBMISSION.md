# FalkorDB Graph Hacks Hackathon Submission Pack

## Project Name
**Closed-Loop Attack-Path Agent**

---

## Track
**Track 1: Agents That Act on Connected Data**

---

## One-Line Pitch (128 characters)
Autonomous cybersecurity agent using FalkorDB to discover, simulate, and eliminate multi-hop attack paths in container networks.

---

## Short Description (97 words)
Modern container architectures expose complex multi-hop attack paths where attackers breach perimeter servers and traverse internal segments to reach crown jewel databases. Traditional vulnerability scanners report isolated CVEs without understanding network connectivity. The Closed-Loop Attack-Path Agent solves this using FalkorDB. It maps Docker network segmentation and service postures into a connected property graph, executes Cypher traversals and centrality algorithms to isolate the primary choke point, safely simulates remediations in isolated graph copies via `GRAPH.COPY`, executes whitelisted fixes on live containers, and verifies by re-scanning that attack paths dropped from 3 to 0.

---

## Long Description (248 words)
Modern enterprise infrastructures are composed of segmented virtual networks and microservices. When multiple vulnerabilities, exposed ports, and weak credentials exist simultaneously, attackers don't view them as isolated issues—they traverse multi-hop attack paths across security zones to compromise mission-critical crown jewels. Traditional point scanners overwhelm security engineers with hundreds of uncontextualized CVEs, making it nearly impossible to determine which vulnerability poses genuine risk.

The Closed-Loop Attack-Path Agent introduces an autonomous, graph-native approach to infrastructure defense. Built specifically for FalkorDB Graph Hacks (Track 1), the system operates in an automated closed loop: Detect, Decide, Simulate, Act, and Verify. 

First, the agent inspects the Docker environment and constructs a high-fidelity property graph in FalkorDB modeling services, network reachability, vulnerabilities, and crown jewel assets. Next, Cypher traversals discover all paths reaching protected databases, while betweenness centrality and PageRank identify the single architectural choke point (`api`) that intersects every attack path.

Crucially, before touching production infrastructure, the agent calls `GRAPH.COPY lab lab_sim` to clone the graph into a lightweight sandbox. It simulates candidate fixes inside `lab_sim` to mathematically prove which remediation yields the largest attack path reduction. Once validated, the agent enforces a strict defensive whitelist (`patch_service`, `rotate_credential`, `disconnect_network`) to apply the optimal patch to the live container. Finally, the agent re-scans the live environment and verifies that active attack paths dropped from 3 to 0, providing complete explainable proof of remediation.

---

## How FalkorDB is Used (5 Bullets)
1. **Multi-Hop Attack Path Discovery**: Executes variable-length Cypher traversals (`(:Attacker)-[:EXPLOITABLE_FROM*1..5]->(:Service)-[:HOLDS]->(:CrownJewel)`) to find all traversal chains reaching critical assets.
2. **Graph Centrality & Choke Point Analysis**: Computes betweenness centrality and path intersection frequencies in Cypher to identify high-leverage architectural choke points.
3. **Safe Sandbox Simulation via `GRAPH.COPY`**: Clones the live graph into `lab_sim` in sub-milliseconds to simulate remediation actions in isolation without mutating production state.
4. **Graph-Driven MCP Agent Tools**: Exposes 7 Cypher-powered analysis, simulation, and verification tools over the Model Context Protocol (FastMCP) for autonomous LLM tool selection.
5. **Re-Scan Verification & Proof**: Executes Cypher verification queries following remediation to prove that active attack paths decreased from 3 to 0.

---

## Tech Stack List
- **Graph Database & Query Engine**: FalkorDB (Cypher, Graph Algorithms, `GRAPH.COPY`)
- **Backend & API**: Python 3.12, FastAPI, Uvicorn, SSE-Starlette (Server-Sent Events)
- **Agent Orchestration**: Anthropic Python SDK (Claude 3.5 Sonnet tool-use loop) with deterministic autonomous graph policy fallback
- **Agent Protocols**: Model Context Protocol (FastMCP / MCPServer)
- **Infrastructure & Containerization**: Docker, Docker Compose, Docker SDK for Python
- **Frontend & Visualization**: Cytoscape.js, Vanilla CSS, HTML5, JetBrains Mono & Outfit fonts
- **Testing & Verification**: Pytest, HTTPX

---

## Links (Placeholders)
- **GitHub Repository**: `https://github.com/<your-username>/closed-loop-attack-path-agent`
- **Demo Video (3 Minutes)**: `https://youtu.be/<your-video-id>`
- **Live Interactive Demo**: `http://<your-deployment-host>:8000`
- **Technical Blog Post**: Included in repo as `BLOG.md` / `https://dev.to/<your-username>/giving-an-ai-agent-a-graph-closing-attack-paths-with-falkordb`

---

## Challenges and What I Learned (5 Bullets)
1. **Safe Simulation in Production Graphs**: Learned how `GRAPH.COPY` solves a fundamental challenge in agentic AI by providing an instant, sub-millisecond graph sandbox to evaluate candidate actions before executing live infrastructure changes.
2. **Translating Multi-Layer Network Segmentation to Graph Edges**: Learned to dynamically model container network boundaries, open ports, and CVE exploitability into unified `EXPLOITABLE_FROM` relationships that reflect real-world lateral movement.
3. **Choke Point Prioritization vs. Vulnerability Count**: Discovered that graph betweenness centrality allows security agents to neutralize 100% of attack paths with a single targeted patch on the API gateway, eliminating the need to patch all CVEs indiscriminately.
4. **Standardizing Agent Tool Protocols**: Integrated FastMCP and SSE-Starlette to ensure the same graph tools could seamlessly serve both external MCP desktop clients and interactive browser frontends simultaneously.
5. **Fail-Safe Defensive Agent Design**: Enforced strict defensive whitelisting on container remediation to ensure autonomous agents can never execute arbitrary commands or disrupt unapproved network services.
