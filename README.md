# SentinelFlow — Autonomous AI Security Operations Agent

An autonomous multi-agent system that acts as a tireless SOC analyst — triaging alerts, investigating incidents, detecting anomalies, and recommending responses using Splunk's AI capabilities.

![Architecture](architecture_diagram.md)

## Quick Start

### Prerequisites

- **Docker Desktop** (recommended) OR:
  - Python 3.11+
  - Node.js 20+
- **Splunk Enterprise 10.x** with Developer License
- **Splunk MCP Server** app installed
- **API Key** for Claude (Anthropic) or OpenAI

### Option 1: Docker Compose (Recommended for Judges)

```bash
# Clone the repository
git clone https://github.com/nobelchowdary/splunkagenticops.git
cd splunkagenticops

# Copy environment variables
cp .env.example .env
# Edit .env with your Splunk and LLM API credentials

# Start everything
docker compose up --build
```

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **Splunk Web**: http://localhost:8000 (if using Docker Splunk)

### Option 2: Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (in another terminal)
cd frontend
npm install
npm run dev
```

### Load Sample Data into Splunk

**Option A: BOTS Dataset (Recommended for realistic demos)**

Use Splunk's official "Boss of the SOC" dataset — real APT attack data with perfect field extractions:
```bash
# Download BOTSv1 from Splunkbase (3.2GB)
# https://splunkbase.splunk.com/app/2748
# Install via Splunk Web: Apps → Install app from file
```

**Option B: Lightweight custom data (1,666 events)**
```bash
cd splunk/eventgen
python attack_scenario.py
bash upload_to_splunk.sh
```

This generates a multi-stage attack scenario (brute force → credential compromise → lateral movement → data exfiltration).

## How It Works

SentinelFlow uses a multi-agent architecture powered by LangGraph:

1. **Triage Agent** — Classifies alerts, extracts IOCs, assigns severity using Foundation-Sec-8B
2. **Investigation Agent** — Autonomously generates and executes SPL queries via MCP Server, correlates events across indexes
3. **Anomaly Agent** — Uses Cisco Deep Time Series Model to detect behavioral anomalies
4. **Response Agent** — Recommends containment actions, can auto-execute playbooks
5. **Report Agent** — Generates human-readable investigation summaries with MITRE ATT&CK mapping

### Key Architectural Decisions

**Schema-Aware SPL Generation**: Before generating any SPL, the Investigation Agent queries the Splunk environment to discover available indexes, sourcetypes, and field names. This prevents hallucinated queries that reference non-existent data.

**Self-Correction Loop**: If an SPL query returns an error or zero results, the agent autonomously rewrites and retries the query (up to 3 attempts per step), using the error message as context for correction.

**Full Transparency**: Every agent step streams its reasoning, raw SPL queries, raw JSON results, and decision logic to the frontend in real-time. Judges can see exactly how the AI is working — no black boxes.

**Graceful Degradation**: Anomaly and Response agents fall back to simulated outputs if Splunk Hosted Models aren't available, ensuring the demo always works end-to-end.

All agents stream their reasoning in real-time to a Next.js dashboard, giving full visibility into the investigation process.

## Splunk AI Capabilities Used

| Capability | How It's Used |
|-----------|--------------|
| **Splunk MCP Server** | All data queries — agents search indexes, pull alerts, correlate events |
| **Foundation-Sec-8B** (Hosted Model) | Threat classification, IOC extraction, security context |
| **Cisco Deep Time Series Model** (Hosted Model) | Anomaly detection on metrics (login volumes, network traffic) |
| **Splunk Python SDK** | Alert actions, notable event creation, risk score updates |

## Project Structure

```
sentinelflow/
├── backend/          # Python FastAPI + LangGraph agents
├── frontend/         # Next.js real-time dashboard
├── splunk/           # Sample data & Splunk configurations
├── docs/             # Additional documentation
├── docker-compose.yml
├── architecture_diagram.md
└── README.md
```

## Demo Video

[Watch the 3-minute demo →](https://youtube.com/YOUR_VIDEO)

**Scenario demonstrated**: A multi-stage attack (brute force → credential compromise → lateral movement → data exfiltration) is autonomously investigated by SentinelFlow's agents in real-time.

## Tech Stack

- **Backend**: Python, FastAPI, LangGraph, Anthropic Claude
- **Frontend**: Next.js 15, React 19, Tailwind CSS, shadcn/ui
- **AI Models**: Foundation-Sec-8B, Cisco Deep Time Series Model
- **Splunk Integration**: MCP Server, Python SDK
- **Infrastructure**: Docker Compose

## License

MIT — see [LICENSE](LICENSE)
