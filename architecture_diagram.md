# Architecture Diagram — SentinelFlow

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER / SOC ANALYST                               │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ HTTPS
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     SENTINELFLOW FRONTEND                                │
│                   (Next.js 15 + React 19)                                │
│                                                                         │
│  ┌──────────────┐  ┌───────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ Investigation│  │  Reasoning    │  │   MITRE     │  │  Anomaly  │  │
│  │  Timeline    │  │  Chain View   │  │  ATT&CK Map │  │  Charts   │  │
│  └──────────────┘  └───────────────┘  └─────────────┘  └───────────┘  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ WebSocket (real-time streaming)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     SENTINELFLOW BACKEND                                 │
│                   (Python + FastAPI)                                      │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                 ORCHESTRATOR (LangGraph)                          │   │
│  │            State Machine coordinating all agents                  │   │
│  └───┬──────────┬──────────┬──────────┬──────────┬─────────────────┘   │
│      │          │          │          │          │                       │
│      ▼          ▼          ▼          ▼          ▼                       │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐              │
│  │TRIAGE  │ │INVEST- │ │ANOMALY │ │RESPONSE│ │ REPORT │              │
│  │ AGENT  │ │IGATION │ │ AGENT  │ │ AGENT  │ │ AGENT  │              │
│  │        │ │ AGENT  │ │        │ │        │ │        │              │
│  │•Classif│ │•SPL Gen│ │•Time   │ │•Playbok│ │•Summary│              │
│  │•Sevrity│ │•Correlat│ │ Series│ │•Actions│ │•MITRE  │              │
│  │•IOC Ext│ │•MITRE  │ │•Behav. │ │•Contain│ │•Timelne│              │
│  └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘              │
│      │          │          │          │          │                       │
│      └──────────┴──────────┴──────────┴──────────┘                       │
│                            │                                             │
└────────────────────────────┼─────────────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
┌──────────────────┐ ┌─────────────┐ ┌──────────────────┐
│  SPLUNK MCP      │ │   SPLUNK    │ │  SPLUNK PYTHON   │
│  SERVER          │ │   HOSTED    │ │  SDK             │
│                  │ │   MODELS    │ │                  │
│  • Run SPL       │ │             │ │  • Alert Actions │
│    queries       │ │  • Found-   │ │  • Saved Searches│
│  • Search across │ │    Sec-8B   │ │  • Notable Events│
│    indexes       │ │  • Cisco    │ │  • KV Store ops  │
│  • Get alerts    │ │    Deep TSM │ │  • Risk scores   │
│  • Pull events   │ │             │ │                  │
└────────┬─────────┘ └──────┬──────┘ └────────┬─────────┘
         │                   │                  │
         └───────────────────┼──────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SPLUNK ENTERPRISE                                    │
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │  index:  │  │  index:  │  │  index:  │  │  index:  │              │
│  │  auth    │  │ network  │  │ endpoint │  │   dns    │              │
│  │          │  │          │  │          │  │          │              │
│  │ Windows  │  │ Firewall │  │ Process  │  │  DNS     │              │
│  │ Security │  │ Traffic  │  │ Creation │  │  Queries │              │
│  │ Events   │  │ Logs     │  │ File Ops │  │  Logs    │              │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Alert Ingestion**: Splunk fires an alert → SentinelFlow receives it via MCP Server
2. **Triage**: Triage Agent uses Foundation-Sec-8B to classify the threat and extract IOCs
3. **Investigation**: Investigation Agent generates SPL queries and executes them via MCP Server, iterating through multiple indexes to build a complete picture
4. **Anomaly Detection**: Anomaly Agent feeds time-series data to Cisco Deep Time Series Model to identify behavioral anomalies
5. **Response**: Response Agent uses the Python SDK to create notable events, update risk scores, and recommend containment actions
6. **Reporting**: Report Agent compiles findings into a structured summary with MITRE ATT&CK mapping
7. **Real-time UI**: All agent reasoning streams to the frontend via WebSocket for full transparency

## AI Integration Points

| Component | AI Model/Service | Purpose |
|-----------|-----------------|---------|
| Triage Agent | Foundation-Sec-8B (Splunk Hosted) | Threat classification, IOC extraction |
| Investigation Agent | Claude 3.5 Sonnet + MCP Server | SPL generation, event correlation |
| Anomaly Agent | Cisco Deep Time Series Model (Splunk Hosted) | Behavioral anomaly detection |
| Orchestrator | Claude 3.5 Sonnet (LangGraph) | Agent coordination, decision making |
