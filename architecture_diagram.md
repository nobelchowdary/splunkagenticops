# SentinelFlow — Architecture Diagram

## System Overview

SentinelFlow is an autonomous multi-agent AI Security Operations system that investigates security alerts end-to-end — triaging, correlating, detecting anomalies, and recommending responses — with full real-time transparency via WebSocket streaming.

```mermaid
graph TB
    subgraph USER["👤 Security Analyst"]
        Browser["Web Browser"]
    end

    subgraph FRONTEND["Frontend — Next.js 15 + React 19"]
        Dashboard["Investigation Dashboard<br/>(Real-time Streaming UI)"]
        AlertInput["Alert Input Panel<br/>(Manual + Sample Alerts)"]
        InvPage["Investigation Page<br/>(Live Agent Reasoning Chain)"]
    end

    subgraph BACKEND["Backend — Python FastAPI"]
        API["REST API<br/>/api/investigations"]
        WS["WebSocket Server<br/>/ws/{investigation_id}"]
        
        subgraph ORCHESTRATOR["LangGraph Orchestrator"]
            StateMachine["State Machine<br/>(Investigation Lifecycle)"]
        end
        
        subgraph AGENTS["5 Specialized AI Agents"]
            Triage["🔍 Triage Agent<br/>Classification + IOC Extraction"]
            Investigator["🕵️ Investigation Agent<br/>Autonomous SPL Generation"]
            Anomaly["📊 Anomaly Agent<br/>Behavioral Analysis"]
            Responder["🛡️ Response Agent<br/>Containment Playbooks"]
            Reporter["📋 Report Agent<br/>MITRE Mapping + Summary"]
        end
        
        subgraph TOOLS["Tool Layer"]
            SplunkSDK["Splunk Python SDK<br/>(Primary Data Access)"]
            MCP["Splunk MCP Client<br/>(With SDK Fallback)"]
            HostedModels["Hosted Models Client<br/>(Foundation-Sec + DTSM)"]
            SchemaDiscovery["Schema Discovery<br/>(Dynamic Index Mapping)"]
        end
    end

    subgraph SPLUNK["Splunk Enterprise 10.4"]
        SplunkAPI["REST API :8089"]
        HEC["HTTP Event Collector :8088"]
        
        subgraph INDEXES["Data Indexes"]
            Auth["auth_logs<br/>(705 events)"]
            Network["network_traffic<br/>(370 events)"]
            DNS["dns_logs<br/>(430 events)"]
            Endpoint["endpoint_logs<br/>(161 events)"]
        end
    end

    subgraph AI["AI Models"]
        Claude["Claude Sonnet 4<br/>(Anthropic API)<br/>Agent Reasoning Engine"]
        FoundSec["Foundation-Sec-8B<br/>(Threat Classification)"]
        DTSM["Cisco Deep Time Series<br/>(Anomaly Detection)"]
    end

    %% User to Frontend
    Browser --> Dashboard
    Browser --> AlertInput
    Browser --> InvPage

    %% Frontend to Backend
    AlertInput -- "POST /api/investigations" --> API
    InvPage -- "WebSocket bidirectional" --> WS

    %% Backend Internal Flow
    API --> StateMachine
    StateMachine --> Triage
    Triage --> Investigator
    Investigator --> Anomaly
    Anomaly --> Responder
    Responder --> Reporter
    
    %% Agents to Tools
    Triage --> HostedModels
    Investigator --> SplunkSDK
    Investigator --> SchemaDiscovery
    Anomaly --> SplunkSDK
    Anomaly --> HostedModels
    Responder --> SplunkSDK
    Reporter --> Claude

    %% Tools to External
    SplunkSDK --> SplunkAPI
    MCP --> SplunkAPI
    HostedModels --> Claude
    HostedModels --> FoundSec
    HostedModels --> DTSM
    SplunkAPI --> Auth
    SplunkAPI --> Network
    SplunkAPI --> DNS
    SplunkAPI --> Endpoint

    %% WebSocket streaming
    StateMachine -- "Real-time updates" --> WS

    %% HEC for writing
    SplunkSDK -- "Notable Events" --> HEC
```

---

## Data Flow: End-to-End Investigation

This sequence diagram shows the complete lifecycle of an autonomous security investigation, from alert submission to final report delivery.

```mermaid
sequenceDiagram
    participant Analyst as 👤 Analyst
    participant UI as Next.js Frontend
    participant API as FastAPI Backend
    participant Orch as LangGraph Orchestrator
    participant Triage as Triage Agent
    participant Invest as Investigation Agent
    participant Anom as Anomaly Agent
    participant Resp as Response Agent
    participant Report as Report Agent
    participant Splunk as Splunk Enterprise
    participant LLM as Claude (Anthropic)
    participant Models as Hosted Models

    Analyst->>UI: Submit security alert
    UI->>API: POST /api/investigations
    API->>Orch: Create investigation
    API->>UI: Return investigation_id
    UI->>API: Connect WebSocket /ws/{id}
    
    Note over Orch: Phase 1 — TRIAGE
    Orch->>Triage: Classify alert
    Triage->>Models: Foundation-Sec-8B classification
    Models->>LLM: Claude fallback (structured JSON)
    LLM-->>Models: severity, category, iocs
    Models-->>Triage: Classification result
    Triage-->>Orch: Severity 8/10, IOCs extracted
    Orch-->>UI: Stream triage_complete

    Note over Orch: Phase 2 — INVESTIGATION (Autonomous)
    Orch->>Invest: Investigate with context
    Invest->>Splunk: Schema discovery query
    Splunk-->>Invest: Available fields and indexes
    
    loop Autonomous SPL Loop (up to 10 iterations)
        Invest->>LLM: Generate SPL from findings
        LLM-->>Invest: SPL query
        Invest-->>UI: Stream spl_query
        Invest->>Splunk: Execute SPL search
        Splunk-->>Invest: Results
        Invest-->>UI: Stream results + reasoning
        
        alt SPL Error
            Invest->>LLM: Self-correct with error context
            LLM-->>Invest: Corrected SPL
            Invest-->>UI: Stream self_correcting
        end
        
        Invest->>LLM: Analyze results, decide next step
        LLM-->>Invest: Next query or conclude
    end
    
    Invest-->>Orch: Investigation findings
    Orch-->>UI: Stream investigation_complete

    Note over Orch: Phase 3 — ANOMALY DETECTION
    Orch->>Anom: Detect anomalies
    Anom->>Splunk: Pull time-series metrics
    Splunk-->>Anom: Historical data
    Anom->>Models: Cisco DTSM analysis
    Note over Models: Z-score + IQR + Rate-of-change<br/>Multi-method consensus scoring
    Models-->>Anom: Anomaly scores
    Anom-->>Orch: Behavioral anomalies found
    Orch-->>UI: Stream anomalies_detected

    Note over Orch: Phase 4 — RESPONSE
    Orch->>Resp: Generate response plan
    Resp->>LLM: Recommend actions
    LLM-->>Resp: Prioritized containment actions
    Resp->>Splunk: Create notable event
    Resp-->>Orch: Response recommendations
    Orch-->>UI: Stream response_ready

    Note over Orch: Phase 5 — REPORT
    Orch->>Report: Generate summary
    Report->>LLM: Compile findings + MITRE mapping
    LLM-->>Report: Executive report
    Report-->>Orch: Final report
    Orch-->>UI: Stream investigation_complete
    
    UI->>Analyst: Full report card with MITRE techniques,<br/>affected assets, and recommendations
```

---

## Agent Architecture Detail

Each of the 5 agents has a specialized role with clear inputs, processing logic, and outputs:

```mermaid
graph LR
    subgraph TRIAGE["Triage Agent"]
        T1["Parse Alert Text"]
        T2["Extract IOCs<br/>(IPs, Domains, Hashes)<br/>via Regex"]
        T3["Classify Threat<br/>(Foundation-Sec-8B → Claude → Keywords)"]
        T4["Assign Severity (1-10)"]
        T1 --> T2 --> T3 --> T4
    end

    subgraph INVESTIGATION["Investigation Agent — Autonomous SPL Loop"]
        I1["Schema Discovery<br/>(Index fields + sample data)"]
        I2["LLM Prompt Construction<br/>(Schema + Alert + Prior Findings)"]
        I3["SPL Generation<br/>(Claude produces valid SPL)"]
        I4["Execute on Splunk<br/>(oneshot search via SDK)"]
        I5["Analyze Results<br/>(LLM interprets data)"]
        I6{"More to<br/>investigate?"}
        I7["Self-Correction<br/>(up to 3 retries per query)"]
        
        I1 --> I2 --> I3 --> I4 --> I5 --> I6
        I6 -- "Yes" --> I2
        I6 -- "No" --> I8["Compile Findings"]
        I4 -- "SPL Error" --> I7 --> I3
    end

    subgraph ANOMALY["Anomaly Agent — Multi-Method Detection"]
        A1["Pull Baseline Metrics<br/>(auth, network, endpoint)"]
        A2["Z-Score Analysis<br/>(standard deviations)"]
        A3["IQR Outlier Detection<br/>(interquartile range)"]
        A4["Rate-of-Change Detection<br/>(gradient analysis)"]
        A5["Consensus Scoring<br/>(flag if 2+ methods agree)"]
        
        A1 --> A2
        A1 --> A3
        A1 --> A4
        A2 --> A5
        A3 --> A5
        A4 --> A5
    end

    subgraph RESPONSE["Response Agent"]
        R1["Match Threat Category to Playbook"]
        R2["Generate Containment Actions<br/>(Block IP, Disable Account, Isolate Host)"]
        R3["Confidence Scoring per Action"]
        R4["Create Splunk Notable Event"]
        R1 --> R2 --> R3 --> R4
    end

    subgraph REPORT["Report Agent"]
        RP1["Compile Full Evidence Chain"]
        RP2["Map to MITRE ATT&CK Framework"]
        RP3["Generate Executive Summary"]
        RP4["List Affected Assets and Users"]
        RP5["Prioritize Recommendations"]
        RP1 --> RP2 --> RP3 --> RP4 --> RP5
    end
```

---

## Splunk Integration Architecture

Shows how the application accesses Splunk data via the Python SDK (primary) and MCP Client (with SDK fallback):

```mermaid
graph TB
    subgraph APP["SentinelFlow Application"]
        SDK["Splunk Python SDK<br/>(splunk-sdk)"]
        MCPClient["MCP Client<br/>(falls back to SDK<br/>when MCP unavailable)"]
        HECWriter["HEC Writer<br/>(write notable events)"]
        SchemaDisc["Schema Discovery<br/>(auto-detect fields per index)"]
    end

    subgraph SPLUNK_CORE["Splunk Enterprise 10.4"]
        REST["Management REST API<br/>https://localhost:8089"]
        HECPORT["HTTP Event Collector<br/>http://localhost:8088"]
        SearchHead["Search Head<br/>(SPL execution engine)"]
        
        subgraph DATA["Security Data Lake"]
            I1["index=auth_logs<br/>• Windows 4624/4625 events<br/>• Login attempts + failures<br/>• Source IPs, usernames, geo"]
            I2["index=network_traffic<br/>• Firewall logs<br/>• Connection metadata<br/>• Bytes in/out, protocols"]
            I3["index=dns_logs<br/>• DNS queries + responses<br/>• Domain lookups<br/>• Suspicious resolution patterns"]
            I4["index=endpoint_logs<br/>• Process creation events<br/>• File access + modification<br/>• Registry changes"]
        end
    end

    %% Connections
    SDK -- "Auth: username/password<br/>Method: oneshot search<br/>Format: output_mode=json" --> REST
    MCPClient -- "Fallback route<br/>(when MCP token empty)" --> SDK
    HECWriter -- "POST JSON events<br/>Token: HEC auth" --> HECPORT
    SchemaDisc -- "| metadata type=sourcetypes<br/>| fieldsummary" --> SDK
    REST --> SearchHead
    SearchHead --> I1
    SearchHead --> I2
    SearchHead --> I3
    SearchHead --> I4
```

---

## AI Model Integration — Fallback Chain

Every external AI capability has graceful degradation. If the primary service is unavailable, the system falls back to alternatives without failing:

```mermaid
graph TB
    subgraph FOUNDSEC["Foundation-Sec-8B — Threat Classification"]
        FS1["Primary: Splunk Hosted Endpoint<br/>(ml/v1/predict)"]
        FS2["Fallback 1: Claude LLM<br/>(Structured JSON classification<br/>with security domain prompt)"]
        FS3["Fallback 2: Keyword Heuristic<br/>(Pattern matching on alert text)"]
        FS1 -. "HTTP error or timeout" .-> FS2
        FS2 -. "API unavailable" .-> FS3
    end
    
    subgraph CISCO["Cisco DTSM — Anomaly Detection"]
        CD1["Primary: Splunk Hosted Endpoint<br/>(ml/v1/anomaly)"]
        CD2["Fallback: Multi-Method Statistical Analysis"]
        CD1 -. "HTTP error or timeout" .-> CD2
        
        subgraph STATS["Statistical Methods (run in parallel)"]
            S1["Z-Score<br/>(|z| > 2.0 = anomaly)"]
            S2["IQR Outlier<br/>(> Q3 + 1.5*IQR)"]
            S3["Rate-of-Change<br/>(gradient > 50% baseline)"]
        end
        CD2 --> STATS
    end

    subgraph CONSENSUS["Consensus Engine"]
        CON["Flag anomaly only when<br/>2+ methods agree<br/>(reduces false positives)"]
    end

    STATS --> CON

    subgraph CLAUDE["Claude Sonnet 4 — Core Reasoning"]
        CL1["SPL Query Generation<br/>(from natural language + schema)"]
        CL2["Result Analysis<br/>(interpret Splunk data)"]
        CL3["Threat Classification<br/>(structured JSON output)"]
        CL4["Report Generation<br/>(MITRE mapping, summaries)"]
        CL5["Self-Correction<br/>(fix SPL errors with context)"]
    end
```

---

## Real-Time Streaming Architecture

Every agent action is streamed to the frontend in real-time, providing full transparency into the AI's reasoning process:

```mermaid
graph LR
    subgraph BACKEND["FastAPI Backend"]
        Agent["Agent Execution<br/>(asyncio)"]
        Queue["Update Queue<br/>(per investigation)"]
        WSHandler["WebSocket Handler<br/>(JSON serialization)"]
    end

    subgraph MESSAGES["Streamed Message Types"]
        M1["type: phase<br/>Agent phase transitions<br/>(triage → investigation → ...)"]
        M2["type: agent_action<br/>SPL queries, reasoning,<br/>self-corrections, results"]
        M3["type: agent_result<br/>Phase completion with<br/>structured findings"]
        M4["type: status<br/>Investigation lifecycle<br/>(starting, completed, error)"]
    end

    subgraph FRONTEND["Next.js Frontend"]
        WSClient["WebSocket Client<br/>(auto-reconnect)"]
        State["React State<br/>(updates array)"]
        UI["UI Rendering"]
        
        subgraph COMPONENTS["Visual Components"]
            Phase["Phase Progress Sidebar<br/>(5 phases with status)"]
            Chain["Agent Reasoning Chain<br/>(expandable cards)"]
            SPL["SPL Query Display<br/>(syntax highlighted)"]
            Report["Report Card<br/>(MITRE + recommendations)"]
            Timer["Elapsed Time Counter"]
        end
    end

    Agent --> Queue --> WSHandler
    WSHandler -- "JSON over WebSocket" --> WSClient
    WSClient --> State --> UI
    UI --> COMPONENTS
    
    WSHandler --> M1
    WSHandler --> M2
    WSHandler --> M3
    WSHandler --> M4
```

---

## Deployment Architecture

```mermaid
graph TB
    subgraph LOCAL["Deployment Environment"]
        subgraph DOCKER["Docker Compose (single command setup)"]
            FE["frontend<br/>Next.js on :3000<br/>(Production build)"]
            BE["backend<br/>FastAPI + Uvicorn on :8000<br/>(Python 3.11)"]
            Redis["redis<br/>Session + investigation cache"]
        end
        
        Splunk["Splunk Enterprise<br/>:8001 (Web UI)<br/>:8089 (REST API)<br/>:8088 (HEC)"]
    end

    subgraph EXTERNAL["External Services"]
        Anthropic["Anthropic API<br/>claude-sonnet-4-6<br/>(LLM reasoning engine)"]
    end

    FE -- "HTTP + WebSocket :8000" --> BE
    BE -- "splunk-sdk (TCP :8089)" --> Splunk
    BE -- "HEC (HTTP :8088)" --> Splunk
    BE -- "HTTPS" --> Anthropic
    BE -- "TCP :6379" --> Redis
```

---

## Technology Stack

| Layer | Technology | Role in SentinelFlow |
|-------|-----------|------|
| **Frontend** | Next.js 15, React 19, Tailwind CSS, Lucide Icons | Real-time investigation dashboard with WebSocket streaming |
| **Backend** | Python 3.11, FastAPI, Uvicorn | REST API + WebSocket server hosting all agents |
| **Agent Framework** | LangGraph (LangChain) | Multi-agent state machine orchestration with phase transitions |
| **Primary LLM** | Claude Sonnet 4 (Anthropic) | Agent reasoning, SPL generation, result analysis, reports |
| **Security AI** | Foundation-Sec-8B (Splunk Hosted) | Threat classification, severity scoring, IOC extraction |
| **Time Series AI** | Cisco DTSM (Splunk Hosted) | Multi-method anomaly detection with consensus scoring |
| **Data Platform** | Splunk Enterprise 10.4 | Security data lake — auth, network, DNS, endpoint logs |
| **Splunk Access** | Splunk Python SDK + MCP Client | Query execution (oneshot), event writing, schema discovery |
| **Caching** | Redis | Investigation state persistence, response caching |
| **Deployment** | Docker Compose | Single `docker-compose up` setup for judges |

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Autonomous Investigation Loop** | Investigation Agent runs up to 10 SPL queries iteratively with self-correction (3 retries). No human intervention needed for standard investigations. |
| **Graceful Degradation** | Every external service has a fallback: MCP → SDK, Foundation-Sec → Claude → Keywords, DTSM → Statistical methods. System never fails due to a single service outage. |
| **Real-Time Transparency** | Every agent thought, SPL query, and decision is streamed via WebSocket. Judges see the AI reason live — this is the core differentiator. |
| **Schema-Aware SPL Generation** | Before generating queries, the system discovers available indexes, fields, and sample data to produce valid SPL on the first attempt. |
| **Multi-Method Consensus** | Anomaly detection uses 3 independent statistical methods. An anomaly is flagged only when ≥2 methods agree, reducing false positives. |
| **MITRE ATT&CK Mapping** | Every finding is mapped to MITRE techniques, providing standardized threat intelligence that security teams expect. |
