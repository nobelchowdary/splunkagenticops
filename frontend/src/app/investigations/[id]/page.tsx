"use client";

import { useEffect, useState, useRef } from "react";
import {
  Shield,
  Clock,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  Database,
  Brain,
  Zap,
  RefreshCw,
  CheckCircle,
  XCircle,
  Timer,
  TrendingDown,
  MessageSquare,
  Send,
  Target,
} from "lucide-react";

interface AgentUpdate {
  type: string;
  agent?: string;
  phase?: string;
  action?: string;
  detail?: string;
  message?: string;
  status?: string;
  spl_query?: string;
  reasoning?: string;
  result?: Record<string, unknown>;
  result_count?: number;
  raw_results?: Record<string, unknown>[];
  raw_data?: Record<string, unknown>;
}

const AGENT_COLORS: Record<string, string> = {
  triage: "text-amber-400 border-amber-500/30",
  investigation: "text-sky-400 border-sky-500/30",
  anomaly: "text-purple-400 border-purple-500/30",
  response: "text-red-400 border-red-500/30",
  report: "text-green-400 border-green-500/30",
};

const AGENT_BG: Record<string, string> = {
  triage: "bg-amber-500/5",
  investigation: "bg-sky-500/5",
  anomaly: "bg-purple-500/5",
  response: "bg-red-500/5",
  report: "bg-green-500/5",
};

const AGENT_ICONS: Record<string, typeof Shield> = {
  triage: AlertTriangle,
  investigation: Database,
  anomaly: Brain,
  response: Zap,
  report: Shield,
};

const ACTION_ICONS: Record<string, typeof Shield> = {
  reasoning: Brain,
  querying: Database,
  results: CheckCircle,
  spl_error: XCircle,
  self_correcting: RefreshCw,
  classifying: Brain,
  schema_loaded: Database,
};

// MITRE ATT&CK Tactic Categories for heatmap visualization
const MITRE_TACTICS = [
  { id: "TA0001", name: "Initial Access", short: "IA" },
  { id: "TA0002", name: "Execution", short: "EX" },
  { id: "TA0003", name: "Persistence", short: "PE" },
  { id: "TA0004", name: "Privilege Escalation", short: "PR" },
  { id: "TA0005", name: "Defense Evasion", short: "DE" },
  { id: "TA0006", name: "Credential Access", short: "CA" },
  { id: "TA0007", name: "Discovery", short: "DI" },
  { id: "TA0008", name: "Lateral Movement", short: "LM" },
  { id: "TA0009", name: "Collection", short: "CO" },
  { id: "TA0010", name: "Exfiltration", short: "EX" },
  { id: "TA0011", name: "Command & Control", short: "C2" },
];

// Map technique IDs to their tactics
const TECHNIQUE_TO_TACTIC: Record<string, string[]> = {
  "T1110": ["TA0006"], // Brute Force → Credential Access
  "T1078": ["TA0001", "TA0003", "TA0004", "TA0005"], // Valid Accounts
  "T1021": ["TA0008"], // Remote Services → Lateral Movement
  "T1071": ["TA0011"], // Application Layer Protocol → C2
  "T1048": ["TA0010"], // Exfiltration Over Alternative Protocol
  "T1059": ["TA0002"], // Command and Scripting Interpreter
  "T1003": ["TA0006"], // OS Credential Dumping
  "T1570": ["TA0008"], // Lateral Tool Transfer
  "T1105": ["TA0011"], // Ingress Tool Transfer
  "T1018": ["TA0007"], // Remote System Discovery
  "T1046": ["TA0007"], // Network Service Discovery
  "T1547": ["TA0003", "TA0004"], // Boot or Logon Autostart Execution
  "T1190": ["TA0001"], // Exploit Public-Facing Application
  "T1566": ["TA0001"], // Phishing
};

function MitreHeatmap({ techniques }: { techniques: string[] }) {
  // Determine which tactics are "hit" by the detected techniques
  const activeTactics = new Set<string>();
  const tacticTechniques: Record<string, string[]> = {};
  
  techniques.forEach((tech) => {
    const baseId = tech.split(".")[0]; // Handle sub-techniques like T1110.001
    const tactics = TECHNIQUE_TO_TACTIC[baseId] || [];
    tactics.forEach((tactic) => {
      activeTactics.add(tactic);
      if (!tacticTechniques[tactic]) tacticTechniques[tactic] = [];
      tacticTechniques[tactic].push(tech);
    });
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 mb-2">
        <Target className="h-4 w-4 text-red-400" />
        <h4 className="text-xs font-semibold text-slate-400 uppercase">MITRE ATT&CK Coverage</h4>
      </div>
      <div className="grid grid-cols-11 gap-1">
        {MITRE_TACTICS.map((tactic) => {
          const isActive = activeTactics.has(tactic.id);
          const techsInTactic = tacticTechniques[tactic.id] || [];
          return (
            <div
              key={tactic.id}
              className={`mitre-cell relative group rounded-md p-2 text-center border ${
                isActive
                  ? "bg-red-500/20 border-red-500/50 shadow-lg shadow-red-500/10"
                  : "bg-slate-800/30 border-slate-700/30"
              }`}
            >
              <div className={`text-[10px] font-bold ${isActive ? "text-red-300" : "text-slate-600"}`}>
                {tactic.short}
              </div>
              <div className={`text-[8px] mt-0.5 ${isActive ? "text-red-400" : "text-slate-700"}`}>
                {tactic.name.split(" ").slice(0, 2).join(" ")}
              </div>
              {isActive && (
                <div className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-red-400 animate-pulse" />
              )}
              {/* Tooltip */}
              {isActive && (
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-20">
                  <div className="bg-slate-900 border border-red-500/30 rounded-md p-2 text-[10px] whitespace-nowrap shadow-xl">
                    <div className="text-red-300 font-semibold">{tactic.name}</div>
                    {techsInTactic.map((t, i) => (
                      <div key={i} className="text-slate-300">{t}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-4 text-[10px] text-slate-500 mt-1">
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-sm bg-red-500/20 border border-red-500/50" />
          <span>Detected</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-sm bg-slate-800/30 border border-slate-700/30" />
          <span>Not observed</span>
        </div>
        <span className="ml-auto">{activeTactics.size}/{MITRE_TACTICS.length} tactics covered</span>
      </div>
    </div>
  );
}

function AttackTimeline({ techniques }: { techniques: string[] }) {
  // Simulated timeline order based on typical kill chain progression
  const timelineOrder = ["T1190", "T1566", "T1110", "T1078", "T1059", "T1003", "T1547", "T1018", "T1046", "T1021", "T1570", "T1071", "T1105", "T1048"];
  const sorted = techniques.sort((a, b) => {
    const aBase = a.split(".")[0];
    const bBase = b.split(".")[0];
    return timelineOrder.indexOf(aBase) - timelineOrder.indexOf(bBase);
  });

  const TECHNIQUE_NAMES: Record<string, string> = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1071": "App Layer Protocol",
    "T1048": "Exfil Over Alt Protocol",
    "T1059": "Scripting Interpreter",
    "T1003": "Credential Dumping",
    "T1570": "Lateral Tool Transfer",
    "T1105": "Ingress Tool Transfer",
    "T1018": "Remote System Discovery",
    "T1046": "Network Service Discovery",
    "T1547": "Boot Autostart Execution",
    "T1190": "Exploit Public App",
    "T1566": "Phishing",
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Clock className="h-4 w-4 text-sky-400" />
        <h4 className="text-xs font-semibold text-slate-400 uppercase">Attack Kill Chain Timeline</h4>
      </div>
      <div className="relative pl-6 space-y-3">
        {sorted.map((tech, idx) => {
          const baseId = tech.split(".")[0];
          const name = TECHNIQUE_NAMES[baseId] || tech;
          const tactics = TECHNIQUE_TO_TACTIC[baseId] || [];
          const tacticName = tactics.length > 0 
            ? MITRE_TACTICS.find(t => t.id === tactics[0])?.name || ""
            : "";
          
          return (
            <div key={idx} className={`relative ${idx < sorted.length - 1 ? "timeline-connector" : ""}`}>
              <div className="absolute left-0 top-1 h-3 w-3 rounded-full bg-red-500/50 border-2 border-red-400" />
              <div className="ml-6 flex items-center gap-2">
                <span className="font-mono text-xs text-red-300 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                  {tech}
                </span>
                <span className="text-xs text-slate-300">{name}</span>
                <span className="text-[10px] text-slate-500 ml-auto">{tacticName}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TimeSavedBanner({ elapsed }: { elapsed: number }) {
  const manualMinutes = 45;
  const manualSeconds = manualMinutes * 60;
  const reduction = Math.round(((manualSeconds - elapsed) / manualSeconds) * 100);
  
  return (
    <div className="animate-slide-up glass-card p-5 border border-sky-500/30 bg-gradient-to-r from-sky-500/5 via-green-500/5 to-sky-500/5 glow-border">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-12 w-12 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center">
            <TrendingDown className="h-6 w-6 text-green-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">Investigation Time Saved</p>
            <p className="text-xs text-slate-400">Compared to manual SOC analyst investigation</p>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-center">
            <p className="text-xs text-slate-500 uppercase">Manual</p>
            <p className="text-lg font-bold text-slate-400 line-through">45 min</p>
          </div>
          <div className="text-2xl text-slate-600">→</div>
          <div className="text-center">
            <p className="text-xs text-sky-400 uppercase">SentinelFlow</p>
            <p className="text-lg font-bold text-sky-300 animate-count-up">
              {elapsed}s
            </p>
          </div>
          <div className="text-center pl-4 border-l border-slate-700">
            <p className="text-xs text-green-400 uppercase">Reduction</p>
            <p className="text-2xl font-black text-green-400 animate-count-up">
              {reduction}%
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ExpandableSection({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="mt-2">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-300 transition"
      >
        {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {title}
      </button>
      {isOpen && <div className="mt-1.5 animate-fade-in">{children}</div>}
    </div>
  );
}

export default function InvestigationPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const [updates, setUpdates] = useState<AgentUpdate[]>([]);
  const [connected, setConnected] = useState(false);
  const [currentPhase, setCurrentPhase] = useState<string>("starting");
  const [investigationId, setInvestigationId] = useState<string>("");
  const [stepCount, setStepCount] = useState(0);
  const [retryCount, setRetryCount] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [startTime] = useState(Date.now());
  const [elapsed, setElapsed] = useState(0);
  const [followUpQuery, setFollowUpQuery] = useState("");
  const [isAsking, setIsAsking] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    params.then((p) => setInvestigationId(p.id));
  }, [params]);

  // Elapsed time counter
  useEffect(() => {
    if (isComplete) return;
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [startTime, isComplete]);

  useEffect(() => {
    if (!investigationId) return;

    const wsUrl = `${process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000"}/ws/${investigationId}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      const data: AgentUpdate = JSON.parse(event.data);
      setUpdates((prev) => [...prev, data]);

      if (data.type === "phase") {
        setCurrentPhase(data.phase || "");
      }
      if (data.action === "results" || data.action === "concluded") {
        setStepCount((c) => c + 1);
      }
      if (data.action === "self_correcting") {
        setRetryCount((c) => c + 1);
      }
      if (data.type === "status" && data.status === "completed") {
        setIsComplete(true);
      }
    };

    return () => ws.close();
  }, [investigationId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [updates]);

  const phases = ["triage", "investigation", "anomaly", "response", "report"];

  const handleFollowUp = async () => {
    if (!followUpQuery.trim() || isAsking) return;
    setIsAsking(true);
    
    // Add the user's question as a visible update
    const userUpdate: AgentUpdate = {
      type: "agent_action",
      agent: "investigation",
      action: "reasoning",
      detail: `Follow-up question: "${followUpQuery}"`,
      reasoning: "Processing interactive follow-up query from analyst...",
    };
    setUpdates((prev) => [...prev, userUpdate]);
    setIsComplete(false);
    setCurrentPhase("investigation");

    try {
      // Send follow-up via the API
      await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/investigations/${investigationId}/followup`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: followUpQuery }),
        }
      );
    } catch (error) {
      console.error("Follow-up failed:", error);
    }
    
    setFollowUpQuery("");
    setIsAsking(false);
  };

  return (
    <main className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-sky-500" />
            <h1 className="text-xl font-bold text-white">SentinelFlow</h1>
            <span className="text-slate-500">/</span>
            <span className="text-slate-300 font-mono text-sm">
              {investigationId?.slice(0, 8)}...
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Clock className="h-3 w-3" />
              <span className="font-mono">{Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, '0')}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Database className="h-3 w-3" />
              <span>{stepCount} queries</span>
            </div>
            {retryCount > 0 && (
              <div className="flex items-center gap-2 text-xs text-amber-400">
                <RefreshCw className="h-3 w-3" />
                <span>{retryCount} self-corrections</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <div
                className={`h-2 w-2 rounded-full ${
                  connected ? "bg-green-400 animate-pulse-slow" : "bg-red-400"
                }`}
              />
              <span className="text-xs text-slate-400">
                {connected ? "Live" : "Disconnected"}
              </span>
            </div>
          </div>
        </div>
      </header>

      <div className="flex-1 flex">
        {/* Phase Progress Sidebar */}
        <aside className="w-64 border-r border-slate-800 p-4 flex-shrink-0">
          <h3 className="text-sm font-semibold text-slate-400 uppercase mb-4">
            Investigation Phases
          </h3>
          <div className="space-y-2">
            {phases.map((phase, idx) => {
              const Icon = AGENT_ICONS[phase] || Shield;
              const isActive = currentPhase === phase;
              const isComplete = phases.indexOf(currentPhase) > idx;

              return (
                <div
                  key={phase}
                  className={`flex items-center gap-3 p-3 rounded-lg transition ${
                    isActive
                      ? "bg-sky-500/10 border border-sky-500/30"
                      : isComplete
                      ? "bg-green-500/5 border border-green-500/20"
                      : "border border-transparent"
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 ${
                      isActive
                        ? "text-sky-400"
                        : isComplete
                        ? "text-green-400"
                        : "text-slate-600"
                    }`}
                  />
                  <span
                    className={`text-sm capitalize ${
                      isActive
                        ? "text-sky-300 font-medium"
                        : isComplete
                        ? "text-green-300"
                        : "text-slate-500"
                    }`}
                  >
                    {phase}
                  </span>
                  {isActive && (
                    <div className="ml-auto h-1.5 w-1.5 rounded-full bg-sky-400 animate-pulse" />
                  )}
                  {isComplete && (
                    <span className="ml-auto text-xs text-green-400">✓</span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Live Stats */}
          <div className="mt-6 pt-4 border-t border-slate-800 space-y-3">
            <h4 className="text-xs font-semibold text-slate-500 uppercase">Live Stats</h4>
            <div className="text-xs text-slate-400 space-y-1">
              <p>SPL Queries: <span className="text-white font-mono">{stepCount}</span></p>
              <p>Self-Corrections: <span className="text-amber-400 font-mono">{retryCount}</span></p>
              <p>Updates: <span className="text-white font-mono">{updates.length}</span></p>
            </div>
          </div>
        </aside>

        {/* Main Feed — Agent Reasoning Chain */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-4xl mx-auto space-y-3">
            {updates.length === 0 && (
              <div className="text-center py-20 text-slate-500">
                <Brain className="h-16 w-16 mx-auto mb-4 opacity-30 animate-pulse" />
                <p className="text-lg">Waiting for investigation to begin...</p>
                <p className="text-sm mt-2">
                  Watch the AI agents reason, query Splunk, and investigate in real-time
                </p>
              </div>
            )}

            {updates.map((update, idx) => (
              <div key={idx} className="animate-fade-in">
                {/* Status Messages */}
                {update.type === "status" && update.status === "starting" && (
                  <div className="flex items-center gap-3 p-4 glass-card border-l-2 border-sky-500/30 bg-sky-500/5">
                    <div className="h-2 w-2 rounded-full bg-sky-400 animate-pulse" />
                    <p className="text-sm text-sky-300">{update.message || "Investigation starting..."}</p>
                  </div>
                )}

                {/* Phase Dividers */}
                {update.type === "phase" && (
                  <div className="flex items-center gap-2 py-4">
                    <div className="flex-1 h-px bg-slate-700" />
                    <span className={`text-xs font-semibold uppercase px-3 py-1 rounded-full ${
                      update.status === "completed"
                        ? "bg-green-500/10 text-green-400"
                        : "bg-sky-500/10 text-sky-400"
                    }`}>
                      {update.phase} — {update.status}
                    </span>
                    <div className="flex-1 h-px bg-slate-700" />
                  </div>
                )}

                {/* Agent Actions — The Core Transparency Layer */}
                {update.type === "agent_action" && (
                  <div className={`glass-card p-4 border-l-2 ${AGENT_COLORS[update.agent || ""] || "border-slate-500/30"} ${AGENT_BG[update.agent || ""] || ""}`}>
                    <div className="flex items-start gap-3">
                      {/* Action Icon */}
                      <div className={`mt-0.5 ${AGENT_COLORS[update.agent || ""]?.split(" ")[0] || "text-slate-400"}`}>
                        {(() => {
                          const ActionIcon = ACTION_ICONS[update.action || ""] || ChevronRight;
                          return <ActionIcon className="h-4 w-4" />;
                        })()}
                      </div>

                      <div className="flex-1 min-w-0">
                        {/* Agent + Action Header */}
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs font-bold uppercase ${AGENT_COLORS[update.agent || ""]?.split(" ")[0] || "text-slate-400"}`}>
                            {update.agent}
                          </span>
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            update.action === "spl_error"
                              ? "bg-red-500/20 text-red-400"
                              : update.action === "self_correcting"
                              ? "bg-amber-500/20 text-amber-400"
                              : update.action === "results"
                              ? "bg-green-500/20 text-green-400"
                              : "bg-slate-700 text-slate-400"
                          }`}>
                            {update.action}
                          </span>
                        </div>

                        {/* Main Detail */}
                        <p className="text-sm text-slate-300">{update.detail}</p>

                        {/* Reasoning — The key "Show Don't Tell" element */}
                        {update.reasoning && (
                          <div className="mt-2 flex items-start gap-2 p-2 bg-slate-800/50 rounded-md border border-slate-700/50">
                            <Brain className="h-3 w-3 text-purple-400 mt-0.5 flex-shrink-0" />
                            <p className="text-xs text-purple-300 italic">{update.reasoning}</p>
                          </div>
                        )}

                        {/* SPL Query — Always visible for investigation steps */}
                        {update.spl_query && (
                          <div className="mt-2">
                            <div className="flex items-center gap-1 mb-1">
                              <Database className="h-3 w-3 text-sky-400" />
                              <span className="text-[10px] text-sky-400 uppercase font-semibold">SPL Query</span>
                            </div>
                            <pre className="text-xs bg-slate-900 text-sky-300 p-3 rounded-md overflow-x-auto font-mono border border-slate-700/50">
                              {update.spl_query}
                            </pre>
                          </div>
                        )}

                        {/* Result Count Badge */}
                        {update.result_count !== undefined && (
                          <span className={`inline-block mt-2 text-xs px-2 py-0.5 rounded font-mono ${
                            update.result_count > 0
                              ? "bg-green-500/20 text-green-400"
                              : "bg-slate-700 text-slate-400"
                          }`}>
                            {update.result_count} results
                          </span>
                        )}

                        {/* Raw Results — Expandable for full transparency */}
                        {update.raw_results && update.raw_results.length > 0 && (
                          <ExpandableSection title={`View raw Splunk results (${update.raw_results.length} shown)`}>
                            <pre className="text-[11px] bg-slate-900 text-slate-300 p-3 rounded-md overflow-x-auto font-mono border border-slate-700/50 max-h-48 overflow-y-auto">
                              {JSON.stringify(update.raw_results, null, 2)}
                            </pre>
                          </ExpandableSection>
                        )}

                        {/* Schema Data */}
                        {update.raw_data && (
                          <ExpandableSection title="View discovered schema">
                            <pre className="text-[11px] bg-slate-900 text-slate-300 p-3 rounded-md overflow-x-auto font-mono border border-slate-700/50 max-h-48 overflow-y-auto">
                              {JSON.stringify(update.raw_data, null, 2)}
                            </pre>
                          </ExpandableSection>
                        )}
                      </div>

                      {/* Timestamp */}
                      <Clock className="h-3 w-3 text-slate-600 mt-1 flex-shrink-0" />
                    </div>
                  </div>
                )}

                {/* Agent Results */}
                {update.type === "agent_result" && (
                  <div className={`glass-card p-4 border-l-2 border-green-500/50 bg-green-500/5`}>
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span className={`text-xs font-bold uppercase ${AGENT_COLORS[update.agent || ""]?.split(" ")[0] || "text-slate-400"}`}>
                        {update.agent} — Complete
                      </span>
                    </div>
                    <ExpandableSection title="View agent output" defaultOpen={true}>
                      <pre className="text-xs text-slate-300 bg-slate-900 p-3 rounded-md overflow-x-auto font-mono border border-slate-700/50">
                        {JSON.stringify(update.result, null, 2)}
                      </pre>
                    </ExpandableSection>
                  </div>
                )}

                {/* Investigation Complete — Full Report Card */}
                {update.type === "status" && update.status === "completed" && (
                  <div className="mt-6 space-y-4 animate-slide-up">
                    {/* Time Saved Banner */}
                    <TimeSavedBanner elapsed={elapsed} />

                    <div className="glass-card p-6 border border-green-500/30 bg-green-500/5">
                      <div className="flex items-center gap-3 mb-4">
                        <Shield className="h-8 w-8 text-green-400" />
                        <div>
                          <p className="text-green-300 font-semibold text-lg">
                            Investigation Complete
                          </p>
                          <p className="text-xs text-slate-400">
                            {stepCount} SPL queries • {retryCount} self-corrections • {updates.length} total steps
                          </p>
                        </div>
                      </div>

                      {/* Summary */}
                      {update.result && (() => {
                        const r = update.result as Record<string, unknown>;
                        return (
                        <div className="space-y-4">
                          {/* Executive Summary */}
                          {r.summary ? (
                            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Executive Summary</h4>
                              <p className="text-sm text-slate-200 leading-relaxed">
                                {String(r.summary)}
                              </p>
                            </div>
                          ) : null}

                          {/* MITRE ATT&CK Techniques */}
                          {(r.mitre_techniques as string[])?.length > 0 ? (
                            <div className="space-y-4">
                              <div>
                                <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">MITRE ATT&CK Techniques</h4>
                                <div className="flex flex-wrap gap-2">
                                  {(r.mitre_techniques as string[]).map((t: string, i: number) => (
                                    <span key={i} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono">
                                      <AlertTriangle className="h-3 w-3" />
                                      {t}
                                    </span>
                                  ))}
                                </div>
                              </div>
                              
                              {/* MITRE ATT&CK Heatmap */}
                              <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
                                <MitreHeatmap techniques={r.mitre_techniques as string[]} />
                              </div>

                              {/* Attack Kill Chain Timeline */}
                              <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
                                <AttackTimeline techniques={r.mitre_techniques as string[]} />
                              </div>
                            </div>
                          ) : null}

                          {/* Affected Assets & Users */}
                          <div className="grid grid-cols-2 gap-4">
                            {(r.affected_assets as string[])?.length > 0 ? (
                              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Affected Assets</h4>
                                <div className="space-y-1">
                                  {(r.affected_assets as string[]).map((a: string, i: number) => (
                                    <div key={i} className="flex items-center gap-2 text-sm text-slate-200">
                                      <div className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                                      <span className="font-mono text-xs">{a}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : null}
                            {(r.affected_users as string[])?.length > 0 ? (
                              <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Affected Users</h4>
                                <div className="space-y-1">
                                  {(r.affected_users as string[]).map((u: string, i: number) => (
                                    <div key={i} className="flex items-center gap-2 text-sm text-slate-200">
                                      <div className="h-1.5 w-1.5 rounded-full bg-sky-400" />
                                      <span className="font-mono text-xs">{u}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : null}
                          </div>

                          {/* Recommendations */}
                          {(r.recommendations as string[])?.length > 0 ? (
                            <div>
                              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-2">Recommended Actions</h4>
                              <div className="space-y-2">
                                {(r.recommendations as string[]).map((rec: string, i: number) => (
                                  <div key={i} className="flex items-start gap-2 p-2 bg-slate-800/50 rounded-md border border-slate-700/50">
                                    <Zap className="h-3.5 w-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                                    <span className="text-sm text-slate-300">{rec}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : null}
                        </div>
                        );
                      })()}
                    </div>
                  </div>
                )}

                {/* Error State */}
                {update.type === "error" && (
                  <div className="glass-card p-4 border border-red-500/30 bg-red-500/5">
                    <div className="flex items-center gap-2">
                      <XCircle className="h-5 w-5 text-red-400" />
                      <p className="text-red-300 text-sm">{update.message}</p>
                    </div>
                  </div>
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        </div>
      </div>

      {/* Follow-up Question Input — Interactive Mode */}
      {isComplete && (
        <div className="border-t border-slate-800 px-6 py-4 bg-slate-900/80 backdrop-blur-sm animate-slide-up">
          <div className="max-w-4xl mx-auto flex items-center gap-3">
            <MessageSquare className="h-5 w-5 text-sky-400 flex-shrink-0" />
            <input
              type="text"
              value={followUpQuery}
              onChange={(e) => setFollowUpQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleFollowUp()}
              placeholder="Ask a follow-up question... e.g., 'What other accounts did this IP access?' or 'Show DNS queries from the compromised host'"
              className="flex-1 bg-slate-800/50 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500"
            />
            <button
              onClick={handleFollowUp}
              disabled={!followUpQuery.trim() || isAsking}
              className="flex items-center gap-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition"
            >
              <Send className="h-4 w-4" />
              Ask
            </button>
          </div>
          <p className="max-w-4xl mx-auto text-[10px] text-slate-500 mt-1.5 pl-8">
            Interactive mode — ask follow-up questions and the agent will run additional SPL queries to investigate further
          </p>
        </div>
      )}
    </main>
  );
}
