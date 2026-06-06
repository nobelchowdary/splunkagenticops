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
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    params.then((p) => setInvestigationId(p.id));
  }, [params]);

  useEffect(() => {
    if (!investigationId) return;

    const wsUrl = `${process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000"}/ws/${investigationId}`;
    const ws = new WebSocket(wsUrl);

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
    };

    return () => ws.close();
  }, [investigationId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [updates]);

  const phases = ["triage", "investigation", "anomaly", "response", "report"];

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

                {/* Investigation Complete */}
                {update.type === "status" && update.status === "completed" && (
                  <div className="glass-card p-6 border border-green-500/30 bg-green-500/5 text-center mt-4">
                    <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
                    <p className="text-green-300 font-medium text-lg">
                      Investigation Complete
                    </p>
                    <p className="text-sm text-slate-400 mt-1">
                      {update.message}
                    </p>
                    <div className="flex justify-center gap-4 mt-4 text-xs text-slate-400">
                      <span>{stepCount} SPL queries executed</span>
                      <span>•</span>
                      <span>{retryCount} self-corrections</span>
                      <span>•</span>
                      <span>{updates.length} total steps</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
        </div>
      </div>
    </main>
  );
}
