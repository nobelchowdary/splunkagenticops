"use client";

import { useState } from "react";
import { Shield, Activity, AlertTriangle, Search, Zap, Brain, Clock, Target, ChevronRight, Database, Eye } from "lucide-react";

export default function Home() {
  const [alertInput, setAlertInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const sampleAlerts = [
    "Multiple failed login attempts detected from IP 203.0.113.42 targeting user jsmith on WKS-JSMITH-01. 500 failed RDP attempts (EventCode 4625) in 30 minutes followed by a successful login (EventCode 4624). Possible brute force attack with credential compromise. Source IP is external and not previously seen in the environment.",
    "Unusual data exfiltration detected: Host 10.0.1.50 (WKS-JSMITH-01) sending large outbound transfers (500KB-5MB per connection) to external IP 198.51.100.77 over port 443. DNS queries to cdn-updates.evil.com observed from same host. Total egress volume exceeds normal baseline by 10x.",
    "Suspicious process execution on WKS-JSMITH-01 by user jsmith: powershell.exe with encoded command, mimikatz.exe for credential dumping, psexec.exe for lateral movement to SRV-FILE01. Process chain suggests post-exploitation activity following credential compromise.",
  ];

  const loadSampleAlert = () => {
    const randomAlert = sampleAlerts[Math.floor(Math.random() * sampleAlerts.length)];
    setAlertInput(randomAlert);
  };

  const handleStartInvestigation = async () => {
    if (!alertInput.trim()) return;
    setIsLoading(true);

    // Extract source IP and user from alert text for better context
    const ipMatch = alertInput.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const userMatch = alertInput.match(/(?:user|targeting|account)\s+(\w+)/i);

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/investigations`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title: alertInput.slice(0, 80),
            description: alertInput,
            source_ip: ipMatch ? ipMatch[0] : undefined,
            user: userMatch ? userMatch[1] : undefined,
            timerange: "-24h",
          }),
        }
      );
      const data = await response.json();
      window.location.href = `/investigations/${data.investigation_id}`;
    } catch (error) {
      console.error("Failed to start investigation:", error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-sky-500" />
            <h1 className="text-2xl font-bold text-white">SentinelFlow</h1>
            <span className="text-xs bg-sky-500/20 text-sky-400 px-2 py-0.5 rounded-full">
              AI Security Agent
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
            <span>System Online</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center justify-center px-6 py-12">
        <div className="max-w-4xl w-full space-y-8">
          {/* Hero */}
          <div className="text-center space-y-4">
            <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-300 text-xs px-3 py-1 rounded-full mb-2">
              <AlertTriangle className="h-3 w-3" />
              <span>11,000+ alerts/day overwhelm SOC teams — 76% never investigated</span>
            </div>
            <h2 className="text-5xl font-bold text-white leading-tight">
              Autonomous Security<br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-sky-400 to-green-400">
                Investigation in 60s
              </span>
            </h2>
            <p className="text-lg text-slate-400 max-w-2xl mx-auto">
              5 AI agents autonomously triage, investigate, detect anomalies, and respond to threats — 
              with full transparency. Watch every SPL query, every decision, every finding in real-time.
            </p>
          </div>

          {/* Impact Stats Row */}
          <div className="grid grid-cols-4 gap-3">
            <div className="glass-card p-4 text-center border border-sky-500/20">
              <p className="text-2xl font-black text-sky-400">60s</p>
              <p className="text-[10px] text-slate-400 uppercase mt-1">Avg Investigation</p>
            </div>
            <div className="glass-card p-4 text-center border border-green-500/20">
              <p className="text-2xl font-black text-green-400">98%</p>
              <p className="text-[10px] text-slate-400 uppercase mt-1">Time Reduction</p>
            </div>
            <div className="glass-card p-4 text-center border border-purple-500/20">
              <p className="text-2xl font-black text-purple-400">5</p>
              <p className="text-[10px] text-slate-400 uppercase mt-1">AI Agents</p>
            </div>
            <div className="glass-card p-4 text-center border border-amber-500/20">
              <p className="text-2xl font-black text-amber-400">0</p>
              <p className="text-[10px] text-slate-400 uppercase mt-1">Human Steps</p>
            </div>
          </div>

          {/* Input Area */}
          <div className="glass-card p-6 space-y-4 glow-border">
            <div className="flex items-center gap-2 mb-2">
              <Target className="h-4 w-4 text-sky-400" />
              <span className="text-sm font-semibold text-white">Start an Investigation</span>
            </div>
            <textarea
              value={alertInput}
              onChange={(e) => setAlertInput(e.target.value)}
              placeholder="Paste a security alert or describe suspicious activity...&#10;&#10;Example: Multiple failed login attempts from IP 192.168.1.100 targeting user admin@corp.com followed by successful authentication from unusual geolocation."
              className="w-full h-32 bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-slate-200 placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500"
            />
            <div className="flex items-center justify-between">
              <div className="flex gap-2">
                <button
                  onClick={loadSampleAlert}
                  className="flex items-center gap-1.5 text-xs bg-slate-800 text-slate-400 px-3 py-1.5 rounded-md hover:bg-slate-700 hover:text-slate-300 transition border border-slate-700"
                >
                  <Zap className="h-3 w-3" />
                  Load Sample Alert
                </button>
              </div>
              <button
                onClick={handleStartInvestigation}
                disabled={!alertInput.trim() || isLoading}
                className="flex items-center gap-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white px-6 py-2.5 rounded-lg font-medium transition shadow-lg shadow-sky-500/20"
              >
                <Zap className="h-4 w-4" />
                {isLoading ? "Starting..." : "Investigate Autonomously"}
              </button>
            </div>
          </div>

          {/* How It Works — Agent Pipeline */}
          <div className="glass-card p-6">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-400" />
              How It Works — 5 Agent Pipeline
            </h3>
            <div className="flex items-center justify-between">
              {[
                { icon: AlertTriangle, name: "Triage", desc: "Classify & extract IOCs", color: "text-amber-400" },
                { icon: Database, name: "Investigate", desc: "Autonomous SPL queries", color: "text-sky-400" },
                { icon: Brain, name: "Anomaly", desc: "Behavioral detection", color: "text-purple-400" },
                { icon: Shield, name: "Respond", desc: "Containment actions", color: "text-red-400" },
                { icon: Eye, name: "Report", desc: "MITRE ATT&CK mapping", color: "text-green-400" },
              ].map((agent, idx) => (
                <div key={idx} className="flex items-center">
                  <div className="text-center group">
                    <div className={`h-10 w-10 rounded-full border border-slate-700 flex items-center justify-center mx-auto mb-1.5 group-hover:scale-110 transition ${agent.color}`}>
                      <agent.icon className="h-4 w-4" />
                    </div>
                    <p className="text-xs font-semibold text-slate-300">{agent.name}</p>
                    <p className="text-[10px] text-slate-500">{agent.desc}</p>
                  </div>
                  {idx < 4 && <ChevronRight className="h-4 w-4 text-slate-600 mx-2" />}
                </div>
              ))}
            </div>
          </div>

          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass-card p-5 border border-sky-500/10 hover:border-sky-500/30 transition">
              <div className="flex items-center gap-3 mb-2">
                <Eye className="h-5 w-5 text-sky-400" />
                <span className="text-sm font-semibold text-white">Full Transparency</span>
              </div>
              <p className="text-xs text-slate-400">
                Watch every agent thought, SPL query, and decision streamed live. No black boxes.
              </p>
            </div>
            <div className="glass-card p-5 border border-purple-500/10 hover:border-purple-500/30 transition">
              <div className="flex items-center gap-3 mb-2">
                <Activity className="h-5 w-5 text-purple-400" />
                <span className="text-sm font-semibold text-white">Self-Correcting</span>
              </div>
              <p className="text-xs text-slate-400">
                Agents auto-retry failed queries with error context. Up to 3 corrections per step.
              </p>
            </div>
            <div className="glass-card p-5 border border-green-500/10 hover:border-green-500/30 transition">
              <div className="flex items-center gap-3 mb-2">
                <Clock className="h-5 w-5 text-green-400" />
                <span className="text-sm font-semibold text-white">45 min → 60 seconds</span>
              </div>
              <p className="text-xs text-slate-400">
                What takes a SOC analyst 45 minutes, SentinelFlow completes in under 60 seconds.
              </p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
