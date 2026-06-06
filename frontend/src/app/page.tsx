"use client";

import { useState } from "react";
import { Shield, Activity, AlertTriangle, Search, Zap } from "lucide-react";

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
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-sky-500" />
          <h1 className="text-2xl font-bold text-white">SentinelFlow</h1>
          <span className="text-xs bg-sky-500/20 text-sky-400 px-2 py-0.5 rounded-full">
            AI Security Agent
          </span>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex flex-col items-center justify-center px-6 py-12">
        <div className="max-w-3xl w-full space-y-8">
          {/* Hero */}
          <div className="text-center space-y-4">
            <h2 className="text-4xl font-bold text-white">
              Autonomous Security Investigation
            </h2>
            <p className="text-lg text-slate-400 max-w-xl mx-auto">
              Drop in an alert or describe a suspicious activity. SentinelFlow's
              AI agents will autonomously investigate, correlate, and report.
            </p>
          </div>

          {/* Input Area */}
          <div className="glass-card p-6 space-y-4">
            <textarea
              value={alertInput}
              onChange={(e) => setAlertInput(e.target.value)}
              placeholder="Describe the alert or paste alert details...&#10;&#10;Example: Multiple failed login attempts from IP 192.168.1.100 targeting user admin@corp.com followed by successful authentication from unusual geolocation."
              className="w-full h-32 bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-slate-200 placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500"
            />
            <div className="flex items-center justify-between">
              <div className="flex gap-2">
                <button
                  onClick={loadSampleAlert}
                  className="text-xs bg-slate-800 text-slate-400 px-3 py-1.5 rounded-md hover:bg-slate-700 transition"
                >
                  Load Sample Alert
                </button>
              </div>
              <button
                onClick={handleStartInvestigation}
                disabled={!alertInput.trim() || isLoading}
                className="flex items-center gap-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-500 text-white px-6 py-2.5 rounded-lg font-medium transition"
              >
                <Zap className="h-4 w-4" />
                {isLoading ? "Starting..." : "Investigate"}
              </button>
            </div>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="glass-card p-5">
              <div className="flex items-center gap-3 mb-2">
                <Activity className="h-5 w-5 text-green-400" />
                <span className="text-sm text-slate-400">Active Investigations</span>
              </div>
              <p className="text-2xl font-bold text-white">0</p>
            </div>
            <div className="glass-card p-5">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-amber-400" />
                <span className="text-sm text-slate-400">Threats Detected</span>
              </div>
              <p className="text-2xl font-bold text-white">0</p>
            </div>
            <div className="glass-card p-5">
              <div className="flex items-center gap-3 mb-2">
                <Search className="h-5 w-5 text-sky-400" />
                <span className="text-sm text-slate-400">SPL Queries Run</span>
              </div>
              <p className="text-2xl font-bold text-white">0</p>
            </div>
          </div>

          {/* Recent Investigations */}
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              Recent Investigations
            </h3>
            <div className="text-center py-8 text-slate-500">
              <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No investigations yet. Start one above.</p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
