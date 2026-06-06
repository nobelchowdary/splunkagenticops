"use client";

import { Shield, Activity, AlertTriangle, Clock, Search } from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
  // Mock data for the SOC dashboard
  const stats = {
    activeInvestigations: 2,
    threatsDetected: 5,
    queriesRun: 47,
    avgInvestigationTime: "3.2 min",
  };

  const recentAlerts = [
    {
      id: "1",
      title: "Brute Force Detected",
      severity: "high",
      source_ip: "192.168.1.100",
      time: "2 min ago",
    },
    {
      id: "2",
      title: "Unusual Outbound Traffic",
      severity: "medium",
      source_ip: "10.0.0.54",
      time: "15 min ago",
    },
    {
      id: "3",
      title: "Privilege Escalation Attempt",
      severity: "critical",
      source_ip: "172.16.0.22",
      time: "1 hour ago",
    },
  ];

  const severityColors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };

  return (
    <main className="min-h-screen">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-sky-500" />
            <h1 className="text-xl font-bold text-white">SentinelFlow</h1>
            <span className="text-slate-500">/</span>
            <span className="text-slate-300">SOC Dashboard</span>
          </div>
          <Link
            href="/"
            className="text-sm bg-sky-600 hover:bg-sky-500 text-white px-4 py-2 rounded-lg transition"
          >
            + New Investigation
          </Link>
        </div>
      </header>

      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="glass-card p-5">
            <div className="flex items-center gap-3 mb-2">
              <Activity className="h-5 w-5 text-sky-400" />
              <span className="text-sm text-slate-400">Active</span>
            </div>
            <p className="text-3xl font-bold text-white">
              {stats.activeInvestigations}
            </p>
          </div>
          <div className="glass-card p-5">
            <div className="flex items-center gap-3 mb-2">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <span className="text-sm text-slate-400">Threats</span>
            </div>
            <p className="text-3xl font-bold text-white">
              {stats.threatsDetected}
            </p>
          </div>
          <div className="glass-card p-5">
            <div className="flex items-center gap-3 mb-2">
              <Search className="h-5 w-5 text-purple-400" />
              <span className="text-sm text-slate-400">Queries</span>
            </div>
            <p className="text-3xl font-bold text-white">
              {stats.queriesRun}
            </p>
          </div>
          <div className="glass-card p-5">
            <div className="flex items-center gap-3 mb-2">
              <Clock className="h-5 w-5 text-green-400" />
              <span className="text-sm text-slate-400">Avg Time</span>
            </div>
            <p className="text-3xl font-bold text-white">
              {stats.avgInvestigationTime}
            </p>
          </div>
        </div>

        {/* Alert Feed */}
        <div className="glass-card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Recent Alerts
          </h2>
          <div className="space-y-3">
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-sky-500/30 transition cursor-pointer"
              >
                <div className="flex items-center gap-4">
                  <span
                    className={`text-xs font-medium px-2 py-1 rounded border ${
                      severityColors[alert.severity]
                    }`}
                  >
                    {alert.severity.toUpperCase()}
                  </span>
                  <div>
                    <p className="text-sm font-medium text-white">
                      {alert.title}
                    </p>
                    <p className="text-xs text-slate-400">
                      Source: {alert.source_ip}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-slate-500">{alert.time}</p>
                  <button className="text-xs text-sky-400 hover:text-sky-300 mt-1">
                    Investigate →
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </main>
  );
}
