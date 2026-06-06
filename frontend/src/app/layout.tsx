import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelFlow — AI Security Operations Agent",
  description: "Autonomous multi-agent system for security investigation",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0a0a0f] text-slate-200 antialiased">
        {children}
      </body>
    </html>
  );
}
