"use client";

import { useEffect, useState } from "react";
import AppShell from "@/components/AppShell";
import { ErrorBox, Panel, ToolChip } from "@/components/ui";
import { apiGet } from "@/lib/api";

type ToolInfo = {
  name: string;
  description: string;
  action: string;
  sensitivity: number;
  untrusted_output: boolean;
  privileged: boolean;
  usage: { ALLOW: number; REVIEW: number; DENY: number };
};

export default function ToolsPage() {
  return (
    <AppShell title="Tool Registry" eyebrow="What agents can request">
      <ToolsContent />
    </AppShell>
  );
}

function ToolsContent() {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [allowlist, setAllowlist] = useState<Record<string, string[]>>({});
  const [blocklist, setBlocklist] = useState<string[]>([]);
  const [emailMode, setEmailMode] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<{ tools: ToolInfo[]; web_allowlist: Record<string, string[]>; web_blocklist: string[]; email_mode: string }>("/api/tools")
      .then((d) => {
        setTools(d.tools);
        setAllowlist(d.web_allowlist);
        setBlocklist(d.web_blocklist);
        setEmailMode(d.email_mode);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load tools."));
  }, []);

  return (
    <>
      {error && <ErrorBox message={error} />}
      <Panel title="Registered tools" subtitle="Security metadata the policy engine reasons over">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-white/35">
              <tr>
                <th className="pb-2 font-normal">Tool</th>
                <th className="pb-2 font-normal">Action</th>
                <th className="pb-2 font-normal">Sensitivity</th>
                <th className="pb-2 font-normal">Flags</th>
                <th className="pb-2 font-normal">Usage (A / R / D)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {tools.map((t) => (
                <tr key={t.name} className="align-top">
                  <td className="py-3 pr-4">
                    <div className="font-mono text-sm">{t.name}</div>
                    <div className="mt-1 max-w-sm text-[11px] text-white/40">{t.description}</div>
                  </td>
                  <td className="py-3 font-mono text-white/60">{t.action}</td>
                  <td className="py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-white/10">
                        <div
                          className={`h-full rounded-full ${t.sensitivity >= 0.75 ? "bg-red-400" : t.sensitivity >= 0.45 ? "bg-amber-400" : "bg-emerald-400"}`}
                          style={{ width: `${t.sensitivity * 100}%` }}
                        />
                      </div>
                      <span className="font-mono text-white/60">{t.sensitivity.toFixed(2)}</span>
                    </div>
                  </td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {t.untrusted_output && <span className="rounded bg-amber-400/10 px-1.5 text-[10px] text-amber-300">untrusted output</span>}
                      {t.privileged && <span className="rounded bg-red-400/10 px-1.5 text-[10px] text-red-300">privileged</span>}
                    </div>
                  </td>
                  <td className="py-3 font-mono">
                    <span className="text-emerald-300">{t.usage.ALLOW}</span>
                    <span className="text-white/25"> / </span>
                    <span className="text-amber-300">{t.usage.REVIEW}</span>
                    <span className="text-white/25"> / </span>
                    <span className="text-red-300">{t.usage.DENY}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="mt-6 grid gap-6 xl:grid-cols-[2fr_1fr]">
        <Panel title="Vetted web domains" subtitle="Fetched normally. Unknown domains need human review. Subdomains match their parent.">
          <div className="space-y-4">
            {Object.entries(allowlist).map(([group, domains]) => (
              <div key={group}>
                <div className="mb-1.5 text-[11px] uppercase tracking-wider text-white/35">{group} ({domains.length})</div>
                <div className="flex flex-wrap gap-1.5">{domains.map((d) => <ToolChip key={d} name={d} />)}</div>
              </div>
            ))}
          </div>
        </Panel>
        <div className="space-y-6">
          <Panel title="Blocked destinations" subtitle="Paste, tunnelling and exfiltration services: always DENY">
            <div className="flex flex-wrap gap-1.5">
              {blocklist.map((d) => <span key={d} className="rounded-md border border-red-400/20 bg-red-400/5 px-2 py-0.5 font-mono text-[11px] text-red-300">{d}</span>)}
            </div>
          </Panel>
          <Panel title="Email delivery">
            <div className="text-sm">
              Mode: <span className={`font-mono ${emailMode === "gmail" ? "text-emerald-300" : "text-amber-300"}`}>{emailMode || "…"}</span>
            </div>
            <p className="mt-2 text-xs text-white/40">
              {emailMode === "gmail" ? "Real delivery through Gmail SMTP." : "Gmail not configured: emails are logged to workspace/outbox only. Set GMAIL_ADDRESS and GMAIL_APP_PASSWORD in .env."}
            </p>
          </Panel>
        </div>
      </div>
    </>
  );
}
