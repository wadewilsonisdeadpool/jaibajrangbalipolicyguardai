"use client";

import { useEffect, useState } from "react";
import { Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiGet, type TrustEvent } from "@/lib/api";
import { formatTime } from "@/components/ui";

export default function TrustHistory({ kind, id }: { kind: "agent" | "user"; id: number }) {
  const [events, setEvents] = useState<TrustEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<TrustEvent[]>(`/api/trust/${kind}/${id}?limit=60`)
      .then(setEvents)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load history"));
  }, [kind, id]);

  if (error) return <div className="text-xs text-red-300">{error}</div>;
  if (!events) return <div className="text-xs text-white/35">Loading history…</div>;
  if (events.length === 0) return <div className="text-xs text-white/35">No trust events yet. Trust starts at the baseline prior.</div>;

  const data = events.map((e, i) => ({ i, mean: e.mean_after, cautious: e.lower_after }));
  return (
    <div>
      <div className="h-32">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: -25 }}>
            <XAxis dataKey="i" hide />
            <YAxis domain={[0, 1]} tick={{ fontSize: 10, fill: "rgba(255,255,255,0.35)" }} />
            <Tooltip contentStyle={{ background: "#0d121c", border: "1px solid rgba(255,255,255,0.1)", fontSize: 11 }} />
            <ReferenceLine y={0.55} stroke="rgba(251,191,36,0.35)" strokeDasharray="3 3" />
            <ReferenceLine y={0.35} stroke="rgba(248,113,113,0.35)" strokeDasharray="3 3" />
            <Line type="monotone" dataKey="mean" stroke="rgba(255,255,255,0.35)" dot={false} strokeWidth={1.5} />
            <Line type="monotone" dataKey="cautious" stroke="#38bdf8" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <ul className="mt-3 max-h-48 space-y-1.5 overflow-y-auto pr-1">
        {[...events].reverse().slice(0, 15).map((e) => (
          <li key={e.id} className="flex gap-2 text-[11px]">
            <span className={`w-12 shrink-0 font-mono ${e.neg_delta > 0 ? "text-red-300" : e.pos_delta > 0 ? "text-emerald-300" : "text-white/35"}`}>
              {e.neg_delta > 0 ? `-${e.neg_delta.toFixed(2)}` : e.pos_delta > 0 ? `+${e.pos_delta.toFixed(2)}` : "·"}
            </span>
            <span className="flex-1 text-white/55">{e.reason}</span>
            <span className="shrink-0 text-white/25">{formatTime(e.created_at)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
