"use client";

import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import AppShell from "@/components/AppShell";
import { EmptyState, ErrorBox, Panel } from "@/components/ui";
import { apiGet, downloadFile } from "@/lib/api";

type OutFile = { name: string; path: string; size: number; kind: string; modified: number; conversation_id: string; conversation_title: string };

export default function FilesPage() {
  return (
    <AppShell title="My Files" eyebrow="Only you (and admins) can see these files">
      <FilesContent />
    </AppShell>
  );
}

function FilesContent() {
  const [files, setFiles] = useState<OutFile[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<OutFile[]>("/api/files").then(setFiles).catch((e) => setError(e instanceof Error ? e.message : "Failed to load files."));
  }, []);

  return (
    <>
      {error && <ErrorBox message={error} />}
      <Panel title={`Your files (${files.length})`} subtitle="Uploads and agent-created files, stored locally per chat. Originals are never modified.">
        {files.length === 0 ? (
          <EmptyState message="No files yet. Ask an agent in Chat to create a summary or edit a copy of a file." />
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-white/35">
              <tr>
                <th className="pb-2 font-normal">File</th>
                <th className="pb-2 font-normal">From chat</th>
                <th className="pb-2 font-normal">Size</th>
                <th className="pb-2 font-normal">Created</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {files.map((f) => (
                <tr key={f.path}>
                  <td className="py-2.5 font-mono">
                    {f.name}
                    <span className={`ml-2 rounded px-1.5 font-sans text-[10px] ${f.kind === "generated" ? "bg-emerald-400/10 text-emerald-300" : "bg-white/10 text-white/50"}`}>{f.kind}</span>
                  </td>
                  <td className="max-w-xs truncate py-2.5 text-white/50">{f.conversation_title}</td>
                  <td className="py-2.5 text-white/45">{(f.size / 1024).toFixed(1)} KB</td>
                  <td className="py-2.5 text-white/45">{new Date(f.modified * 1000).toLocaleString()}</td>
                  <td className="py-2.5 text-right">
                    <button onClick={() => downloadFile(f.path, f.name)} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-2.5 py-1 hover:bg-white/[0.06]">
                      <Download size={12} /> Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}
