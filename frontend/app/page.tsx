"use client";

import { useMemo, useState } from "react";

type Issue = { type: string; severity: "LOW" | "MEDIUM" | "HIGH"; evidence: string };
type Resp = {
  status: "ALLOW" | "REWRITE" | "BLOCK";
  risk_score: number;
  issues: Issue[];
  suggested_prompt?: string | null;
  lakera: { flagged: boolean; request_uuid?: string | null; breakdown?: any };
};

export default function Home() {
  const [systemPrompt, setSystemPrompt] = useState("You are a helpful assistant.");
  const [userPrompt, setUserPrompt] = useState("");
  const [resp, setResp] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(false);

  const badge = useMemo(() => {
    if (!resp) return null;
    const map: Record<string, string> = { ALLOW: "✅ ALLOW", REWRITE: "🛠️ REWRITE", BLOCK: "⛔ BLOCK" };
    return map[resp.status];
  }, [resp]);

  async function validate() {
    setLoading(true);
    setResp(null);
    try {
      const api = process.env.NEXT_PUBLIC_API_URL;
      if (!api) throw new Error("NEXT_PUBLIC_API_URL is not set");
      const r = await fetch(api + "/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          system_prompt: systemPrompt,
          user_prompt: userPrompt,
          context_docs: [],
          tools: [],
          metadata: { channel: "web" }
        })
      });
      const data = (await r.json()) as Resp;
      setResp(data);
    } catch (e: any) {
      setResp({
        status: "BLOCK",
        risk_score: 1,
        issues: [{ type: "CLIENT_ERROR", severity: "HIGH", evidence: String(e?.message || e) }],
        suggested_prompt: null,
        lakera: { flagged: true }
      });
    } finally {
      setLoading(false);
    }
  }

  const finalPrompt = resp?.suggested_prompt ?? userPrompt;

  return (
    <div style={{ maxWidth: 980, margin: "32px auto", fontFamily: "system-ui", padding: 16 }}>
      <h1 style={{ marginBottom: 8 }}>PromptShield</h1>
      <p style={{ marginTop: 0, opacity: 0.8 }}>
        Validate prompts for injection risk and gate with Lakera Guard before sending to an LLM.
      </p>

      <div style={{ display: "grid", gap: 10 }}>
        <label style={{ fontWeight: 600 }}>System prompt</label>
        <textarea
          value={systemPrompt}
          onChange={(e) => setSystemPrompt(e.target.value)}
          rows={4}
          style={{ width: "100%", padding: 10, borderRadius: 10, border: "1px solid #ddd" }}
        />

        <label style={{ fontWeight: 600, marginTop: 8 }}>User prompt</label>
        <textarea
          value={userPrompt}
          onChange={(e) => setUserPrompt(e.target.value)}
          rows={7}
          placeholder="Paste your prompt here..."
          style={{ width: "100%", padding: 10, borderRadius: 10, border: "1px solid #ddd" }}
        />

        <button
          onClick={validate}
          disabled={loading || !userPrompt.trim()}
          style={{ padding: "10px 14px", borderRadius: 10, border: "1px solid #ddd", cursor: "pointer", width: 140 }}
        >
          {loading ? "Validating..." : "Validate"}
        </button>
      </div>

      {resp && (
        <div style={{ marginTop: 18, padding: 14, border: "1px solid #ddd", borderRadius: 12 }}>
          <div style={{ display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap" }}>
            <strong>{badge}</strong>
            <span>Risk: {(resp.risk_score * 100).toFixed(0)}%</span>
            <span>Lakera: {resp.lakera.flagged ? "FLAGGED" : "PASS"}</span>
            {resp.lakera.request_uuid ? <span>UUID: {resp.lakera.request_uuid}</span> : null}
          </div>

          <h3 style={{ marginBottom: 6 }}>Issues</h3>
          {resp.issues.length === 0 ? (
            <p style={{ marginTop: 0 }}>None.</p>
          ) : (
            <ul style={{ marginTop: 0 }}>
              {resp.issues.map((i, idx) => (
                <li key={idx}>
                  <b>{i.severity}</b> — {i.type} — <code>{i.evidence}</code>
                </li>
              ))}
            </ul>
          )}

          {resp.suggested_prompt && (
            <>
              <h3 style={{ marginBottom: 6 }}>Suggested safe prompt</h3>
              <textarea
                value={finalPrompt}
                readOnly
                rows={10}
                style={{ width: "100%", padding: 10, borderRadius: 10, border: "1px solid #ddd" }}
              />
              <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
                <button
                  onClick={() => navigator.clipboard.writeText(finalPrompt)}
                  style={{ padding: "10px 14px", borderRadius: 10, border: "1px solid #ddd", cursor: "pointer" }}
                >
                  Copy final prompt
                </button>
              </div>
            </>
          )}
        </div>
      )}

      <div style={{ marginTop: 22, opacity: 0.7, fontSize: 12 }}>
        Tip: For RAG, pass retrieved documents into <code>context_docs</code>. For tools, pass tool names into <code>tools</code>.
      </div>
    </div>
  );
}
