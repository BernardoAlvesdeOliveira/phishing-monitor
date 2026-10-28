import { useEffect, useRef, useState } from "react";
import { Check, Clipboard, FileUp, LoaderCircle, ShieldAlert, Upload } from "lucide-react";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

function RiskBadge({ level }) {
  return (
    <span className={`rounded-full border px-3 py-1 text-xs font-bold tracking-widest ${level === "CRITICAL" || level === "HIGH" ? "border-red-400/40 bg-red-400/10 text-red-300" : level === "MEDIUM" ? "border-amber-300/40 bg-amber-300/10 text-amber-200" : "border-emerald-300/30 bg-emerald-300/10 text-emerald-300"}`}>
      {level}
    </span>
  );
}

function AnalysisLoading({ fileName }) {
  return (
    <section className="loading-panel mt-4" aria-live="polite" aria-label="Email analysis in progress">
      <div className="loading-icon">
        <ShieldAlert size={25} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="eyebrow">ANALYSIS IN PROGRESS</p>
        <h2 className="title">Checking email signals</h2>
        <p className="mt-2 truncate text-sm text-[#686868]">{fileName}</p>
        <div className="loading-track mt-4" role="progressbar" aria-label="Analysis progress">
          <span />
        </div>
        <div className="mt-3 flex items-center gap-2 text-xs font-semibold text-[#686868]">
          <span className="loading-dot" />
          Parsing headers, links, and authentication evidence...
        </div>
      </div>
    </section>
  );
}

export function App() {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [copyState, setCopyState] = useState(false);
  const [busy, setBusy] = useState(false);
  const resultRef = useRef(null);
  const analysisUrl = `${window.location.origin}/analyze/email`;

  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [result]);

  const selectFile = (selected) => {
    if (!selected) return;
    setError("");
    setResult(null);
    setFile(selected);
  };

  const analyze = async (event) => {
    event.preventDefault();
    setError("");
    if (!file || !file.name.toLowerCase().endsWith(".eml")) {
      setError("Choose an .eml file.");
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError("File exceeds the 10 MB limit.");
      return;
    }
    setBusy(true);
    try {
      const response = await fetch(analysisUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_email: await file.text() }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || "Analysis failed.");
      setResult(payload);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  };

  const copyWebhook = async () => {
    const webhookUrl = `${window.location.origin}/webhook/email`;
    await navigator.clipboard.writeText(webhookUrl);
    setCopyState(true);
    window.setTimeout(() => setCopyState(false), 1800);
  };

  return (
    <main className="min-h-screen bg-[#f7f7f5] px-4 py-6 text-[#171717] sm:px-8 sm:py-8">
      <div className="mx-auto max-w-5xl">
        <nav className="mb-16 flex items-center justify-between border-b border-black/10 pb-5">
          <div className="flex items-center gap-3">
            <img className="h-10 w-auto" src="/mastercard-logo.png" alt="Mastercard" />
            <span className="border-l border-black/20 pl-3 text-sm font-bold tracking-tight">Phishing Monitor</span>
          </div>
          <span className="rounded-full bg-black px-3 py-1 text-[10px] font-bold tracking-[0.16em] text-white">SECURITY CENTER</span>
        </nav>

        <header className="mb-10 max-w-3xl">
          <p className="mb-4 text-xs font-extrabold tracking-[0.2em] text-[#e4002b]">EMAIL PROTECTION</p>
          <h1 className="text-4xl font-semibold leading-[1.02] tracking-[-0.05em] text-[#171717] sm:text-7xl">Inspect an email before it becomes a threat.</h1>
          <p className="mt-6 max-w-xl text-lg text-[#595959]">Upload an <code>.eml</code> file for deterministic phishing analysis.</p>
        </header>

        <section className="panel mb-4">
          <p className="eyebrow">WEBHOOK</p>
          <h2 className="title">Your ingestion endpoint</h2>
          <p className="mt-2 text-sm text-[#686868]">Use this endpoint with your email provider. The shared secret is never displayed.</p>
          <div className="mt-5 flex flex-col gap-2 sm:flex-row">
            <code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-black/10 bg-white px-3 py-3 text-sm text-[#e4002b]">{`${window.location.origin}/webhook/email`}</code>
            <button className="button-secondary" onClick={copyWebhook} type="button">
              {copyState ? <Check size={16} /> : <Clipboard size={16} />} {copyState ? "Copied" : "Copy"}
            </button>
          </div>
        </section>

        <section className="panel">
          <div className="flex items-start justify-between gap-4">
            <div><p className="eyebrow">ANALYSIS</p><h2 className="title">Upload email file</h2></div>
            <span className="hidden rounded-full border border-black/10 px-3 py-1 text-xs font-bold tracking-widest text-[#686868] sm:inline">LOCAL PROCESSING</span>
          </div>
          <form onSubmit={analyze}>
            <button
              className="group mt-6 flex w-full flex-col items-center gap-2 rounded-xl border border-dashed border-black/20 bg-white px-5 py-10 transition hover:border-[#f79e1b] hover:bg-[#fffaf0]"
              onClick={() => inputRef.current?.click()}
              onDragOver={(event) => event.preventDefault()}
              onDrop={(event) => { event.preventDefault(); selectFile(event.dataTransfer.files[0]); }}
              type="button"
            >
              <input ref={inputRef} className="hidden" type="file" accept=".eml,message/rfc822" onChange={(event) => selectFile(event.target.files[0])} />
              {file ? <FileUp className="text-[#e4002b]" size={32} /> : <Upload className="text-[#e4002b]" size={32} />}
              <strong>{file ? file.name : "Drop an .eml file here"}</strong>
              <span className="text-sm text-[#686868]">{file ? `${(file.size / 1024).toFixed(1)} KB selected` : "or click to browse · maximum 10 MB"}</span>
            </button>
            <button className="button-primary mt-5" disabled={busy} type="submit">
              {busy && <LoaderCircle className="animate-spin" size={17} />} {busy ? "Analyzing..." : "Analyze email"}
            </button>
          </form>
          {error && <p className="mt-3 text-sm text-red-300" role="alert">{error}</p>}
        </section>

        {busy && <AnalysisLoading fileName={file.name} />}

        {result && (
          <section ref={resultRef} className="panel mt-4 scroll-mt-6">
            <div className="flex items-start justify-between gap-4"><div><p className="eyebrow">RESULT</p><h2 className="title">Analysis complete</h2></div><RiskBadge level={result.risk.level} /></div>
            <div className="mt-6 flex items-baseline justify-between border-b border-black/10 pb-4"><span className="text-[#686868]">Risk score</span><strong className="text-4xl text-[#e4002b]">{result.risk.score}<small className="text-sm text-[#686868]">/100</small></strong></div>
            <p className="mt-3 text-sm text-[#686868]">Assessment status: {result.risk.status}</p>
            <h3 className="mt-6 font-semibold">Findings</h3>
            <ul className="mt-2 list-disc space-y-2 pl-5 text-sm text-[#686868]">{result.findings.map((finding) => <li key={finding}>{finding}</li>)}</ul>
            <p className="mt-5 text-sm text-[#686868]">{result.notification_sent ? "Security notification sent." : "No notification sent."}</p>
          </section>
        )}
      </div>
    </main>
  );
}
