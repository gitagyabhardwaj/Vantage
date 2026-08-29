/* Signal / Matte Yellow & Blue: Neo-brutalist control-room system. */
import { useMemo, useRef, useState } from "react";
import { useLocation } from "wouter";
import {
  Activity,
  AlertOctagon,
  ArrowLeft,
  ArrowUpRight,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Code2,
  FileCode2,
  FileUp,
  Fingerprint,
  Gauge,
  Github,
  History,
  Layers3,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Play,
  Radar,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  UploadCloud,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ────────────────────────────────────────────────────────────────────
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "PASSED";
type Finding = {
  rule_id: string;
  severity: Exclude<Severity, "PASSED">;
  resource: string;
  description: string;
  remediation: string;
  service: string;
  line: string;
};
type ScanPayload = {
  summary: { critical: number; high: number; medium: number; passed: number };
  findings: Finding[];
  security_score?: { score: number; grade: string; verdict: string };
};
type ViewName =
  | "Overview"
  | "Scan queue"
  | "Rule library"
  | "Assets"
  | "Integrations"
  | "Notifications"
  | "Settings";

// ─── Initial Scan Data ────────────────────────────────────────────────────────
const initialScan: ScanPayload = {
  summary: { critical: 1, high: 2, medium: 0, passed: 15 },
  findings: [
    {
      rule_id: "AWS-001",
      severity: "CRITICAL",
      resource: "aws_s3_bucket.main",
      service: "S3 / storage",
      line: "infra/storage.tf:18",
      description: "S3 bucket allows public read access via ACL.",
      remediation: 'Change acl = "public-read" to acl = "private" and enforce Block Public Access.',
    },
    {
      rule_id: "AWS-002",
      severity: "HIGH",
      resource: "aws_security_group.web",
      service: "EC2 / network",
      line: "infra/network.tf:42",
      description: "Security group allows unrestricted inbound SSH (port 22) from 0.0.0.0/0.",
      remediation: 'Replace cidr_blocks = ["0.0.0.0/0"] with a trusted CIDR or use SSM Session Manager.',
    },
    {
      rule_id: "AWS-003",
      severity: "HIGH",
      resource: "aws_iam_policy.deploy",
      service: "IAM / identity",
      line: "infra/iam.tf:77",
      description: 'IAM policy grants Action:"*" on Resource:"*" — full administrator access.',
      remediation: "Scope actions and resources to the exact needs of the release pipeline.",
    },
  ],
};

// ─── Navigation Items ─────────────────────────────────────────────────────────
const navItems: { label: ViewName; icon: typeof Gauge; count?: string; path: string }[] = [
  { label: "Overview", icon: Gauge, path: "/" },
  { label: "Scan queue", icon: History, count: "03", path: "/queue" },
  { label: "Rule library", icon: Code2, path: "/rules" },
  { label: "Assets", icon: Layers3, path: "/assets" },
];

const systemItems: { label: ViewName; icon: typeof Github; hasDot?: boolean; path: string }[] = [
  { label: "Integrations", icon: Github, path: "/integrations" },
  { label: "Notifications", icon: Bell, hasDot: true, path: "/notifications" },
  { label: "Settings", icon: Settings2, path: "/settings" },
];

const routeToView: Record<string, ViewName> = {
  "/": "Overview",
  "/queue": "Scan queue",
  "/rules": "Rule library",
  "/assets": "Assets",
  "/integrations": "Integrations",
  "/notifications": "Notifications",
  "/settings": "Settings",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function severityClass(severity: Severity) {
  return { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", PASSED: "passed" }[severity] ?? "";
}
function scanFindingsLabel(score: number) {
  return score >= 80 ? "02" : "03";
}
function StatusDot({ state = "live" }: { state?: "live" | "idle" | "warn" }) {
  return <span className={`status-dot ${state}`} aria-label={state} />;
}

// ─── Score Ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score, scanning }: { score: number; scanning: boolean }) {
  const radius = 76;
  const circumference = 2 * Math.PI * radius;
  const dash = circumference * (score / 100);
  return (
    <div className={`score-ring-container ${scanning ? "is-scanning" : ""}`}>
      <div className="score-alert-count">
        <ShieldAlert size={12} /> {scanning ? "LIVE EVALUATION" : `${scanFindingsLabel(score)} OPEN RISK PATHS`}
      </div>
      <div className="score-ring">
        <svg viewBox="0 0 200 200" aria-hidden="true">
          <circle className="score-track" cx="100" cy="100" r={radius} />
          <circle
            className="score-progress"
            cx="100"
            cy="100"
            r={radius}
            strokeDasharray={`${dash} ${circumference - dash}`}
          />
          <circle className="score-orbit" cx="100" cy="100" r="90" />
          <path className="score-tick" d="M100 8v8M100 184v8M8 100h8M184 100h8" />
        </svg>
        <div className="score-center">
          <span className="score-value">{score}</span>
          <span className="score-caption">posture score</span>
          <span className="score-tag">{scanning ? "SCANNING" : score >= 80 ? "HARDENED" : "ACTION NEEDED"}</span>
        </div>
      </div>
    </div>
  );
}

// ─── Workspace Header ─────────────────────────────────────────────────────────
function WorkspaceHeader({
  eyebrow,
  title,
  description,
  action,
  setLocation,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
  setLocation: (path: string) => void;
}) {
  return (
    <section className="workspace-header">
      <div>
        <div className="eyebrow"><span className="eyebrow-line" /> {eyebrow}</div>
        <h1>{title}</h1>
        <p className="intro-copy">{description}</p>
      </div>
      <div className="workspace-header-actions">
        <button className="back-button" onClick={() => setLocation("/")}>
          <ArrowLeft size={15} /> OVERVIEW
        </button>
        {action}
      </div>
    </section>
  );
}

// ─── View: Overview / Dashboard ───────────────────────────────────────────────
function DashboardView({
  scan,
  setScan,
  scanState,
  setScanState,
  fileName,
  setFileName,
  file,
  setFile,
  setLocation,
}: {
  scan: ScanPayload;
  setScan: (scan: ScanPayload) => void;
  scanState: "idle" | "scanning" | "complete";
  setScanState: (state: "idle" | "scanning" | "complete") => void;
  fileName: string;
  setFileName: (name: string) => void;
  file: File | null;
  setFile: (file: File | null) => void;
  setLocation: (path: string) => void;
}) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(scan.findings[0]?.rule_id ?? null);
  const [search, setSearch] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const score = useMemo(() => {
    if (scan.security_score) return scan.security_score.score;
    const { critical, high, medium, passed } = scan.summary;
    const total = critical + high + medium + passed;
    return total === 0 ? 100 : Math.round(((passed + medium * 0.65 + high * 0.35) / total) * 100);
  }, [scan]);
  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return scan.findings;
    return scan.findings.filter((finding) =>
      [finding.rule_id, finding.resource, finding.service, finding.description].some((value) =>
        value?.toLowerCase().includes(query)
      )
    );
  }, [scan.findings, search]);

  const startScan = async () => {
    if (scanState === "scanning") return;
    setScanState("scanning");
    toast("Scanner armed", { description: `Inspecting ${fileName} against 35 active rules.` });

    let currentFile = file;
    if (!currentFile) {
      const demoContent = `
resource "aws_s3_bucket" "main" {
  bucket = "vantage-prod"
  acl    = "public-read"
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_policy" "deploy" {
  policy = jsonencode({
    Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }]
  })
}
`;
      currentFile = new File([demoContent], "vantage-prod.tf", { type: "text/plain" });
    }

    try {
      const formData = new FormData();
      formData.append("file", currentFile);
      const response = await fetch("/api/scan", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || "Scan failed");
      }

      const data = await response.json();
      setScan({ summary: data.summary, findings: data.findings, security_score: data.security_score });
      setScanState("complete");
      setExpandedFinding(data.findings[0]?.rule_id ?? null);
      toast.success("Scan complete", { description: `${data.findings.length} actionable findings remain.` });
    } catch (error) {
      toast.error("Scan error", { description: String(error) });
      setScanState("idle");
    }
  };

  const emptyScan: ScanPayload = {
    summary: { critical: 0, high: 0, medium: 0, passed: 0 },
    findings: [],
    security_score: { score: 100, grade: "A+", verdict: "Ready to scan" }
  };

  const handleFile = (f?: File) => {
    if (!f) return;
    setFile(f);
    setFileName(f.name);
    setScanState("idle");
    setScan(emptyScan);
    setExpandedFinding(null);
    toast("Configuration loaded", { description: `${f.name} is ready for a local posture pass.` });
  };

  const totalExposures = scan.summary.critical + scan.summary.high + scan.summary.medium;

  return (
    <>
      <section className="page-intro">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            <span>LIVE POSTURE / {fileName.toUpperCase()}</span>
            <span className={`status-pill ${totalExposures > 0 ? "warn" : "clean"}`}>
              <StatusDot state={totalExposures > 0 ? "warn" : "live"} />
              {totalExposures > 0 ? `${totalExposures} EXPOSURES` : "HARDENED"}
            </span>
          </div>
          <h1>
            {scanState === "scanning" ? (
              <>Evaluating <span className="mono">{fileName}</span></>
            ) : totalExposures > 0 ? (
              <>{totalExposures} security issues <span>require review.</span></>
            ) : (
              <>All checks passed. <span>Workspace secured.</span></>
            )}
          </h1>
          <p className="intro-copy">
            {scanState === "scanning"
              ? `Running static analysis across 35 security controls for ${fileName}...`
              : totalExposures > 0
              ? `Vantage detected ${totalExposures} security exposures in ${fileName}. Remediate before apply.`
              : `0 active risks found in ${fileName}. All 35 security policy rules passed successfully.`}
          </p>
        </div>
        <div className="intro-actions">
          <button
            className={`primary-cta ${scanState === "scanning" ? "scanning" : ""}`}
            onClick={startScan}
            disabled={scanState === "scanning"}
          >
            {scanState === "scanning" ? (
              <><RefreshCw size={16} className="spin" /> SCANNING FILE</>
            ) : scanState === "complete" ? (
              <><Check size={16} /> RE-RUN SCAN</>
            ) : (
              <><Play size={16} fill="currentColor" /> RUN LOCAL SCAN</>
            )}
            <span className="cta-shortcut">⌘ ↵</span>
          </button>
          <span className="last-scan"><span className="mini-pulse" /> ENGINE <strong>READY</strong></span>
        </div>
      </section>

      <section className="telemetry-banner">
        <div className="telemetry-overlay" />
        <div className="telemetry-copy">
          <span className="mono signal-code">PLAN / LOCAL</span>
          <strong>Plan evidence is ready.</strong>
          <span>Local run · Vantage analysis attached · 0 queue latency</span>
        </div>
        <div className="telemetry-readout">
          <span>RULES EVALUATED</span>
          <strong>{scan.summary.passed + scan.findings.length}<small> / 35</small></strong>
        </div>
        <div className="telemetry-readout">
          <span>LAST SYNC</span>
          <strong>00:04<small> ago</small></strong>
        </div>
        <div className="telemetry-wave">
          <span /><span /><span /><span /><span /><span /><span /><span /><span />
        </div>
      </section>

      <section className="hero-grid">
        <article className="panel score-panel">
          <div className="panel-head">
            <div>
              <span className="panel-kicker"><Radar size={14} /> POSTURE INDEX</span>
              <h2>Security posture</h2>
            </div>
            <button className="quiet-button" onClick={() => toast("Score methodology", { description: "Passes, weighted findings, asset criticality, and exposure context roll into this index." })}>
              <MoreHorizontal size={17} />
            </button>
          </div>
          <div className="score-layout">
            <ScoreRing score={score} scanning={scanState === "scanning"} />
            <div className="score-context">
              <div className="context-status">
                <StatusDot state={scanState === "complete" ? "live" : "warn"} />
                <span>{scanState === "complete" ? "IMPROVING" : "EXPOSURE DETECTED"}</span>
              </div>
              <p>
                {scanState === "complete"
                  ? "Critical exposure cleared. High-impact paths still need an owner."
                  : "Public access and unrestricted ingress are the dominant risk paths in this workspace."}
              </p>
              <div className="metric-split">
                <div><strong>{scan.summary.passed}</strong><span>checks passed</span></div>
                <div><strong>{totalExposures}</strong><span>open findings</span></div>
              </div>
            </div>
          </div>
          <div className="score-footer">
            <span>SOURCE / LOCAL RUN</span>
            <span><Zap size={12} /> REAL-TIME</span>
          </div>
        </article>

        <article className="panel upload-panel">
          <div className="upload-tint" />
          <div className="panel-head on-dark">
            <div>
              <span className="panel-kicker"><UploadCloud size={14} /> MANUAL SOURCE SCAN</span>
              <h2>Scan a local config.</h2>
            </div>
            <span className="secure-label"><LockKeyhole size={12} /> LOCAL PASS</span>
          </div>
          <label
            className="dropzone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); handleFile(e.dataTransfer.files?.[0]); }}
          >
            <input ref={fileInput} type="file" accept=".tf,.zip,.tar,.gz" onChange={(e) => handleFile(e.target.files?.[0])} />
            <div className="drop-icon"><FileUp size={22} /></div>
            <div>
              <strong>{fileName}</strong>
              <span>Terraform · ready to inspect</span>
            </div>
            <span className="drop-action">CHANGE <ChevronDown size={14} /></span>
          </label>
          <div className="upload-footer">
            <span><ShieldCheck size={14} /> Files are analyzed by the local API</span>
            <button onClick={() => fileInput.current?.click()}>BROWSE FILES <ArrowUpRight size={14} /></button>
          </div>
          <div className="source-mode-note">
            <span className="mono">MANUAL PATH</span>
            <span>Local file analysis mode.</span>
          </div>
        </article>
      </section>

      <section className="insight-grid">
        <article className="panel findings-panel">
          <div className="panel-head findings-head">
            <div>
              <span className="panel-kicker"><ShieldAlert size={14} /> FINDINGS / {String(filteredFindings.length).padStart(2, "0")}</span>
              <h2>Action required</h2>
            </div>
            <div className="findings-tools">
              <div className="search-field">
                <Search size={14} />
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter findings" aria-label="Filter findings" />
              </div>
              <button className="filter-button" onClick={() => toast("Filters are clear", { description: "Showing critical, high, and medium findings." })}>
                <SlidersHorizontal size={15} /> FILTER
              </button>
            </div>
          </div>
          <div className="severity-strip">
            <div><span className="sev-dot critical-bg" /> CRITICAL <strong>{scan.summary.critical}</strong></div>
            <div><span className="sev-dot high-bg" /> HIGH <strong>{scan.summary.high}</strong></div>
            <div><span className="sev-dot medium-bg" /> MEDIUM <strong>{scan.summary.medium}</strong></div>
            <div className="severity-spacer" />
            <span className="mono finding-count">{scan.summary.passed} passed / 35 rules</span>
          </div>
          <div className="finding-list">
            {filteredFindings.length ? (
              filteredFindings.map((finding) => {
                const open = expandedFinding === finding.rule_id;
                return (
                  <div key={finding.rule_id} className={`finding-row ${open ? "open" : ""}`}>
                    <button className="finding-summary" onClick={() => setExpandedFinding(open ? null : finding.rule_id)} aria-expanded={open}>
                      <span className={`severity-badge ${severityClass(finding.severity)}`}>{finding.severity}</span>
                      <span className="rule-id mono">{finding.rule_id}</span>
                      <span className="finding-resource">{finding.resource}</span>
                      <span className="finding-service">{finding.service}</span>
                      <ChevronDown className={`finding-chevron ${open ? "rotate" : ""}`} size={16} />
                    </button>
                    {open && (
                      <div className="finding-detail">
                        <div className="detail-alert"><AlertOctagon size={17} /><span>{finding.description}</span></div>
                        <div className="detail-meta">
                          <span><TerminalSquare size={13} /> {finding.line}</span>
                          <span><Fingerprint size={13} /> rule engine / terraform</span>
                        </div>
                        <div className="remediation">
                          <span className="mono">REMEDIATION</span>
                          <p>{finding.remediation}</p>
                          <button onClick={async () => {
                            const parts = finding.resource.split(".");
                            if (parts.length !== 2) {
                              toast.error("Invalid resource format", { description: finding.resource });
                              return;
                            }
                            toast.loading("Generating secure code...", { id: "ai-fix-" + finding.rule_id });
                            try {
                              const res = await fetch("/api/ai-fix", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ resource_type: parts[0], resource_name: parts[1], vulnerability_description: finding.description }),
                              });
                              if (!res.ok) {
                                const err = await res.json().catch(() => ({}));
                                throw new Error(err.detail || "AI Fix failed");
                              }
                              const data = await res.json();
                              await navigator.clipboard.writeText(data.fixed_code);
                              toast.success("Secure code copied to clipboard", { id: "ai-fix-" + finding.rule_id });
                            } catch (e) {
                              toast.error(String(e), { id: "ai-fix-" + finding.rule_id });
                            }
                          }}>AUTO-FIX (AI) <Sparkles size={14} /></button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="empty-findings">
                <CheckCircle2 size={20} />
                <span>No findings match “{search}”.</span>
                <button onClick={() => setSearch("")}>CLEAR FILTER</button>
              </div>
            )}
          </div>
          <button className="view-all-button" onClick={() => setLocation("/rules")}>
            VIEW ALL ACTIVE RULES <ArrowUpRight size={14} />
          </button>
        </article>

        <article className="panel topology-panel">
          <div className="topology-tint" />
          <div className="panel-head on-dark">
            <div><span className="panel-kicker"><Cloud size={14} /> RESOURCE MAP</span><h2>Attack surface</h2></div>
            <span className="map-live"><StatusDot /> LIVE</span>
          </div>
          <div className="topology-center">
            <div className="topology-orbit orbit-one" />
            <div className="topology-orbit orbit-two" />
            <div className="topology-core"><ShieldCheck size={24} /><span>VANTAGE</span></div>
            <span className="topology-node node-one">S3 <b>01</b></span>
            <span className="topology-node node-two">IAM <b>07</b></span>
            <span className="topology-node node-three">VPC <b>03</b></span>
            <span className="topology-node node-four">EC2 <b>12</b></span>
          </div>
          <div className="topology-stats">
            <div><span>RESOURCES</span><strong>23</strong></div>
            <div><span>PROTECTED</span><strong className="volt">20</strong></div>
            <div><span>EXPOSED</span><strong className="coral">03</strong></div>
          </div>
          <button className="topology-link" onClick={() => setLocation("/assets")}>
            OPEN ASSET MAP <ArrowUpRight size={14} />
          </button>
        </article>
      </section>

      <section className="check-status-strip panel">
        <div className="check-status-intro">
          <span className="panel-kicker"><ShieldCheck size={14} /> CHECK PROVENANCE</span>
          <strong>Two layers. One safer apply.</strong>
          <p>Terraform config validation. Vantage evaluates security exposure.</p>
        </div>
        <div className="check-status-item">
          <span className="status-icon native"><Check size={14} /></span>
          <div>
            <span>TERRAFORM</span>
            <strong>Native checks online</strong>
            <small>validation · plan · policy gates</small>
          </div>
        </div>
        <div className="check-status-item">
          <span className="status-icon vantage"><ShieldAlert size={14} /></span>
          <div>
            <span>VANTAGE</span>
            <strong>Security analysis ready</strong>
            <small>35 risk rules · plan-aware findings</small>
          </div>
        </div>
        <div className="check-status-item drift">
          <span className="status-icon drift"><Radar size={14} /></span>
          <div>
            <span>DRIFT SIGNAL</span>
            <strong>Assessment dependent</strong>
            <small>direct AWS changes need drift detection</small>
          </div>
        </div>
      </section>
    </>
  );
}

// ─── Rule Library Data (matches backend rules) ────────────────────────────────
type Rule = {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  service: string;
  coverage: string;
  status: string;
  description: string;
};

const ruleLibrary: Rule[] = [
  { id: "AWS-001", severity: "CRITICAL", title: "S3 Bucket: Public ACL",                           service: "aws_s3_bucket",                     coverage: "security", status: "ACTIVE", description: "S3 bucket allows public read access via ACL." },
  { id: "AWS-002", severity: "CRITICAL", title: "Security Group: Open SSH to the World",            service: "aws_security_group",                coverage: "security", status: "ACTIVE", description: "Security group allows unrestricted inbound SSH from 0.0.0.0/0." },
  { id: "AWS-003", severity: "HIGH",     title: "IAM Policy: Wildcard Star/Star Permissions",       service: "aws_iam_policy",                    coverage: "security", status: "ACTIVE", description: "IAM policy grants Action:* on Resource:* — full administrator access." },
  { id: "AWS-004", severity: "HIGH",     title: "RDS Instance: Unencrypted Storage at Rest",        service: "aws_db_instance",                   coverage: "security", status: "ACTIVE", description: "RDS instance does not have storage_encrypted enabled." },
  { id: "AWS-005", severity: "MEDIUM",   title: "S3 Bucket: Versioning Not Enabled",                service: "aws_s3_bucket_versioning",          coverage: "security", status: "ACTIVE", description: "S3 versioning is Suspended or missing, preventing object recovery." },
  { id: "AWS-016", severity: "HIGH",     title: "EFS File System: Unencrypted",                     service: "aws_efs_file_system",               coverage: "security", status: "ACTIVE", description: "EFS file system is not encrypted at rest." },
  { id: "AWS-017", severity: "HIGH",     title: "ElastiCache: Transit Encryption Disabled",         service: "aws_elasticache_replication_group", coverage: "security", status: "ACTIVE", description: "ElastiCache replication group has transit encryption disabled." },
  { id: "AWS-018", severity: "HIGH",     title: "ElastiCache: At-Rest Encryption Disabled",         service: "aws_elasticache_replication_group", coverage: "security", status: "ACTIVE", description: "ElastiCache replication group has at-rest encryption disabled." },
  { id: "AWS-019", severity: "MEDIUM",   title: "CloudFront: Allows Unencrypted HTTP",              service: "aws_cloudfront_distribution",       coverage: "security", status: "ACTIVE", description: "CloudFront viewer_protocol_policy is set to allow-all." },
  { id: "AWS-020", severity: "HIGH",     title: "SageMaker: Notebook Root Access Enabled",          service: "aws_sagemaker_notebook_instance",   coverage: "security", status: "ACTIVE", description: "SageMaker notebook instance has root access enabled." },
  { id: "AWS-021", severity: "HIGH",     title: "DocumentDB: Cluster Not Encrypted",                service: "aws_docdb_cluster",                 coverage: "security", status: "ACTIVE", description: "DocumentDB cluster is not encrypted." },
  { id: "AWS-022", severity: "HIGH",     title: "DAX: Cluster Not Encrypted at Rest",               service: "aws_dax_cluster",                   coverage: "security", status: "ACTIVE", description: "DAX cluster does not have server-side encryption enabled." },
  { id: "AWS-023", severity: "HIGH",     title: "Kinesis: Stream Not Encrypted",                    service: "aws_kinesis_stream",                coverage: "security", status: "ACTIVE", description: "Kinesis stream has no encryption_type set." },
  { id: "AWS-024", severity: "CRITICAL", title: "Redshift: Cluster Publicly Accessible",            service: "aws_redshift_cluster",              coverage: "security", status: "ACTIVE", description: "Redshift cluster is exposed to the public internet." },
  { id: "AWS-025", severity: "HIGH",     title: "Redshift: Cluster Not Encrypted",                  service: "aws_redshift_cluster",              coverage: "security", status: "ACTIVE", description: "Redshift cluster does not have encryption enabled." },
  { id: "AWS-026", severity: "CRITICAL", title: "EKS: Cluster Endpoint Publicly Accessible",        service: "aws_eks_cluster",                   coverage: "security", status: "ACTIVE", description: "EKS cluster API server endpoint is publicly accessible." },
  { id: "AWS-027", severity: "HIGH",     title: "EMR: Security Configuration Missing Encryption",   service: "aws_emr_security_configuration",    coverage: "security", status: "ACTIVE", description: "EMR security configuration does not enforce at-rest encryption." },
  { id: "AWS-028", severity: "HIGH",     title: "Amazon MQ: Broker Publicly Accessible",            service: "aws_mq_broker",                     coverage: "security", status: "ACTIVE", description: "Amazon MQ broker is publicly accessible." },
  { id: "AWS-029", severity: "HIGH",     title: "Neptune: Graph Database Not Encrypted",            service: "aws_neptune_cluster",               coverage: "security", status: "ACTIVE", description: "Neptune graph database is not encrypted." },
  { id: "AWS-030", severity: "MEDIUM",   title: "WorkSpaces: Root Volume Not Encrypted",            service: "aws_workspaces_workspace",          coverage: "security", status: "ACTIVE", description: "WorkSpaces root volume encryption is not enabled." },
  { id: "AWS-031", severity: "MEDIUM",   title: "Athena: Workgroup Encryption Not Enforced",        service: "aws_athena_workgroup",              coverage: "security", status: "ACTIVE", description: "Athena workgroup does not enforce query result encryption." },
  { id: "AWS-032", severity: "MEDIUM",   title: "SNS: Topic Not Encrypted with KMS",                service: "aws_sns_topic",                     coverage: "security", status: "ACTIVE", description: "SNS topic is not encrypted with a KMS key." },
  { id: "AWS-033", severity: "MEDIUM",   title: "ECS: Task Definition Missing Transit Encryption",  service: "aws_ecs_task_definition",           coverage: "security", status: "ACTIVE", description: "ECS task definition does not enable transit encryption." },
  { id: "AWS-034", severity: "MEDIUM",   title: "CodeBuild: Project Missing Encryption Key",        service: "aws_codebuild_project",             coverage: "security", status: "ACTIVE", description: "CodeBuild project is missing an encryption key." },
  { id: "AWS-035", severity: "LOW",      title: "AppSync: GraphQL API Missing WAF",                  service: "aws_appsync_graphql_api",           coverage: "security", status: "ACTIVE", description: "AppSync GraphQL API does not have a WAF web ACL attached." },
  { id: "AWS-036", severity: "LOW",      title: "API Gateway: Stage Missing WAF",                    service: "aws_api_gateway_stage",             coverage: "security", status: "ACTIVE", description: "API Gateway stage does not have a WAF web ACL attached." },
  { id: "AWS-037", severity: "LOW",      title: "Lambda: X-Ray Tracing Disabled",                   service: "aws_lambda_function",               coverage: "security", status: "ACTIVE", description: "Lambda function does not have X-Ray tracing enabled." },
  { id: "AWS-038", severity: "MEDIUM",   title: "VPC: Flow Logs Disabled",                          service: "aws_vpc",                           coverage: "security", status: "ACTIVE", description: "VPC does not have Flow Logs enabled." },
  { id: "AWS-039", severity: "MEDIUM",   title: "IAM: Password Policy Allows Reuse",               service: "aws_iam_account_password_policy",   coverage: "security", status: "ACTIVE", description: "IAM password policy allows immediate password reuse." },
];

// ─── View: Rules Library ──────────────────────────────────────────────────────
function RulesView({ setLocation }: { setLocation: (path: string) => void }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const counts = { CRITICAL: 4, HIGH: 13, MEDIUM: 9, LOW: 3 } as const;
  const filtered = ruleLibrary.filter(
    (rule) =>
      (severity === "ALL" || rule.severity === severity) &&
      [rule.id, rule.title, rule.service, rule.description].some((v) => v.toLowerCase().includes(query.toLowerCase()))
  );

  return (
    <>
      <WorkspaceHeader
        setLocation={setLocation}
        eyebrow={`EVIDENCE REGISTER / ${ruleLibrary.length} ACTIVE`}
        title="Security rules"
        description="A searchable register of the controls Vantage applies to every Terraform configuration."
        action={
          <button
            className="primary-cta compact"
            onClick={() => toast.success("Rule set synced", { description: `${ruleLibrary.length} active Vantage rules are current.` })}
          >
            <RefreshCw size={15} /> SYNC RULES
          </button>
        }
      />
      <section className="workspace-toolbar">
        <div className="search-field wide">
          <Search size={14} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search rule ID, service, or control" />
        </div>
        <div className="segmented-control">
          {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
            <button key={sev} className={severity === sev ? "selected" : ""} onClick={() => setSeverity(sev)}>
              {sev}<span>{sev === "ALL" ? ruleLibrary.length : counts[sev as keyof typeof counts] ?? 0}</span>
            </button>
          ))}
        </div>
      </section>
      <section className="rule-grid">
        {filtered.map((rule) => (
          <article className="rule-card" key={rule.id}>
            <div className="rule-card-top">
              <span className={`severity-badge ${severityClass(rule.severity)}`}>{rule.severity}</span>
              <span className="mono rule-card-id">{rule.id}</span>
              <span className="rule-active"><StatusDot /> {rule.status}</span>
            </div>
            <h2>{rule.title}</h2>
            <p>{rule.description}</p>
            <div className="rule-card-footer">
              <span><Code2 size={13} /> {rule.service}</span>
              <span className="mono">/{rule.coverage}</span>
              <button onClick={() => toast("Rule details", { description: `${rule.id} · ${rule.title}` })}>
                INSPECT <ArrowUpRight size={13} />
              </button>
            </div>
          </article>
        ))}
      </section>
      {filtered.length === 0 && (
        <div className="workspace-empty">
          <Search size={20} />
          <strong>No rules match this filter.</strong>
          <button onClick={() => { setQuery(""); setSeverity("ALL"); }}>RESET LIBRARY</button>
        </div>
      )}
    </>
  );
}

// ─── View: Scan Queue ─────────────────────────────────────────────────────────
const queueData = [
  { id: "SCAN-0884", file: "vantage-prod.tf", branch: "main", status: "COMPLETE", score: "90", findings: "02", time: "4 min ago", duration: "1.8s", author: "Leah Stone" },
  { id: "SCAN-0883", file: "network-baseline.tf", branch: "release/1.4", status: "COMPLETE", score: "84", findings: "05", time: "18 min ago", duration: "2.1s", author: "DevOps Bot" },
  { id: "SCAN-0882", file: "sandbox-stack.tf", branch: "feat/sandbox", status: "QUEUED", score: "—", findings: "—", time: "waiting", duration: "—", author: "Leah Stone" },
];

function QueueView({ setLocation }: { setLocation: (path: string) => void }) {
  const [selected, setSelected] = useState(queueData[0]);
  return (
    <>
      <section className="workspace-header">
        <div>
          <h1>Scan queue</h1>
          <p className="intro-copy">A lightweight run history for every configuration that has crossed the Vantage engine.</p>
        </div>
        <div className="workspace-header-actions">
          <button className="back-button" onClick={() => setLocation("/")}>
            <ArrowLeft size={15} /> OVERVIEW
          </button>
          <button className="primary-cta compact" onClick={() => setLocation("/")}>
            <Play size={14} fill="currentColor" /> NEW SCAN
          </button>
        </div>
      </section>

      <section className="queue-summary">
        <div>
          <span>RUNS TODAY</span>
          <strong>08</strong>
          <small><ArrowUpRight size={13} /> 2 vs yesterday</small>
        </div>
        <div>
          <span>AVG DURATION</span>
          <strong>1.8s</strong>
          <small><Zap size={13} /> stable</small>
        </div>
        <div>
          <span>QUEUE LATENCY</span>
          <strong>00:00</strong>
          <small><Check size={13} /> clear</small>
        </div>
        <div>
          <span>LAST FAILURE</span>
          <strong>12d</strong>
          <small><ShieldCheck size={13} /> ago</small>
        </div>
      </section>

      <section className="queue-layout">
        <article className="panel queue-list">
          <div className="panel-head">
            <div>
              <span className="panel-kicker"><History size={14} /> RUN HISTORY</span>
              <h2>Recent scans</h2>
            </div>
            <button className="filter-button" onClick={() => toast("Filter applied")}>
              <SlidersHorizontal size={14} /> FILTER
            </button>
          </div>
          {queueData.map((item) => (
            <button
              key={item.id}
              className={`queue-row ${selected.id === item.id ? "selected" : ""}`}
              onClick={() => setSelected(item)}
            >
              <span className={`queue-status ${item.status === "QUEUED" ? "queued" : ""}`}>
                <StatusDot state={item.status === "COMPLETE" ? "live" : "idle"} /> {item.status}
              </span>
              <span className="queue-file">
                <strong>{item.file}</strong>
                <small>{item.branch}</small>
              </span>
              <div className="queue-stat">
                <span>SCORE</span>
                <strong>{item.score}</strong>
              </div>
              <div className="queue-stat">
                <span>FINDINGS</span>
                <strong>{item.findings}</strong>
              </div>
              <span className="queue-time">{item.time}</span>
            </button>
          ))}
        </article>

        <article className="panel queue-detail">
          <div className="panel-head">
            <div>
              <span className="panel-kicker"><FileCode2 size={14} /> RUN DETAIL</span>
            </div>
          </div>
          <div className="queue-detail-status">
            <StatusDot state={selected.status === "COMPLETE" ? "live" : "idle"} /> {selected.status}
          </div>
          <h2>{selected.file}</h2>
          <p>Terraform configuration evaluated against the current Vantage ruleset.</p>
          <div className="queue-detail-grid">
            <div>
              <span>POSTURE</span>
              <strong>{selected.score}</strong>
            </div>
            <div>
              <span>FINDINGS</span>
              <strong className={selected.findings !== "—" && selected.findings !== "00" ? "coral-text" : ""}>{selected.findings}</strong>
            </div>
            <div>
              <span>BRANCH</span>
              <strong>{selected.branch}</strong>
            </div>
            <div>
              <span>DURATION</span>
              <strong>{selected.duration}</strong>
            </div>
          </div>
        </article>
      </section>
    </>
  );
}

// ─── View: Assets Inventory ───────────────────────────────────────────────────
const assetData = [
  {
    name: "aws_s3_bucket.main",
    type: "S3 bucket",
    group: "Storage",
    owner: "platform-team",
    state: "EXPOSED",
    risk: "CRITICAL",
    detail: "Public read access detected via ACL. Bucket contains 3.2 GB of artifacts.",
    evidence: 'resource "aws_s3_bucket" "main" {\n  bucket = "vantage-prod"\n  acl    = "public-read"\n}',
  },
  {
    name: "aws_security_group.web",
    type: "Security group",
    group: "Network",
    owner: "infra-core",
    state: "EXPOSED",
    risk: "HIGH",
    detail: "Unrestricted ingress SSH from 0.0.0.0/0 on port 22.",
    evidence: 'resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}',
  },
  {
    name: "aws_iam_policy.deploy",
    type: "IAM policy",
    group: "Identity",
    owner: "secops",
    state: "EXPOSED",
    risk: "HIGH",
    detail: "Wildcard Action:* granted on Resource:* in deployment policy.",
    evidence: 'resource "aws_iam_policy" "deploy" {\n  policy = jsonencode({\n    Statement = [{ Action = "*", Resource = "*" }]\n  })\n}',
  },
  {
    name: "aws_vpc.core",
    type: "VPC",
    group: "Network",
    owner: "infra-core",
    state: "PROTECTED",
    risk: "PASSED",
    detail: "Private subnets and VPC Flow Logs are configured correctly.",
    evidence: 'resource "aws_vpc" "core" {\n  cidr_block = "10.0.0.0/16"\n  enable_dns_hostnames = true\n}',
  },
];

function AssetsView({ setLocation }: { setLocation: (path: string) => void }) {
  const [filter, setFilter] = useState<"ALL" | "EXPOSED" | "PROTECTED">("ALL");
  const [selected, setSelected] = useState(assetData[0]);

  return (
    <>
      <section className="workspace-header">
        <div>
          <h1>Attack surface</h1>
          <p className="intro-copy">Trace exposed resources to the exact Terraform object that created them.</p>
        </div>
        <div className="workspace-header-actions">
          <button className="back-button" onClick={() => setLocation("/")}>
            <ArrowLeft size={15} /> OVERVIEW
          </button>
          <button className="primary-cta compact" onClick={() => toast.success("Map refreshed")}>
            <RefreshCw size={14} /> REFRESH MAP
          </button>
        </div>
      </section>

      <div className="asset-toolbar-strip panel">
        <div className="asset-summary-counts">
          <div>
            <strong>23</strong>
            <span>resources tracked</span>
          </div>
          <i />
          <div>
            <strong className="volt">20</strong>
            <span>protected</span>
          </div>
          <i />
          <div>
            <strong className="coral">03</strong>
            <span>exposed</span>
          </div>
        </div>
        <div className="segmented-control">
          {(["ALL", "EXPOSED", "PROTECTED"] as const).map((tab) => (
            <button key={tab} className={filter === tab ? "selected" : ""} onClick={() => setFilter(tab)}>
              {tab}
            </button>
          ))}
        </div>
      </div>

      <section className="assets-layout">
        <article className="panel asset-graph-panel">
          <div className="asset-graph-grid" />
          <svg className="asset-graph-lines" viewBox="0 0 500 350" preserveAspectRatio="none">
            <line x1="250" y1="175" x2="100" y2="135" stroke="rgba(56, 189, 248, 0.35)" strokeWidth="1.5" />
            <line x1="250" y1="175" x2="400" y2="110" stroke="rgba(56, 189, 248, 0.35)" strokeWidth="1.5" />
            <line x1="250" y1="175" x2="110" y2="270" stroke="rgba(244, 63, 94, 0.35)" strokeWidth="1.5" />
            <line x1="250" y1="175" x2="390" y2="260" stroke="rgba(229, 184, 59, 0.35)" strokeWidth="1.5" />
          </svg>
          <div className="asset-graph-core">
            <ShieldCheck size={26} />
            <span>VANTAGE</span>
            <small>workspace root</small>
          </div>
          <button
            className={`graph-node graph-node-a ${selected.name === assetData[0].name ? "selected" : ""}`}
            onClick={() => setSelected(assetData[0])}
          >
            <span>S3 <b>01</b></span>
            <span className="node-dot coral" />
          </button>
          <button
            className={`graph-node graph-node-b ${selected.name === assetData[1].name ? "selected" : ""}`}
            onClick={() => setSelected(assetData[1])}
          >
            <span>EC2 <b>12</b></span>
            <span className="node-dot coral" />
          </button>
          <button
            className={`graph-node graph-node-d ${selected.name === assetData[2].name ? "selected" : ""}`}
            onClick={() => setSelected(assetData[2])}
          >
            <span>IAM <b>07</b></span>
            <span className="node-dot coral" />
          </button>
          <button
            className={`graph-node graph-node-c ${selected.name === assetData[3].name ? "selected" : ""}`}
            onClick={() => setSelected(assetData[3])}
          >
            <span>VPC <b>03</b></span>
            <span className="node-dot volt" />
          </button>
        </article>

        <article className="panel asset-detail">
          <div className="panel-head">
            <div>
              <span className="panel-kicker"><Layers3 size={14} /> SELECTED RESOURCE</span>
            </div>
          </div>
          <div className="asset-tags">
            <span className={`asset-tag ${selected.state.toLowerCase()}`}>{selected.state}</span>
            <span className={`asset-tag ${selected.risk.toLowerCase()}`}>{selected.risk}</span>
          </div>
          <h2>{selected.name}</h2>
          <p>{selected.detail}</p>
          <div className="asset-props-grid">
            <div>
              <span>TYPE</span>
              <strong>{selected.type}</strong>
            </div>
            <div>
              <span>GROUP</span>
              <strong>{selected.group}</strong>
            </div>
            <div>
              <span>OWNER</span>
              <strong>{selected.owner}</strong>
            </div>
          </div>
          <div className="asset-evidence-box">
            <span>EVIDENCE</span>
            <pre>{selected.evidence}</pre>
          </div>
        </article>
      </section>
    </>
  );
}

// ─── View: Integrations ───────────────────────────────────────────────────────
const integrationData = [
  { id: "github", name: "GitHub Actions", desc: "Automated scan on PR creation, comments on lines with security exposures.", connected: true, icon: "volt", badge: "CI/CD" },
  { id: "gitlab", name: "GitLab CI", desc: "Pipeline security gate blocking deployment jobs on CRITICAL policy failures.", connected: false, icon: "cyan", badge: "PIPELINE" },
  { id: "tfc", name: "Terraform Cloud", desc: "Run task integration inspecting planned changes before workspace apply.", connected: false, icon: "coral", badge: "RUN TASK" },
];

function IntegrationsView({ setLocation }: { setLocation: (path: string) => void }) {
  const [items, setItems] = useState(integrationData);
  return (
    <>
      <WorkspaceHeader
        setLocation={setLocation}
        eyebrow="SYSTEM / CONNECTORS"
        title="Integrations"
        description="Connect your VCS and CI/CD pipelines to run Vantage security checks before code merges."
      />
      <section className="integration-grid">
        {items.map((item, idx) => (
          <article className="panel integration-card" key={item.id}>
            <span className={`integration-icon ${item.icon}`}><Github size={20} /></span>
            <div className="integration-card-title">
              <h2>{item.name}</h2>
              <span className={`connection-state ${item.connected ? "connected" : ""}`}>
                <StatusDot state={item.connected ? "live" : "idle"} /> {item.connected ? "CONNECTED" : "OFFLINE"}
              </span>
            </div>
            <p>{item.desc}</p>
            <div className="integration-meta mono">/{item.badge}</div>
            <button
              className={`toggle-control ${item.connected ? "on" : ""}`}
              onClick={() => {
                const next = [...items];
                next[idx].connected = !next[idx].connected;
                setItems(next);
                toast.success(`${item.name} ${next[idx].connected ? "connected" : "disconnected"}`);
              }}
              aria-label={`Toggle ${item.name}`}
            >
              <span />
            </button>
          </article>
        ))}
      </section>
      <section className="panel integration-note">
        <span className="mono signal-code">WEBHOOK READY</span>
        <p>Your local Vantage instance exposes <code>POST /api/scan</code> for direct curl and CI integration.</p>
        <button onClick={() => toast.info("Webhook docs: POST /api/scan with multipart file")}>CURL EXAMPLE <ArrowUpRight size={13} /></button>
      </section>
    </>
  );
}

// ─── View: Notifications ──────────────────────────────────────────────────────
const notificationData = [
  { id: "1", title: "Public S3 Bucket detected in infra/storage.tf", time: "4m ago", type: "critical", unread: true },
  { id: "2", title: "Local scan completed: 23 resources inspected", time: "18m ago", type: "scan", unread: true },
  { id: "3", title: "Security Operator session started", time: "1h ago", type: "owner", unread: false },
];

function NotificationsView({ setLocation }: { setLocation: (path: string) => void }) {
  const [notifs, setNotifs] = useState(notificationData);
  return (
    <>
      <WorkspaceHeader
        setLocation={setLocation}
        eyebrow="EVENTS / AUDIT TRAIL"
        title="Notifications"
        description="System events, policy violation alerts, and local scanning execution log."
        action={
          <button
            className="primary-cta compact"
            onClick={() => {
              setNotifs(notifs.map((n) => ({ ...n, unread: false })));
              toast.success("All notifications marked as read");
            }}
          >
            MARK ALL READ
          </button>
        }
      />
      <section className="panel notification-summary">
        <div className="notification-summary-icon"><Bell size={22} /></div>
        <div><span>TOTAL ALERTS</span><strong>{notifs.length}</strong></div>
        <div><span>UNREAD</span><strong className="volt-text">{notifs.filter((n) => n.unread).length}</strong></div>
        <div><span>HIGH/CRIT</span><strong className="coral-text">01</strong></div>
      </section>
      <section className="panel notification-list">
        {notifs.map((item) => (
          <div key={item.id} className={`notification-row ${item.unread ? "" : "read"}`}>
            <span className={`notification-type ${item.type}`}><StatusDot state={item.type === "critical" ? "warn" : "live"} /> {item.type.toUpperCase()}</span>
            <div className="notification-copy">
              <strong>{item.title}</strong>
              <small>Rule engine verification pass</small>
            </div>
            <span className="notification-time">{item.time}</span>
            <ChevronRight size={14} />
          </div>
        ))}
      </section>
    </>
  );
}

// ─── View: Settings ───────────────────────────────────────────────────────────
function SettingsView({ setLocation }: { setLocation: (path: string) => void }) {
  const [autoFixEnabled, setAutoFixEnabled] = useState(true);
  const [strictExit, setStrictExit] = useState(false);

  return (
    <>
      <WorkspaceHeader
        setLocation={setLocation}
        eyebrow="SYSTEM / CONFIGURATION"
        title="Settings"
        description="Configure scanner behavior, AI remediation endpoints, and severity thresholds."
      />
      <section className="settings-layout">
        <div className="settings-sections">
          <article className="panel settings-section">
            <div className="panel-head">
              <div><span className="panel-kicker"><Settings2 size={14} /> AI REMEDIATION</span><h2>Gemini 1.5 Flash</h2></div>
            </div>
            <div className="setting-row">
              <div>
                <strong>Auto-Fix Code Generation</strong>
                <small>Allows one-click remediation snippet creation directly from findings.</small>
              </div>
              <button
                className={`toggle-control ${autoFixEnabled ? "on" : ""}`}
                onClick={() => {
                  setAutoFixEnabled(!autoFixEnabled);
                  toast.success(`Auto-fix ${!autoFixEnabled ? "enabled" : "disabled"}`);
                }}
                aria-label="Toggle Auto-Fix"
              >
                <span />
              </button>
            </div>
            <div className="setting-row">
              <div>
                <strong>Strict CI Gate Threshold</strong>
                <small>Fail the pipeline run if any CRITICAL or HIGH findings are detected.</small>
              </div>
              <button
                className={`toggle-control ${strictExit ? "on" : ""}`}
                onClick={() => {
                  setStrictExit(!strictExit);
                  toast.success(`Strict mode ${!strictExit ? "enabled" : "disabled"}`);
                }}
                aria-label="Toggle Strict CI Gate"
              >
                <span />
              </button>
            </div>
          </article>
        </div>

        <article className="panel settings-aside">
          <span className="panel-kicker"><Fingerprint size={14} /> LOCAL ENGINE</span>
          <code>VANTAGE v1.0.0-PROD</code>
          <p>Running with local Python rule evaluator. 29 registered rules online.</p>
          <div className="settings-aside-divider" />
          <button onClick={() => toast.success("Environment healthy", { description: "API on localhost:8000" })}>
            TEST CONNECTION <ArrowUpRight size={13} />
          </button>
        </article>
      </section>
    </>
  );
}

// ─── Workspace Switcher ───────────────────────────────────────────────────────
function WorkspaceView({ view, setLocation }: { view: ViewName; setLocation: (path: string) => void }) {
  switch (view) {
    case "Rule library":
      return <RulesView setLocation={setLocation} />;
    case "Scan queue":
      return <QueueView setLocation={setLocation} />;
    case "Assets":
      return <AssetsView setLocation={setLocation} />;
    case "Integrations":
      return <IntegrationsView setLocation={setLocation} />;
    case "Notifications":
      return <NotificationsView setLocation={setLocation} />;
    case "Settings":
      return <SettingsView setLocation={setLocation} />;
    default:
      return null;
  }
}

// ─── Main App Shell ───────────────────────────────────────────────────────────
export default function Home() {
  const [location, setLocation] = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [scanState, setScanState] = useState<"idle" | "scanning" | "complete">("idle");
  const [scan, setScan] = useState<ScanPayload>(initialScan);
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("vantage-prod.tf");

  const view = routeToView[location] ?? "Overview";
  const navigate = (path: string) => {
    setLocation(path);
    setMobileNavOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className={`command-rail ${mobileNavOpen ? "open" : ""}`}>
        <div className="rail-brand">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <div className="brand-lockup">
            <span>VANTAGE</span>
            <small>cloud security</small>
          </div>
          <button className="mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>

        <div className="rail-section-label">WORKBENCH</div>
        <nav className="rail-nav" aria-label="Primary navigation">
          {navItems.map(({ label, icon: Icon, count, path }) => (
            <button
              key={label}
              className={`rail-nav-item ${view === label ? "active" : ""}`}
              onClick={() => navigate(path)}
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
              {count && <em>{count}</em>}
              {view === label && <span className="nav-pip" />}
            </button>
          ))}
        </nav>

        <div className="rail-spacer" />

        <div className="rail-section-label">SYSTEM</div>
        <nav className="rail-nav" aria-label="System navigation">
          {systemItems.map(({ label, icon: Icon, hasDot, path }) => (
            <button
              key={label}
              className={`rail-nav-item ${view === label ? "active" : ""}`}
              onClick={() => navigate(path)}
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
              {hasDot && <span className="notif-dot" />}
              {view === label && <span className="nav-pip" />}
            </button>
          ))}
        </nav>

        <div className="rail-footer">
          <div className="operator-avatar">LS</div>
          <div>
            <strong>Leah Stone</strong>
            <span>SECURITY OPERATOR</span>
          </div>
        </div>
      </aside>

      <main className="main-stage">
        <header className="topbar">
          <div className="crumb">
            <button className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
              <Menu size={18} />
            </button>
            <span className="crumb-brand">VANTAGE</span>
            <ChevronRight size={13} />
            <span>WORKBENCH</span>
            <ChevronRight size={13} />
            <strong>{view.toUpperCase()}</strong>
          </div>
          <div className="topbar-tools">
            <span className="environment-chip"><StatusDot /> LOCAL ENV</span>
            <span className="topbar-time">
              <Activity size={14} /> LIVE TELEMETRY{" "}
              <span className="mono">{new Date().toLocaleTimeString()}</span>
            </span>
          </div>
        </header>

        <div className="content-wrap">
          {view === "Overview" ? (
            <DashboardView
              scan={scan}
              setScan={setScan}
              scanState={scanState}
              setScanState={setScanState}
              fileName={fileName}
              setFileName={setFileName}
              file={file}
              setFile={setFile}
              setLocation={setLocation}
            />
          ) : (
            <WorkspaceView view={view} setLocation={setLocation} />
          )}
        </div>
      </main>
    </div>
  );
}
