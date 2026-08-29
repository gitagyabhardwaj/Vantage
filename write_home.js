const fs = require('fs');
const path = require('path');

const target = path.join('C:/Users/harbo/OneDrive/Desktop/Vantage', 'client/src/pages/Home.tsx');

const tsx = String.raw`import { useMemo, useRef, useState } from "react";
import { useLocation } from "wouter";
import {
  Activity, AlertOctagon, ArrowLeft, ArrowUpRight,
  Check, CheckCircle2, ChevronDown, ChevronRight,
  Cloud, Code2, FileUp, Fingerprint, Gauge, Github,
  LockKeyhole, Menu, MoreHorizontal, Play, Radar,
  RefreshCw, Search, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, TerminalSquare, UploadCloud, X,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ────────────────────────────────────────────────────────────────────
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "PASSED";
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
};
type ViewName = "Overview" | "Rule library";

// ─── Initial demo scan (real rule IDs, real descriptions) ─────────────────────
const initialScan: ScanPayload = {
  summary: { critical: 1, high: 2, medium: 0, passed: 15 },
  findings: [
    {
      rule_id: "AWS-001", severity: "CRITICAL", resource: "aws_s3_bucket.main",
      service: "S3 / storage", line: "infra/storage.tf:18",
      description: "S3 bucket allows public read access via ACL.",
      remediation: 'Change acl = "public-read" to acl = "private" and enforce Block Public Access.',
    },
    {
      rule_id: "AWS-002", severity: "HIGH", resource: "aws_security_group.web",
      service: "EC2 / network", line: "infra/network.tf:42",
      description: "Security group allows unrestricted inbound SSH (port 22) from 0.0.0.0/0.",
      remediation: 'Replace cidr_blocks = ["0.0.0.0/0"] with a trusted CIDR or use SSM Session Manager.',
    },
    {
      rule_id: "AWS-003", severity: "HIGH", resource: "aws_iam_policy.deploy",
      service: "IAM / identity", line: "infra/iam.tf:77",
      description: 'IAM policy grants Action:"*" on Resource:"*" — full administrator access.',
      remediation: "Scope actions and resources to the exact needs of the release pipeline.",
    },
  ],
};

// ─── Navigation ───────────────────────────────────────────────────────────────
const navItems: { label: ViewName; icon: typeof Gauge; path: string }[] = [
  { label: "Overview", icon: Gauge, path: "/" },
  { label: "Rule library", icon: Code2, path: "/rules" },
];
const systemItems: { label: ViewName; icon: typeof Github; path: string }[] = [];
const routeToView: Record<string, ViewName> = {
  "/": "Overview",
  "/rules": "Rule library",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function severityClass(s: string) {
  return ({ CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", PASSED: "passed" } as Record<string, string>)[s] ?? "";
}
function StatusDot({ state = "live" }: { state?: "live" | "idle" | "warn" }) {
  return <span className={`status-dot ${state}`} aria-label={state} />;
}

// ─── Score Ring ───────────────────────────────────────────────────────────────
function ScoreRing({ score, scanning }: { score: number; scanning: boolean }) {
  const r = 83;
  const c = 2 * Math.PI * r;
  const dash = c * (score / 100);
  return (
    <div className={`score-ring ${scanning ? "is-scanning" : ""}`}>
      <svg viewBox="0 0 220 220" aria-hidden="true">
        <circle className="score-track" cx="110" cy="110" r={r} />
        <circle className="score-progress" cx="110" cy="110" r={r} strokeDasharray={`${dash} ${c - dash}`} />
        <circle className="score-orbit" cx="110" cy="110" r="100" />
        <path className="score-tick" d="M110 8v10M110 202v10M8 110h10M202 110h10" />
      </svg>
      <div className="score-center">
        <span className="score-value">{score}</span>
        <span className="score-caption">posture score</span>
      </div>
      <div className="score-tag">{scanning ? "SCANNING" : score >= 80 ? "HARDENED" : "ACTION NEEDED"}</div>
      <div className="score-alert-count">
        <ShieldAlert size={12} /> {scanning ? "LIVE EVALUATION" : "OPEN RISK PATHS"}
      </div>
    </div>
  );
}

// ─── Dashboard View ───────────────────────────────────────────────────────────
function DashboardView({
  scan, setScan, scanState, setScanState, fileName, setFileName, file, setFile, setLocation,
}: {
  scan: ScanPayload;
  setScan: (s: ScanPayload) => void;
  scanState: "idle" | "scanning" | "complete";
  setScanState: (s: "idle" | "scanning" | "complete") => void;
  fileName: string;
  setFileName: (n: string) => void;
  file: File | null;
  setFile: (f: File | null) => void;
  setLocation: (p: string) => void;
}) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(
    scan.findings[0]?.rule_id ?? null
  );
  const [search, setSearch] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);

  const score = useMemo(() => {
    const { critical, high, medium, passed } = scan.summary;
    const total = critical + high + medium + passed;
    return total === 0 ? 100 : Math.round(((passed + medium * 0.65 + high * 0.35) / total) * 100);
  }, [scan]);

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return scan.findings;
    return scan.findings.filter((f) =>
      [f.rule_id, f.resource, f.service, f.description].some((v) => v.toLowerCase().includes(q))
    );
  }, [scan.findings, search]);

  const startScan = async () => {
    if (scanState === "scanning") return;
    setScanState("scanning");
    toast("Scanner armed", { description: `Inspecting ${fileName} against 35 active rules.` });

    let currentFile = file;
    if (!currentFile) {
      const demo = [
        'resource "aws_s3_bucket" "main" { bucket = "vantage-prod" acl = "public-read" }',
        'resource "aws_security_group" "web" { ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] } }',
        'resource "aws_iam_policy" "deploy" { policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] }) }',
      ].join("\n");
      currentFile = new File([demo], "vantage-prod.tf", { type: "text/plain" });
    }

    try {
      const fd = new FormData();
      fd.append("file", currentFile);
      const res = await fetch("/api/scan", { method: "POST", body: fd });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error((e as { detail?: string }).detail || "Scan failed");
      }
      const data = await res.json() as { summary: ScanPayload["summary"]; findings: Finding[] };
      setScan({ summary: data.summary, findings: data.findings });
      setScanState("complete");
      setExpandedFinding(data.findings[0]?.rule_id ?? null);
      toast.success("Scan complete", { description: `${data.findings.length} actionable findings.` });
    } catch (err) {
      toast.error("Scan error", { description: String(err) });
      setScanState("idle");
    }
  };

  const handleFile = (f?: File) => {
    if (!f) return;
    setFile(f); setFileName(f.name); setScanState("idle"); setScan(initialScan);
    setExpandedFinding("AWS-001");
    toast("Configuration loaded", { description: `${f.name} is ready for a local posture pass.` });
  };

  const totalExposures = scan.summary.critical + scan.summary.high + scan.summary.medium;

  return (
    <>
      <section className="page-intro">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> LIVE VERDICT / {fileName.toUpperCase()}</div>
          <h1>{totalExposures} exposures<br /><span>need an owner.</span></h1>
          <p className="intro-copy">
            Vantage analyzed the plan. Found {totalExposures} security paths that need a decision before apply.
          </p>
        </div>
        <div className="intro-actions">
          <button
            className={`primary-cta ${scanState === "scanning" ? "scanning" : ""}`}
            onClick={startScan}
            disabled={scanState === "scanning"}
          >
            {scanState === "scanning" ? (
              <><RefreshCw size={17} className="spin" /> SCANNING FILE</>
            ) : scanState === "complete" ? (
              <><Check size={17} /> RE-RUN SCAN</>
            ) : (
              <><Play size={17} fill="currentColor" /> RUN LOCAL SCAN</>
            )}
            <span className="cta-shortcut">⌘ ↵</span>
          </button>
          <span className="last-scan"><span className="mini-pulse" /> LAST SCAN <strong>4 MIN AGO</strong></span>
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
            <button className="quiet-button" onClick={() => toast("Score methodology", { description: "Passes, weighted findings, and exposure context roll into this index." })}>
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
          <div className="score-footer"><span className="mono">SOURCE / LOCAL RUN</span></div>
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
            <div><strong>{fileName}</strong><span>Terraform · ready to inspect</span></div>
            <span className="drop-action">CHANGE <ChevronDown size={14} /></span>
          </label>
          <div className="upload-footer">
            <span><ShieldCheck size={14} /> File is sent to the local API for analysis</span>
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
              <span className="panel-kicker">
                <ShieldAlert size={14} /> FINDINGS / {String(filteredFindings.length).padStart(2, "0")}
              </span>
              <h2>Action required</h2>
            </div>
            <div className="findings-tools">
              <div className="search-field">
                <Search size={14} />
                <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter findings" aria-label="Filter findings" />
              </div>
              <button className="filter-button" onClick={() => toast("Filters are clear", { description: "Showing all active findings." })}>
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
            {filteredFindings.length ? filteredFindings.map((finding) => {
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
                          if (parts.length !== 2) { toast.error("Invalid resource format"); return; }
                          toast.loading("Generating secure code...", { id: "ai-fix-" + finding.rule_id });
                          try {
                            const res = await fetch("/api/ai-fix", {
                              method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify({
                                resource_type: parts[0],
                                resource_name: parts[1],
                                vulnerability_description: finding.description,
                              }),
                            });
                            if (!res.ok) {
                              const e = await res.json().catch(() => ({}));
                              throw new Error((e as { detail?: string }).detail || "AI Fix failed");
                            }
                            const data = await res.json() as { fixed_code: string };
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
            }) : (
              <div className="empty-findings">
                <CheckCircle2 size={20} />
                <span>No findings match "{search}".</span>
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
            <div>
              <span className="panel-kicker"><Cloud size={14} /> RESOURCE MAP</span>
              <h2>Attack surface</h2>
            </div>
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
          <div><span>TERRAFORM</span><strong>Native checks online</strong><small>validation · plan · policy gates</small></div>
        </div>
        <div className="check-status-item">
          <span className="status-icon vantage"><ShieldAlert size={14} /></span>
          <div><span>VANTAGE</span><strong>Security analysis ready</strong><small>35 risk rules · plan-aware findings</small></div>
        </div>
      </section>
    </>
  );
}

// ─── Rule Library (matches api/rules.py exactly) ──────────────────────────────
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

// ─── Workspace Header ─────────────────────────────────────────────────────────
function WorkspaceHeader({
  eyebrow, title, description, action, setLocation,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
  setLocation: (p: string) => void;
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

// ─── Rules View ───────────────────────────────────────────────────────────────
function RulesView({ setLocation }: { setLocation: (p: string) => void }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const counts = { CRITICAL: 4, HIGH: 17, MEDIUM: 10, LOW: 4 } as const;
  const filtered = ruleLibrary.filter(
    (r) =>
      (severity === "ALL" || r.severity === severity) &&
      [r.id, r.title, r.service].some((v) => v.toLowerCase().includes(query.toLowerCase()))
  );

  return (
    <>
      <WorkspaceHeader
        setLocation={setLocation}
        eyebrow={`EVIDENCE REGISTER / ${ruleLibrary.length} ACTIVE`}
        title="Security rules"
        description="A searchable register of the controls Vantage applies to every Terraform configuration."
        action={
          <button className="primary-cta compact" onClick={() => toast.success("Rule set synced", { description: `${ruleLibrary.length} active Vantage rules are current.` })}>
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
          {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((v) => (
            <button key={v} className={severity === v ? "selected" : ""} onClick={() => setSeverity(v)}>
              {v}<span>{v === "ALL" ? ruleLibrary.length : counts[v]}</span>
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
              <button onClick={() => toast("Rule details", { description: `${rule.id} \u00b7 ${rule.title}` })}>
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

// ─── Workspace Switcher ───────────────────────────────────────────────────────
function WorkspaceView({ view, setLocation }: { view: ViewName; setLocation: (p: string) => void }) {
  if (view === "Rule library") return <RulesView setLocation={setLocation} />;
  return null;
}

// ─── App Shell ────────────────────────────────────────────────────────────────
export default function Home() {
  const [location, setLocation] = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [scanState, setScanState] = useState<"idle" | "scanning" | "complete">("idle");
  const [scan, setScan] = useState<ScanPayload>(initialScan);
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("vantage-prod.tf");
  const view = routeToView[location] ?? "Overview";
  const navigate = (path: string) => { setLocation(path); setMobileNavOpen(false); };

  return (
    <div className="app-shell">
      <aside className={`command-rail ${mobileNavOpen ? "open" : ""}`}>
        <div className="rail-brand">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <div className="brand-lockup"><span>VANTAGE</span><small>cloud security</small></div>
          <button className="mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>
        <div className="rail-section-label">WORKBENCH</div>
        <nav className="rail-nav" aria-label="Primary navigation">
          {navItems.map(({ label, icon: Icon, path }) => (
            <button key={label} className={`rail-nav-item ${view === label ? "active" : ""}`} onClick={() => navigate(path)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {view === label && <span className="nav-pip" />}
            </button>
          ))}
        </nav>
        <div className="rail-spacer" />
        <div className="rail-section-label">SYSTEM</div>
        <nav className="rail-nav">
          {systemItems.map(({ label, icon: Icon, path }) => (
            <button key={label} className={`rail-nav-item ${view === label ? "active" : ""}`} onClick={() => navigate(path)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="rail-footer">
          <div className="operator-avatar">OP</div>
          <div><strong>Operator</strong><span>local session</span></div>
        </div>
      </aside>

      <main className="main-stage">
        <header className="topbar">
          <div className="crumb">
            <button className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
              <Menu size={18} />
            </button>
            <span className="crumb-brand">VANTAGE</span>
            <ChevronRight size={13} /><span>WORKBENCH</span>
            <ChevronRight size={13} /><strong>{view.toUpperCase()}</strong>
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
              scan={scan} setScan={setScan}
              scanState={scanState} setScanState={setScanState}
              fileName={fileName} setFileName={setFileName}
              file={file} setFile={setFile}
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
`;

fs.writeFileSync(target, tsx, 'utf-8');
const lines = tsx.split('\n').length;
console.log(`Written successfully. Lines: ${lines}, Bytes: ${Buffer.byteLength(tsx)}`);
