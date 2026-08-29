/* Signal / Infrared: neo-brutalist control-room dashboard, Vantage Volt signal hierarchy, asymmetric workbench, Space Grotesk + IBM Plex Mono. */
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
  CircleDot,
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
  TimerReset,
  UploadCloud,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

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
  security_score?: { score: number; grade: string; verdict: string };
};
type ViewName = "Overview" | "Rule library";

const initialScan: ScanPayload = {
  summary: { critical: 1, high: 1, medium: 0, passed: 15 },
  findings: [
    { rule_id: "AWS-001", severity: "CRITICAL", resource: "aws_s3_bucket.main", service: "S3 / storage", line: "infra/storage.tf:18", description: "S3 bucket allows public read access.", remediation: 'Change `acl = "public-read"` to `acl = "private"` and enforce Block Public Access.' },
    { rule_id: "AWS-002", severity: "HIGH", resource: "aws_security_group.web", service: "EC2 / network", line: "infra/network.tf:42", description: "Ingress rule exposes SSH to the entire internet.", remediation: 'Replace `cidr_blocks = ["0.0.0.0/0"]` with a trusted bastion CIDR or SSM Session Manager.' },
    { rule_id: "AWS-003", severity: "HIGH", resource: "aws_iam_policy.deploy", service: "IAM / identity", line: "infra/iam.tf:77", description: "Deployment policy grants wildcard actions on all resources.", remediation: "Scope actions and resources to the release pipeline's exact needs." },
  ],
};
const completedScan: ScanPayload = {
  summary: { critical: 0, high: 1, medium: 1, passed: 17 },
  findings: [
    { rule_id: "AWS-002", severity: "HIGH", resource: "aws_security_group.web", service: "EC2 / network", line: "infra/network.tf:42", description: "Ingress rule exposes SSH to the entire internet.", remediation: 'Replace `cidr_blocks = ["0.0.0.0/0"]` with a trusted bastion CIDR or SSM Session Manager.' },
    { rule_id: "AWS-003", severity: "HIGH", resource: "aws_iam_policy.deploy", service: "IAM / identity", line: "infra/iam.tf:77", description: "Deployment policy grants wildcard actions on all resources.", remediation: "Scope actions and resources to the release pipeline's exact needs." },
  ],
};
const navItems: { label: ViewName; icon: typeof Gauge; count?: string; path: string }[] = [{ label: "Overview", icon: Gauge, path: "/" }, { label: "Rule library", icon: Code2, path: "/rules" }];
const systemItems: { label: ViewName; icon: typeof Github; path: string }[] = [];
const routeToView: Record<string, ViewName> = {
  "/": "Overview", "/rules": "Rule library",
};

function severityClass(severity: Severity) { return { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", PASSED: "passed" }[severity]; }
function scanFindingsLabel(score: number) { return score >= 80 ? "02" : "03"; }
function StatusDot({ state = "live" }: { state?: "live" | "idle" | "warn" }) { return <span className={`status-dot ${state}`} aria-label={state} />; }

function ScoreRing({ score, scanning }: { score: number; scanning: boolean }) {
  const radius = 83;
  const circumference = 2 * Math.PI * radius;
  const dash = circumference * (score / 100);
  return <div className={`score-ring ${scanning ? "is-scanning" : ""}`}>
    <svg viewBox="0 0 220 220" aria-hidden="true">
      <circle className="score-track" cx="110" cy="110" r={radius} />
      <circle className="score-progress" cx="110" cy="110" r={radius} strokeDasharray={`${dash} ${circumference - dash}`} />
      <circle className="score-orbit" cx="110" cy="110" r="100" />
      <path className="score-tick" d="M110 8v10M110 202v10M8 110h10M202 110h10" />
    </svg>
    <div className="score-center"><span className="score-value">{score}</span><span className="score-caption">posture score</span></div>
    <div className="score-tag">{scanning ? "SCANNING" : score >= 80 ? "HARDENED" : "ACTION NEEDED"}</div>
    <div className="score-alert-count"><ShieldAlert size={12} /> {scanning ? "LIVE EVALUATION" : `${scanFindingsLabel(score)} OPEN RISK PATHS`}</div>
  </div>;
}

function DashboardView({ scan, setScan, scanState, setScanState, fileName, setFileName, file, setFile, setLocation }: { scan: ScanPayload; setScan: (scan: ScanPayload) => void; scanState: "idle" | "scanning" | "complete"; setScanState: (state: "idle" | "scanning" | "complete") => void; fileName: string; setFileName: (name: string) => void; file: File | null; setFile: (file: File | null) => void; setLocation: (path: string) => void }) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(scan.findings[0]?.rule_id ?? null);
  const [search, setSearch] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const score = useMemo(() => {
    if (scan.security_score) return scan.security_score.score;
    const { critical, high, medium, passed } = scan.summary;
    const total = critical + high + medium + passed;
    return total === 0 ? 100 : Math.round(((passed + medium * .65 + high * .35) / total) * 100);
  }, [scan]);
  const filteredFindings = useMemo(() => { const query = search.trim().toLowerCase(); if (!query) return scan.findings; return scan.findings.filter((finding) => [finding.rule_id, finding.resource, finding.description].some((value) => value?.toLowerCase().includes(query))); }, [scan.findings, search]);
  
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
      setScan({ summary: data.summary, findings: data.findings });
      setScanState("complete");
      setExpandedFinding(data.findings[0]?.rule_id ?? null);
      toast.success("Scan complete", { description: `${data.findings.length} actionable findings remain.` });
    } catch (error) {
      toast.error("Scan error", { description: String(error) });
      setScanState("idle");
    }
  };

  const handleFile = (f?: File) => { if (!f) return; setFile(f); setFileName(f.name); setScanState("idle"); setScan(initialScan); setExpandedFinding("AWS-001"); toast("Configuration loaded", { description: `${f.name} is ready for a local posture pass.` }); };

  return <>
    <section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-line" /> LIVE VERDICT / {fileName.toUpperCase()}</div><h1>{scan.summary.critical + scan.summary.high + scan.summary.medium} exposures<br /><span>need an owner.</span></h1><p className="intro-copy">Vantage analyzed the plan. Vantage found {scan.summary.critical + scan.summary.high + scan.summary.medium} security paths that need a decision before apply.</p></div><div className="intro-actions"><button className={`primary-cta ${scanState === "scanning" ? "scanning" : ""}`} onClick={startScan} disabled={scanState === "scanning"}>{scanState === "scanning" ? <><RefreshCw size={17} className="spin" /> SCANNING FILE</> : scanState === "complete" ? <><Check size={17} /> RE-RUN SCAN</> : <><Play size={17} fill="currentColor" /> RUN LOCAL SCAN</>}<span className="cta-shortcut">⌘ ↵</span></button><span className="last-scan"><span className="mini-pulse" /> LAST SCAN <strong>4 MIN AGO</strong></span></div></section>
    <section className="telemetry-banner" ><div className="telemetry-overlay" /><div className="telemetry-copy"><span className="mono signal-code">PLAN / LOCAL</span><strong>Plan evidence is ready.</strong><span>Local run · Vantage analysis attached · 0 queue latency</span></div><div className="telemetry-readout"><span>RULES EVALUATED</span><strong>{scan.summary.passed + scan.findings.length}<small> / 35</small></strong></div><div className="telemetry-readout"><span>LAST SYNC</span><strong>00:04<small> ago</small></strong></div><div className="telemetry-wave"><span /><span /><span /><span /><span /><span /><span /><span /><span /></div></section>
    <section className="hero-grid"><article className="panel score-panel"><div className="panel-head"><div><span className="panel-kicker"><Radar size={14} /> POSTURE INDEX</span><h2>Security posture</h2></div><button className="quiet-button" onClick={() => toast("Score methodology", { description: "Passes, weighted findings, asset criticality, and exposure context roll into this index." })}><MoreHorizontal size={17} /></button></div><div className="score-layout"><ScoreRing score={score} scanning={scanState === "scanning"} /><div className="score-context"><div className="context-status"><StatusDot state={scanState === "complete" ? "live" : "warn"} /><span>{scanState === "complete" ? "IMPROVING" : "EXPOSURE DETECTED"}</span></div><p>{scanState === "complete" ? "Critical exposure cleared. Two high-impact paths still need an owner." : "Public access and unrestricted ingress are the dominant risk paths in this workspace."}</p><div className="metric-split"><div><strong>{scan.summary.passed}</strong><span>checks passed</span></div><div><strong>{scan.summary.critical + scan.summary.high + scan.summary.medium}</strong><span>open findings</span></div></div></div></div><div className="score-footer"><span className="mono">SOURCE / LOCAL RUN</span></div></article>
      <article className="panel upload-panel" ><div className="upload-tint" /><div className="panel-head on-dark"><div><span className="panel-kicker"><UploadCloud size={14} /> MANUAL SOURCE SCAN</span><h2>Scan a local config.</h2></div><span className="secure-label"><LockKeyhole size={12} /> LOCAL PASS</span></div><label className="dropzone" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); handleFile(event.dataTransfer.files?.[0]); }}><input ref={fileInput} type="file" accept=".tf,.zip,.tar,.gz" onChange={(event) => handleFile(event.target.files?.[0])} /><div className="drop-icon"><FileUp size={22} /></div><div><strong>{fileName}</strong><span>Terraform · 18.4 KB · ready to inspect</span></div><span className="drop-action">CHANGE <ChevronDown size={14} /></span></label><div className="upload-footer"><span><ShieldCheck size={14} /> Files are analyzed by the local API</span><button onClick={() => fileInput.current?.click()}>BROWSE FILES <ArrowUpRight size={14} /></button></div><div className="source-mode-note"><span className="mono">MANUAL PATH</span><span>Local file analysis mode.</span></div></article></section>
    <section className="insight-grid"><article className="panel findings-panel"><div className="panel-head findings-head"><div><span className="panel-kicker"><ShieldAlert size={14} /> FINDINGS / {String(filteredFindings.length).padStart(2, "0")}</span><h2>Action required</h2></div><div className="findings-tools"><div className="search-field"><Search size={14} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter findings" aria-label="Filter findings" /></div><button className="filter-button" onClick={() => toast("Filters are clear", { description: "Showing critical, high, and medium findings." })}><SlidersHorizontal size={15} /> FILTER</button></div></div><div className="severity-strip"><div><span className="sev-dot critical-bg" /> CRITICAL <strong>{scan.summary.critical}</strong></div><div><span className="sev-dot high-bg" /> HIGH <strong>{scan.summary.high}</strong></div><div><span className="sev-dot medium-bg" /> MEDIUM <strong>{scan.summary.medium}</strong></div><div className="severity-spacer" /><span className="mono finding-count">{scan.summary.passed} passed / 35 rules</span></div><div className="finding-list">{filteredFindings.length ? filteredFindings.map((finding) => { const open = expandedFinding === finding.rule_id; return <div key={finding.rule_id} className={`finding-row ${open ? "open" : ""}`}><button className="finding-summary" onClick={() => setExpandedFinding(open ? null : finding.rule_id)} aria-expanded={open}><span className={`severity-badge ${severityClass(finding.severity)}`}>{finding.severity}</span><span className="rule-id mono">{finding.rule_id}</span><span className="finding-resource">{finding.resource}</span><span className="finding-service">{finding.service}</span><ChevronDown className={`finding-chevron ${open ? "rotate" : ""}`} size={16} /></button>{open && <div className="finding-detail"><div className="detail-alert"><AlertOctagon size={17} /><span>{finding.description}</span></div><div className="detail-meta"><span><TerminalSquare size={13} /> {finding.line}</span><span><Fingerprint size={13} /> rule engine / terraform</span></div><div className="remediation"><span className="mono">REMEDIATION</span><p>{finding.remediation}</p><button onClick={async () => {
      const parts = finding.resource.split(".");
      if (parts.length !== 2) {
        toast.error("Invalid resource format", { description: finding.resource });
        return;
      }
      toast.loading("Generating secure code...", { id: "ai-fix-" + finding.rule_id });
      try {
        const response = await fetch("/api/ai-fix", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ resource_type: parts[0], resource_name: parts[1], vulnerability_description: finding.description })
        });
        if (!response.ok) {
          const err = await response.json().catch(() => ({}));
          throw new Error(err.detail || "AI Fix failed");
        }
        const data = await response.json();
        await navigator.clipboard.writeText(data.fixed_code);
        toast.success("Secure code copied to clipboard", { id: "ai-fix-" + finding.rule_id });
      } catch (e) {
        toast.error(String(e), { id: "ai-fix-" + finding.rule_id });
      }
    }}>AUTO-FIX (AI) <Sparkles size={14} /></button></div></div>}</div>; }) : <div className="empty-findings"><CheckCircle2 size={20} /><span>No findings match “{search}”.</span><button onClick={() => setSearch("")}>CLEAR FILTER</button></div>}</div><button className="view-all-button" onClick={() => setLocation("/rules")}>VIEW ALL ACTIVE RULES <ArrowUpRight size={14} /></button></article>
      <article className="panel topology-panel"><div className="topology-tint" /><div className="panel-head on-dark"><div><span className="panel-kicker"><Cloud size={14} /> RESOURCE MAP</span><h2>Attack surface</h2></div><span className="map-live"><StatusDot /> LIVE</span></div><div className="topology-center"><div className="topology-orbit orbit-one" /><div className="topology-orbit orbit-two" /><div className="topology-core"><ShieldCheck size={24} /><span>VANTAGE</span></div><span className="topology-node node-one">S3 <b>01</b></span><span className="topology-node node-two">IAM <b>07</b></span><span className="topology-node node-three">VPC <b>03</b></span><span className="topology-node node-four">EC2 <b>12</b></span></div><div className="topology-stats"><div><span>RESOURCES</span><strong>23</strong></div><div><span>PROTECTED</span><strong className="volt">20</strong></div><div><span>EXPOSED</span><strong className="coral">03</strong></div></div><button className="topology-link" onClick={() => setLocation("/assets")}>OPEN ASSET MAP <ArrowUpRight size={14} /></button></article></section>
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
  </>;
}

type Rule = {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  service: string;
  coverage: string;
  status: string;
  description: string;
};

function WorkspaceHeader({ eyebrow, title, description, action, setLocation }: { eyebrow: string; title: string; description: string; action?: React.ReactNode; setLocation: (path: string) => void }) {
  return <section className="workspace-header"><div><div className="eyebrow"><span className="eyebrow-line" /> {eyebrow}</div><h1>{title}</h1><p className="intro-copy">{description}</p></div><div className="workspace-header-actions"><button className="back-button" onClick={() => setLocation("/")}><ArrowLeft size={15} /> OVERVIEW</button>{action}</div></section>;
}

const ruleLibrary: Rule[] = [
  { id: "AWS-001", severity: "CRITICAL", title: "S3 Bucket: Public ACL",                           service: "aws_s3_bucket",                     coverage: "security", status: "ACTIVE", description: "S3 bucket allows public read access via ACL." },
  { id: "AWS-002", severity: "CRITICAL", title: "Security Group: Open SSH to the World",            service: "aws_security_group",                coverage: "security", status: "ACTIVE", description: "Security group allows unrestricted inbound SSH from 0.0.0.0/0." },
  { id: "AWS-003", severity: "HIGH",     title: "aws_iam_policy: IAM Policy Wildcard Permissions",    service: "aws_iam_policy",                  coverage: "security", status: "ACTIVE", description: "IAM policy grants Action:* on Resource:* — full admin access." },
  { id: "AWS-004", severity: "HIGH",     title: "aws_db_instance: RDS Unencrypted Storage",           service: "aws_db_instance",                 coverage: "security", status: "ACTIVE", description: "RDS instance does not have storage_encrypted enabled." },
  { id: "AWS-005", severity: "MEDIUM",   title: "aws_s3_bucket_versioning: S3 Versioning Disabled",   service: "aws_s3_bucket_versioning",        coverage: "security", status: "ACTIVE", description: "S3 versioning is Suspended or missing, preventing object recovery." },
  { id: "AWS-016", severity: "HIGH",     title: "aws_efs_file_system: EFS Unencrypted",               service: "aws_efs_file_system",             coverage: "security", status: "ACTIVE", description: "EFS file system is not encrypted at rest." },
  { id: "AWS-017", severity: "HIGH",     title: "aws_elasticache_replication_group: ElastiCache Transit Encryption Disabled", service: "aws_elasticache_replication_group", coverage: "security", status: "ACTIVE", description: "ElastiCache transit encryption is disabled." },
  { id: "AWS-018", severity: "HIGH",     title: "aws_elasticache_replication_group: ElastiCache At-Rest Encryption Disabled", service: "aws_elasticache_replication_group", coverage: "security", status: "ACTIVE", description: "ElastiCache at-rest encryption is disabled." },
  { id: "AWS-019", severity: "MEDIUM",   title: "aws_cloudfront_distribution: CloudFront Allows HTTP", service: "aws_cloudfront_distribution",    coverage: "security", status: "ACTIVE", description: "CloudFront allows unencrypted HTTP traffic (allow-all)." },
  { id: "AWS-020", severity: "HIGH",     title: "aws_sagemaker_notebook_instance: SageMaker Root Access", service: "aws_sagemaker_notebook_instance", coverage: "security", status: "ACTIVE", description: "SageMaker notebook has root access enabled." },
  { id: "AWS-021", severity: "HIGH",     title: "aws_docdb_cluster: DocumentDB Unencrypted",          service: "aws_docdb_cluster",               coverage: "security", status: "ACTIVE", description: "DocumentDB cluster is not encrypted." },
  { id: "AWS-022", severity: "HIGH",     title: "aws_dax_cluster: DAX Unencrypted",                   service: "aws_dax_cluster",                 coverage: "security", status: "ACTIVE", description: "DAX cluster is not encrypted at rest." },
  { id: "AWS-023", severity: "HIGH",     title: "aws_kinesis_stream: Kinesis Stream Unencrypted",     service: "aws_kinesis_stream",              coverage: "security", status: "ACTIVE", description: "Kinesis stream has no encryption type set." },
  { id: "AWS-024", severity: "CRITICAL", title: "aws_redshift_cluster: Redshift Publicly Accessible", service: "aws_redshift_cluster",            coverage: "security", status: "ACTIVE", description: "Redshift cluster is exposed to the public internet." },
  { id: "AWS-025", severity: "HIGH",     title: "aws_redshift_cluster: Redshift Unencrypted",         service: "aws_redshift_cluster",            coverage: "security", status: "ACTIVE", description: "Redshift cluster is not encrypted." },
  { id: "AWS-026", severity: "CRITICAL", title: "aws_eks_cluster: EKS Public Endpoint",               service: "aws_eks_cluster",                 coverage: "security", status: "ACTIVE", description: "EKS cluster API server endpoint is publicly accessible." },
  { id: "AWS-027", severity: "HIGH",     title: "aws_emr_security_configuration: EMR Unencrypted",    service: "aws_emr_security_configuration",  coverage: "security", status: "ACTIVE", description: "EMR cluster does not enforce at-rest encryption." },
  { id: "AWS-028", severity: "HIGH",     title: "aws_mq_broker: Amazon MQ Publicly Accessible",       service: "aws_mq_broker",                   coverage: "security", status: "ACTIVE", description: "Amazon MQ broker is publicly accessible." },
  { id: "AWS-029", severity: "HIGH",     title: "aws_neptune_cluster: Neptune Unencrypted",           service: "aws_neptune_cluster",             coverage: "security", status: "ACTIVE", description: "Neptune graph database is not encrypted." },
  { id: "AWS-030", severity: "MEDIUM",   title: "aws_workspaces_workspace: WorkSpaces Root Volume Unencrypted", service: "aws_workspaces_workspace", coverage: "security", status: "ACTIVE", description: "WorkSpaces root volume is not encrypted." },
  { id: "AWS-031", severity: "MEDIUM",   title: "aws_athena_workgroup: Athena Query Encryption Not Enforced", service: "aws_athena_workgroup",   coverage: "security", status: "ACTIVE", description: "Athena workgroup does not enforce query result encryption." },
  { id: "AWS-032", severity: "MEDIUM",   title: "aws_sns_topic: SNS Topic Unencrypted",               service: "aws_sns_topic",                   coverage: "security", status: "ACTIVE", description: "SNS topic is not encrypted with a KMS key." },
  { id: "AWS-033", severity: "MEDIUM",   title: "aws_ecs_task_definition: ECS No Transit Encryption", service: "aws_ecs_task_definition",         coverage: "security", status: "ACTIVE", description: "ECS task definition lacks transit encryption." },
  { id: "AWS-034", severity: "MEDIUM",   title: "aws_codebuild_project: CodeBuild Missing Encryption Key", service: "aws_codebuild_project",     coverage: "security", status: "ACTIVE", description: "CodeBuild project is missing an encryption key." },
  { id: "AWS-035", severity: "LOW",      title: "aws_appsync_graphql_api: AppSync WAF Disabled",      service: "aws_appsync_graphql_api",         coverage: "security", status: "ACTIVE", description: "AppSync GraphQL API does not have a WAF web ACL attached." },
  { id: "AWS-036", severity: "LOW",      title: "aws_api_gateway_stage: API Gateway WAF Disabled",    service: "aws_api_gateway_stage",           coverage: "security", status: "ACTIVE", description: "API Gateway stage does not have a WAF web ACL attached." },
  { id: "AWS-037", severity: "LOW",      title: "aws_lambda_function: Lambda X-Ray Tracing Disabled", service: "aws_lambda_function",             coverage: "security", status: "ACTIVE", description: "Lambda function does not have X-Ray tracing enabled." },
  { id: "AWS-038", severity: "MEDIUM",   title: "aws_vpc: VPC Flow Logs Disabled",                    service: "aws_vpc",                         coverage: "security", status: "ACTIVE", description: "VPC does not have Flow Logs enabled." },
  { id: "AWS-039", severity: "MEDIUM",   title: "aws_iam_account_password_policy: IAM Password Reuse Allowed", service: "aws_iam_account_password_policy", coverage: "security", status: "ACTIVE", description: "IAM password policy allows immediate password reuse." },
];

function RulesView({ setLocation }: { setLocation: (path: string) => void }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("ALL");
  const counts = { CRITICAL: 4, HIGH: 17, MEDIUM: 10, LOW: 4 };
  const rules = ruleLibrary.filter(
    (rule) =>
      (severity === "ALL" || rule.severity === severity) &&
      [rule.id, rule.title, rule.service].some((v) => v.toLowerCase().includes(query.toLowerCase()))
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
              {v}
              <span>{v === "ALL" ? ruleLibrary.length : counts[v] ?? 0}</span>
            </button>
          ))}
        </div>
      </section>
      <section className="rule-grid">
        {rules.map((rule) => (
          <article className="rule-card" key={rule.id}>
            <div className="rule-card-top">
              <span className={`severity-badge ${severityClass(rule.severity as Severity)}`}>{rule.severity}</span>
              <span className="mono rule-card-id">{rule.id}</span>
              <span className="rule-active"><StatusDot /> {rule.status}</span>
            </div>
            <h2>{rule.title.split(": ").slice(1).join(": ") || rule.title}</h2>
            <p>{rule.description}</p>
            <div className="rule-card-footer">
              <span><Code2 size={13} /> {rule.service}</span>
              <span className="mono">/{rule.coverage}</span>
              <button onClick={() => toast("Rule details", { description: `${rule.id} · ${rule.title}` })}>INSPECT <ArrowUpRight size={13} /></button>
            </div>
          </article>
        ))}
      </section>
      {rules.length === 0 && (
        <div className="workspace-empty">
          <Search size={20} />
          <strong>No rules match this filter.</strong>
          <button onClick={() => { setQuery(""); setSeverity("ALL"); }}>RESET LIBRARY</button>
        </div>
      )}
    </>
  );
}

function WorkspaceView({ view, setLocation }: { view: ViewName; setLocation: (path: string) => void }) {
  if (view === "Rule library") return <RulesView setLocation={setLocation} />;
  return null;
}

export default function Home() {
  const [location, setLocation] = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [scanState, setScanState] = useState<"idle" | "scanning" | "complete">("idle");
  const [scan, setScan] = useState<ScanPayload>(initialScan);
  const [file, setFile] = useState<File | null>(null);
  const [fileName, setFileName] = useState("vantage-prod.tf");
  const view = routeToView[location] ?? "Overview";
  const navigate = (path: string) => { setLocation(path); setMobileNavOpen(false); };

  return <div className="app-shell"><aside className={`command-rail ${mobileNavOpen ? "open" : ""}`}><div className="rail-brand"><div className="brand-mark"><ShieldCheck size={22} /></div><div className="brand-lockup"><span>VANTAGE</span><small>cloud security</small></div><button className="mobile-close" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={18} /></button></div><div className="rail-section-label">WORKBENCH</div><nav className="rail-nav" aria-label="Primary navigation">{navItems.map(({ label, icon: Icon, path }) => <button key={label} className={`rail-nav-item ${view === label ? "active" : ""}`} onClick={() => navigate(path)}><Icon size={17} strokeWidth={1.8} /><span>{label}</span>{view === label && <span className="nav-pip" />}</button>)}</nav><div className="rail-spacer" /><div className="rail-section-label">SYSTEM</div><nav className="rail-nav">{systemItems.map(({ label, icon: Icon, path }) => <button key={label} className={`rail-nav-item ${view === label ? "active" : ""}`} onClick={() => navigate(path)}><Icon size={17} strokeWidth={1.8} /><span>{label}</span></button>)}</nav><div className="rail-footer"><div className="operator-avatar">OP</div><div><strong>Operator</strong><span>local session</span></div></div></aside><main className="main-stage"><header className="topbar"><div className="crumb"><button className="mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={18} /></button><span className="crumb-brand">VANTAGE</span><ChevronRight size={13} /><span>WORKBENCH</span><ChevronRight size={13} /><strong>{view.toUpperCase()}</strong></div><div className="topbar-tools"><span className="environment-chip"><StatusDot /> LOCAL ENV</span><span className="topbar-time"><Activity size={14} /> LIVE TELEMETRY <span className="mono">{new Date().toLocaleTimeString()}</span></span></div></header><div className="content-wrap">{view === "Overview" ? <DashboardView scan={scan} setScan={setScan} scanState={scanState} setScanState={setScanState} fileName={fileName} setFileName={setFileName} file={file} setFile={setFile} setLocation={setLocation} /> : <WorkspaceView view={view} setLocation={setLocation} />}</div></main></div>;
}
