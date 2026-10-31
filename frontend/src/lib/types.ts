export type Entities = { users?: string[]; hosts?: string[]; external_ips?: string[]; [k: string]: string[] | undefined };

export interface IncidentRow {
  id: number; title: string; score: number; first_seen: string; last_seen: string; tactics: string[];
  merged_alert_count?: number; signal_count?: number; host_path_text?: string; users?: string[]; hosts?: string[];
  fingerprint?: string; entities?: Entities; technique_ids?: string[]; status?: CaseStatus;
}

export interface TimelineStep {
  step: number; signal_id?: string; ts: string; ts_last?: string; title: string; technique?: string; technique_name?: string;
  technique_ids?: string[]; tactic?: string; kill_chain_stage?: string; severity?: number | string; mapping_reason?: string;
  host?: string; user?: string; src_ip?: string; dst_ip?: string; dst_host?: string; dst_domain?: string;
  event_count?: number; event_ids?: string[]; rule_ids?: string[]; rule_sources?: string[]; vendor_corroborated?: boolean;
}

export interface GraphNode { id: string; label?: string; type?: string; role?: string; suspected?: boolean; steps?: number[] }
export interface GraphEdge {
  id?: string; source: string; target: string; kind: string; steps?: number[]; techniques?: string[]; event_ids?: string[];
  evidence_kind?: string; first_seen?: string; last_seen?: string; relation?: string; cost?: number; derived_via?: string;
}
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface Reachable {
  asset: string; confidence: 'high' | 'medium' | 'low'; relation: string; via: string; hops: number; criticality: number;
  interpretation?: string; evidence?: { event_ids?: string[]; sample_event_id?: string };
}

export interface ForecastSequence { techniques: string[]; model_path_score: number }
export interface Forecast {
  status: string; reason?: string | null; method?: string; training_until?: string;
  candidates?: { technique: string; count?: number; historical_share?: number }[]; sequences?: ForecastSequence[];
  interpretation?: string; evaluation_warnings?: string[];
}

export type CaseStatus = 'new' | 'investigating' | 'contained' | 'closed';
export interface CaseInfo { status: CaseStatus; version: number; history: { ts: string; status: string; note: string }[] }

export interface Incident extends IncidentRow {
  score_interpretation?: string; kill_chain_progression?: number;
  raw_event_count?: number; host_path?: string[]; timeline: TimelineStep[]; graph: Graph; narrative: string;
  lookahead: { status: string; reachable: Reachable[]; assumptions?: string[]; total_candidates?: number };
  forecast?: Forecast; correlation_links?: Record<string, unknown>[]; case: CaseInfo;
  related_incidents?: { source: number; target: number; score: number; [k: string]: unknown }[];
}

export interface Metrics {
  version?: string; input_quality?: string; attack_mapping_version?: string;
  ingest?: Record<string, unknown>;
  rules?: { loaded?: number; covered_techniques?: string[]; community?: Record<string, unknown>; ruleset_hash?: string };
  detect?: { detections_by_source?: Record<string, number>; detections_by_rule?: Record<string, number>; base_rules_evaluated?: number; base_rules_loaded?: number };
  signals?: Record<string, number>; output?: Record<string, number>; correlate?: Record<string, unknown>;
  timings?: Record<string, number>; peak_process_tree_rss_gb?: number; machine?: Record<string, unknown>; label?: Record<string, unknown>;
}

export interface Health { status: string; incidents: number; graph_backend: string; graph_algorithms: string[] }
export interface AIStatus { enabled: boolean; model: string; requests_today: number; daily_request_limit: number; tasks: string[] }
export interface Progress { state: string; stage: string; completed_bytes?: number; source_bytes?: number; chunks?: number; error?: string; timings?: Record<string, number> }

export interface PathResult {
  status: 'found' | 'not_found'; algorithm: string; nodes?: string[]; edge_ids?: string[]; hops?: number;
  total_cost?: number; arrival_ms?: number; interpretation?: string; reason?: string;
}

export interface TriageResult {
  status: string; context_hash: string; fingerprint: string; report_draft: string; errors: string[];
  verdict: { assessment: string; priority: string; severity: string; rationale: string; citations: string[];
    contradictory_evidence: string[]; missing_evidence: string[]; next_checks: string[] };
  [k: string]: unknown;
}
