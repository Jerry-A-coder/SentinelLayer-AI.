/**
 * SentinelLayer AI — Core Security & Multi-Agent Types
 */

export type AttackCategory =
  | 'Instruction Override'
  | 'Role Change'
  | 'Secret Extraction'
  | 'Tool Abuse'
  | 'Credential Theft'
  | 'Context Poisoning'
  | 'Multistep Jailbreaks'
  | 'Encoded Instructions'
  | 'Indirect Prompt Injection'
  | 'Benign / Clean';

export type PolicyOutcome =
  | 'ALLOW'
  | 'SANITISE'
  | 'QUARANTINE'
  | 'BLOCK'
  | 'REQUIRE_REVIEW';

export type ReviewStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'NONE';

export interface ProposedToolCall {
  toolName: string;
  arguments: Record<string, string>;
  destination?: string;
  requestedScope?: string;
}

export interface DetectionFinding {
  id: string;
  category: AttackCategory;
  evidence: string;
  sourceLocation: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  uncertainty: 'LOW_UNCERTAINTY' | 'MODERATE_UNCERTAINTY' | 'HIGH_UNCERTAINTY';
  detectionMethod: 'DETERMINISTIC_RULE' | 'GEMINI_CONTEXTUAL' | 'DECODED_INSPECTION' | 'TOOL_FIREWALL';
  recommendedHandling: PolicyOutcome;
  policyRuleId: string;
  isQuotedOrBenignDiscussion: boolean;
  explanation: string;
}

export interface AgentFindingOutput {
  agentId: 'AGENT_1_INJECTION' | 'AGENT_2_CONTEXT' | 'AGENT_3_LEAKAGE' | 'AGENT_4_TOOL_ABUSE' | 'AGENT_5_CROSS_SOURCE';
  agentName: string;
  status: 'COMPLETED' | 'FALLBACK_DETERMINISTIC' | 'UNAVAILABLE';
  primaryAssessment: string;
  detectedCategories: AttackCategory[];
  evidenceSnippets: string[];
  recommendedAction: PolicyOutcome;
  uncertaintyNote: string;
  latencyMs: number;
}

export interface RagCitation {
  docId: string;
  title: string;
  section: string;
  passage: string;
  relevanceNote: string;
}

export interface ToolFirewallDecision {
  toolName: string;
  allowed: boolean;
  reason: string;
  policyRuleId: string;
  checkedScope: string;
  checkedDestination: string;
}

export interface AutomatedVendorRemediation {
  remediationId: string;
  triggered: boolean;
  flaggedForVendorReview: boolean;
  vendorTeamTarget: string;
  notificationStatus: 'DISPATCHED' | 'STANDBY';
  dispatchChannel: 'VENDOR_PSIRT_WEBHOOK_AND_EMAIL';
  severityLevel: 'CRITICAL' | 'HIGH';
  summaryMessage: string;
  dispatchedAt: string;
}

export interface ScanAnalysisResponse {
  scanId: string;
  sourceName: string;
  sourceType: 'Plain Text' | 'Markdown' | 'HTML' | 'PDF Extract' | 'Email' | 'API Response' | 'Image OCR' | 'Google Chat' | 'Scientific Abstract';
  rawLength: number;
  normalisedPreview: string;
  sanitisedContent: string;
  modificationsLog: string[];
  riskScore: number;
  riskFactors: { factor: string; points: number; detail: string }[];
  outcome: PolicyOutcome;
  primaryCategory: AttackCategory;
  findings: DetectionFinding[];
  agentOutputs: AgentFindingOutput[];
  agentDisagreements: string[];
  toolFirewallDecision?: ToolFirewallDecision;
  automatedRemediation?: AutomatedVendorRemediation;
  ragCitations: RagCitation[];
  aiMode: 'FULL_AI_ORCHESTRATION' | 'DETERMINISTIC_FALLBACK_ONLY';
  fallbackNotice?: string;
  policyVersion: string;
  reviewStatus: ReviewStatus;
  latencyMs: number;
  timestamp: string;
}

export interface SecurityPolicyProfile {
  policyId: string;
  ownerId: string;
  name: string;
  version: string;
  blockThreshold: number;
  quarantineThreshold: number;
  sanitiseThreshold: number;
  failClosedOnAiOffline: boolean;
  enforceStrictToolAllowlist: boolean;
  automatedRemediationEnabled?: boolean;
  vendorNotificationTarget?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface AdversarialTestCase {
  id: string;
  title: string;
  sourceType: ScanAnalysisResponse['sourceType'];
  expectedCategory: AttackCategory;
  expectedMalicious: boolean;
  expectedOutcome: PolicyOutcome;
  content: string;
  proposedToolCall?: ProposedToolCall;
  priorContextMessages?: string[];
}

export interface EvaluationRunSummary {
  runId: string;
  timestamp: string;
  aiModeUsed: string;
  totalCases: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  toolEnforcementSuccessRate: number;
  averageLatencyMs: number;
  results: {
    caseId: string;
    title: string;
    expectedCategory: AttackCategory;
    actualCategory: AttackCategory;
    expectedMalicious: boolean;
    actualMalicious: boolean;
    expectedOutcome: PolicyOutcome;
    actualOutcome: PolicyOutcome;
    passed: boolean;
    latencyMs: number;
  }[];
}
