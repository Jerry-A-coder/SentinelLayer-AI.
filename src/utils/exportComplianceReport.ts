import { ScanAnalysisResponse, SecurityPolicyProfile } from '../types/sentinel.ts';

/**
 * Escapes a value for RFC 4180 CSV compliance.
 */
function escapeCsvField(val: unknown): string {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/\r?\n/g, ' ').trim();
  const escaped = str.replace(/"/g, '""');
  return `"${escaped}"`;
}

/**
 * Triggers a browser file download from string content.
 */
function triggerBrowserDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * Exports the current scan analysis as a structured, offline-verifiable JSON compliance report.
 */
export function exportScanReportAsJson(
  scan: ScanAnalysisResponse,
  policy: SecurityPolicyProfile,
  actorRole: string
) {
  const reportPayload = {
    reportMetadata: {
      generator: 'SentinelLayer AI — Multimodal Agentic Prompt Injection Firewall',
      schemaVersion: '1.0.0-COMPLIANCE',
      exportedAt: new Date().toISOString(),
      exportedByRole: actorRole,
      policyProfile: {
        policyId: policy.policyId,
        name: policy.name,
        version: policy.version,
        thresholds: {
          blockThreshold: policy.blockThreshold,
          quarantineThreshold: policy.quarantineThreshold,
          sanitiseThreshold: policy.sanitiseThreshold,
        },
        failClosedOnAiOffline: policy.failClosedOnAiOffline,
        enforceStrictToolAllowlist: policy.enforceStrictToolAllowlist,
        automatedRemediationEnabled: Boolean(policy.automatedRemediationEnabled ?? true),
        vendorNotificationTarget:
          policy.vendorNotificationTarget || 'psirt-alerts@external-vendor-sec.io',
      },
    },
    scanSummary: {
      scanId: scan.scanId,
      timestamp: scan.timestamp,
      sourceName: scan.sourceName,
      sourceType: scan.sourceType,
      rawLengthChars: scan.rawLength,
      latencyMs: scan.latencyMs,
      aiMode: scan.aiMode,
      fallbackNotice: scan.fallbackNotice || null,
      policyVersion: scan.policyVersion,
      reviewStatus: scan.reviewStatus,
      finalDecisionOutcome: scan.outcome,
      primaryAttackCategory: scan.primaryCategory,
      documentedRiskScore: scan.riskScore,
    },
    riskScoreDecomposition: scan.riskFactors,
    toolExecutionFirewall: scan.toolFirewallDecision || {
      status: 'NO_TOOL_CALL_PROPOSED',
    },
    automatedVendorRemediation: scan.automatedRemediation || {
      status: 'DISABLED_IN_POLICY',
    },
    findings: scan.findings,
    multiAgentAnalysis: {
      agents: scan.agentOutputs,
      recordedDisagreements: scan.agentDisagreements,
    },
    sanitisationAudit: {
      modificationsCount: scan.modificationsLog.length,
      modificationsLog: scan.modificationsLog,
      normalisedInputPreview: scan.normalisedPreview,
      verifiedSanitisedOutput:
        scan.outcome === 'BLOCK'
          ? '[PAYLOAD BLOCKED BY SENTINELLAYER POLICY ENGINE]'
          : scan.sanitisedContent,
    },
    ragSecurityCitations: scan.ragCitations,
  };

  const jsonString = JSON.stringify(reportPayload, null, 2);
  const safeId = scan.scanId.replace(/[^a-zA-Z0-9_-]/g, '_');
  triggerBrowserDownload(
    jsonString,
    `SentinelLayer_Compliance_Report_${safeId}.json`,
    'application/json;charset=utf-8'
  );
}

/**
 * Exports the current scan analysis as a structured, multi-section CSV compliance report
 * suitable for spreadsheet auditing and GRC archival.
 */
export function exportScanReportAsCsv(
  scan: ScanAnalysisResponse,
  policy: SecurityPolicyProfile,
  actorRole: string
) {
  const lines: string[] = [];

  // Section 1: Executive Scan Summary
  lines.push(
    [
      'Section',
      'Scan ID',
      'Timestamp',
      'Exported By Role',
      'Source Name',
      'Source Type',
      'Policy Version',
      'AI Mode',
      'Risk Score (0-100)',
      'Final Policy Outcome',
      'Primary Category',
      'Review Status',
      'Latency (ms)',
    ]
      .map(escapeCsvField)
      .join(',')
  );

  lines.push(
    [
      'SCAN_SUMMARY',
      scan.scanId,
      scan.timestamp,
      actorRole,
      scan.sourceName,
      scan.sourceType,
      `${policy.name} (${scan.policyVersion})`,
      scan.aiMode,
      scan.riskScore,
      scan.outcome,
      scan.primaryCategory,
      scan.reviewStatus,
      scan.latencyMs,
    ]
      .map(escapeCsvField)
      .join(',')
  );

  lines.push('');

  // Section 2: Risk Score Contributor Weights
  lines.push(
    ['Section', 'Scan ID', 'Contributor Factor', 'Weight Points', 'Explanation Detail']
      .map(escapeCsvField)
      .join(',')
  );
  if (scan.riskFactors.length === 0) {
    lines.push(
      ['RISK_FACTOR', scan.scanId, 'Clean Baseline', 0, 'Zero malicious signals or policy violations detected']
        .map(escapeCsvField)
        .join(',')
    );
  } else {
    for (const rf of scan.riskFactors) {
      lines.push(
        ['RISK_FACTOR', scan.scanId, rf.factor, rf.points, rf.detail]
          .map(escapeCsvField)
          .join(',')
      );
    }
  }

  lines.push('');

  // Section 3: Detection Findings
  lines.push(
    [
      'Section',
      'Finding ID',
      'Category',
      'Severity',
      'Detection Method',
      'Recommended Handling',
      'Policy Rule ID',
      'Quoted/Benign Context',
      'Source Location',
      'Evidence Snippet',
      'Explanation',
    ]
      .map(escapeCsvField)
      .join(',')
  );
  if (scan.findings.length === 0) {
    lines.push(
      [
        'FINDING',
        'NONE',
        'Benign / Clean',
        'LOW',
        'DETERMINISTIC_RULE',
        'ALLOW',
        'POL-CORE-001',
        'false',
        'Primary Content Body',
        'No suspicious patterns matched',
        'Content passed all nine prompt injection category checks.',
      ]
        .map(escapeCsvField)
        .join(',')
    );
  } else {
    for (const f of scan.findings) {
      lines.push(
        [
          'FINDING',
          f.id,
          f.category,
          f.severity,
          f.detectionMethod,
          f.recommendedHandling,
          f.policyRuleId,
          f.isQuotedOrBenignDiscussion,
          f.sourceLocation,
          f.evidence,
          f.explanation,
        ]
          .map(escapeCsvField)
          .join(',')
      );
    }
  }

  lines.push('');

  // Section 4: Five-Agent Specialized Assessment
  lines.push(
    [
      'Section',
      'Agent ID',
      'Agent Name',
      'Status',
      'Recommended Action',
      'Detected Categories',
      'Latency (ms)',
      'Primary Assessment',
      'Uncertainty Note',
    ]
      .map(escapeCsvField)
      .join(',')
  );
  for (const ag of scan.agentOutputs) {
    lines.push(
      [
        'AGENT_ASSESSMENT',
        ag.agentId,
        ag.agentName,
        ag.status,
        ag.recommendedAction,
        ag.detectedCategories.join('; '),
        ag.latencyMs,
        ag.primaryAssessment,
        ag.uncertaintyNote,
      ]
        .map(escapeCsvField)
        .join(',')
    );
  }

  lines.push('');

  // Section 5: Tool Execution Firewall Verdict
  lines.push(
    ['Section', 'Tool Name', 'Allowed', 'Policy Rule ID', 'Checked Scope', 'Checked Destination', 'Decision Reason']
      .map(escapeCsvField)
      .join(',')
  );
  if (scan.toolFirewallDecision) {
    const td = scan.toolFirewallDecision;
    lines.push(
      [
        'TOOL_FIREWALL',
        td.toolName,
        td.allowed ? 'ALLOWED' : 'BLOCKED',
        td.policyRuleId,
        td.checkedScope,
        td.checkedDestination,
        td.reason,
      ]
        .map(escapeCsvField)
        .join(',')
    );
  } else {
    lines.push(
      ['TOOL_FIREWALL', 'NONE', 'N/A', 'POL-TOOL-004', 'N/A', 'N/A', 'No downstream tool call proposed during scan.']
        .map(escapeCsvField)
        .join(',')
    );
  }

  lines.push('');

  // Section 6: Automated Vendor Remediation & PSIRT Notification
  lines.push(
    [
      'Section',
      'Remediation ID',
      'Triggered',
      'Notification Status',
      'Vendor Security Target',
      'Severity Level',
      'Summary Message',
    ]
      .map(escapeCsvField)
      .join(',')
  );
  if (scan.automatedRemediation) {
    const ar = scan.automatedRemediation;
    lines.push(
      [
        'AUTOMATED_REMEDIATION',
        ar.remediationId,
        ar.triggered ? 'YES' : 'NO',
        ar.notificationStatus,
        ar.vendorTeamTarget,
        ar.severityLevel,
        ar.summaryMessage,
      ]
        .map(escapeCsvField)
        .join(',')
    );
  } else {
    lines.push(
      [
        'AUTOMATED_REMEDIATION',
        'NONE',
        'NO',
        'DISABLED',
        policy.vendorNotificationTarget || 'N/A',
        'N/A',
        'Automated vendor remediation was disabled in policy configuration during this scan.',
      ]
        .map(escapeCsvField)
        .join(',')
    );
  }

  const csvContent = lines.join('\r\n');
  const safeId = scan.scanId.replace(/[^a-zA-Z0-9_-]/g, '_');
  triggerBrowserDownload(
    csvContent,
    `SentinelLayer_Compliance_Report_${safeId}.csv`,
    'text/csv;charset=utf-8'
  );
}
