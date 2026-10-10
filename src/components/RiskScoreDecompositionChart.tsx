import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ReferenceLine,
} from 'recharts';
import { PolicyOutcome } from '../types/sentinel.ts';

interface RiskFactorItem {
  factor: string;
  points: number;
  detail: string;
}

interface RiskScoreDecompositionChartProps {
  totalScore: number;
  riskFactors: RiskFactorItem[];
  blockThreshold: number;
  quarantineThreshold: number;
  sanitiseThreshold: number;
  outcome: PolicyOutcome;
}

interface ChartRow {
  id: string;
  shortName: string;
  fullName: string;
  categoryGroup: 'Threat Category' | 'Policy Violation' | 'Contextual / Signal' | 'Baseline';
  points: number;
  detail: string;
  color: string;
}

function classifyFactorGroup(factorName: string, pts: number): {
  group: ChartRow['categoryGroup'];
  color: string;
} {
  const lower = factorName.toLowerCase();
  if (lower.includes('tool') || lower.includes('policy') || lower.includes('unauthorized')) {
    return { group: 'Policy Violation', color: '#EF4444' }; // Crimson
  }
  if (lower.includes('quotation') || lower.includes('offline') || lower.includes('context')) {
    return { group: 'Contextual / Signal', color: '#0EA5E9' }; // Sky Blue
  }
  if (pts >= 40) {
    return { group: 'Threat Category', color: '#F97316' }; // High-severity Orange
  }
  return { group: 'Threat Category', color: '#F59E0B' }; // Amber
}

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload || !payload.length) return null;
  const item: ChartRow = payload[0].payload;
  return (
    <div className="p-3 bg-slate-950 border border-slate-700 rounded-lg shadow-xl max-w-xs space-y-1.5 text-xs">
      <div className="flex items-center justify-between gap-3">
        <span className="font-semibold text-white">{item.fullName}</span>
        <span className="font-mono font-bold text-amber-400 tabular-nums">
          +{item.points} pts
        </span>
      </div>
      <div className="text-[11px] font-mono text-slate-400">
        Contributor Type: {item.categoryGroup}
      </div>
      <p className="text-slate-300 leading-relaxed">{item.detail}</p>
    </div>
  );
};

export const RiskScoreDecompositionChart: React.FC<RiskScoreDecompositionChartProps> = ({
  totalScore,
  riskFactors,
  blockThreshold,
  quarantineThreshold,
  sanitiseThreshold,
}) => {
  const rows: ChartRow[] =
    riskFactors.length > 0
      ? riskFactors.map((rf, idx) => {
          const { group, color } = classifyFactorGroup(rf.factor, rf.points);
          const cleanLabel = rf.factor.replace(/\s*\([^)]*\)/g, '').trim();
          return {
            id: `rf-${idx}`,
            shortName: cleanLabel.length > 24 ? `${cleanLabel.slice(0, 22)}...` : cleanLabel,
            fullName: rf.factor,
            categoryGroup: group,
            points: rf.points,
            detail: rf.detail,
            color,
          };
        })
      : [
          {
            id: 'rf-clean',
            shortName: 'Clean / Zero Signals',
            fullName: 'Benign / Clean Content Baseline',
            categoryGroup: 'Baseline',
            points: 0,
            detail: 'Zero malicious signals, policy violations, or unauthorized tool calls detected.',
            color: '#10B981',
          },
        ];

  // Aggregate subtotals by contributor type for quick inspection
  const threatCategoryPts = rows
    .filter((r) => r.categoryGroup === 'Threat Category')
    .reduce((acc, r) => acc + r.points, 0);
  const policyViolationPts = rows
    .filter((r) => r.categoryGroup === 'Policy Violation')
    .reduce((acc, r) => acc + r.points, 0);
  const contextualSignalPts = rows
    .filter((r) => r.categoryGroup === 'Contextual / Signal')
    .reduce((acc, r) => acc + r.points, 0);

  return (
    <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h4 className="text-xs font-semibold text-slate-200">
            Risk Score Decomposition (Contributor Weights)
          </h4>
          <p className="text-[11px] text-slate-400">
            Visual breakdown of individual contributor weights against active policy thresholds (Sanitise: {sanitiseThreshold} · Quarantine: {quarantineThreshold} · Block: {blockThreshold}).
          </p>
        </div>
        <div className="text-xs font-mono text-slate-300 tabular-nums">
          Capped Total: <span className="font-bold text-white">{totalScore}</span> / 100
        </div>
      </div>

      {/* Contributor Group Subtotals */}
      <div className="grid grid-cols-3 gap-2.5 text-xs">
        <div className="p-2.5 bg-slate-900/90 border border-slate-800/90 rounded-md">
          <div className="text-[11px] text-slate-400">Threat Categories</div>
          <div className="text-sm font-bold text-amber-400 font-mono tabular-nums mt-0.5">
            +{threatCategoryPts} pts
          </div>
        </div>
        <div className="p-2.5 bg-slate-900/90 border border-slate-800/90 rounded-md">
          <div className="text-[11px] text-slate-400">Policy & Tool Violations</div>
          <div className="text-sm font-bold text-red-400 font-mono tabular-nums mt-0.5">
            +{policyViolationPts} pts
          </div>
        </div>
        <div className="p-2.5 bg-slate-900/90 border border-slate-800/90 rounded-md">
          <div className="text-[11px] text-slate-400">Contextual Signals</div>
          <div className="text-sm font-bold text-sky-400 font-mono tabular-nums mt-0.5">
            +{contextualSignalPts} pts
          </div>
        </div>
      </div>

      {/* Recharts Horizontal Contributor Weight Bar Chart */}
      <div className="h-52 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={rows}
            layout="vertical"
            margin={{ top: 8, right: 24, left: 8, bottom: 8 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
            <XAxis
              type="number"
              domain={[0, 100]}
              tick={{ fill: '#94A3B8', fontSize: 11, fontFamily: 'JetBrains Mono' }}
              stroke="#334155"
            />
            <YAxis
              type="category"
              dataKey="shortName"
              width={150}
              tick={{ fill: '#E2E8F0', fontSize: 11 }}
              stroke="#334155"
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(148, 163, 184, 0.08)' }} />
            <ReferenceLine
              x={sanitiseThreshold}
              stroke="#38BDF8"
              strokeDasharray="3 3"
              label={{
                value: `Sanitise (${sanitiseThreshold})`,
                position: 'insideTopRight',
                fill: '#38BDF8',
                fontSize: 10,
              }}
            />
            <ReferenceLine
              x={quarantineThreshold}
              stroke="#F59E0B"
              strokeDasharray="3 3"
              label={{
                value: `Quarantine (${quarantineThreshold})`,
                position: 'insideTopRight',
                fill: '#F59E0B',
                fontSize: 10,
              }}
            />
            <ReferenceLine
              x={blockThreshold}
              stroke="#EF4444"
              strokeDasharray="3 3"
              label={{
                value: `Block (${blockThreshold})`,
                position: 'insideTopRight',
                fill: '#EF4444',
                fontSize: 10,
              }}
            />
            <Bar dataKey="points" radius={[0, 4, 4, 0]} barSize={22}>
              {rows.map((entry) => (
                <Cell key={entry.id} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Detailed Contributor Factor List */}
      <div className="space-y-1.5 pt-1 border-t border-slate-800/80">
        {riskFactors.length === 0 ? (
          <div className="text-xs text-emerald-400 font-mono">
            0 points — All deterministic rules, contextual signals, and tool gateway checks passed cleanly.
          </div>
        ) : (
          riskFactors.map((rf, i) => (
            <div
              key={i}
              className="p-2 bg-slate-900/70 border border-slate-800/80 rounded text-xs flex items-start justify-between gap-3"
            >
              <div>
                <div className="font-medium text-slate-200">{rf.factor}</div>
                <div className="text-slate-400 text-[11px]">{rf.detail}</div>
              </div>
              <span className="font-mono font-semibold text-amber-400 tabular-nums shrink-0">
                +{rf.points} pts
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
