import React from 'react';

interface EngagementLogItem {
  step?: string;
  finding?: string;
  status?: string;
  target?: string;
  reproof?: string;
}

interface AgentActivityGraphProps {
  flowStatus?: string;
  costMeterUsd?: number;
  engagementLog?: EngagementLogItem[];
}

export const AgentActivityGraph: React.FC<AgentActivityGraphProps> = ({
  flowStatus = 'initializing',
  engagementLog = []
}) => {
  const steps = ['scope_gate', 'recon', 'vuln_scan', 'exploit', 'validator'];

  const normalizeStatus = (status: string): string => {
    const s = (status || '').toLowerCase().replace('_completed', '');
    if (steps.includes(s)) return s;
    if (s.includes('pre_scan') || s === 'pending' || s === 'initializing') return 'scope_gate';
    if (s.includes('recon') || s.includes('crawl') || s.includes('analyz') || s.includes('domain')) return 'recon';
    if (s.includes('test') || s.includes('vuln') || s.includes('scan')) return 'vuln_scan';
    if (s.includes('nuclei') || s.includes('secret') || s.includes('exploit')) return 'exploit';
    if (s.includes('verif') || s.includes('validat')) return 'validator';
    return s;
  };

  const normalizedFlow = normalizeStatus(flowStatus);
  const currentIdx = steps.indexOf(normalizedFlow);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl my-6" id="agent-activity-graph">
      <div className="mb-6 pb-4 border-b border-slate-800">
        <h3 className="text-lg font-bold text-cyan-400 flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-cyan-500 animate-pulse"></span>
          Autonomous AI Multi-Agent Execution Path
        </h3>
        <p className="text-xs text-slate-400 mt-1">Live LangGraph StateGraph Telemetry Feed</p>
      </div>

      {/* StateGraph Nodes Pipeline */}
      <div className="grid grid-cols-5 gap-2 mb-6">
        {steps.map((step, idx) => {
          const isDone = currentIdx > idx || flowStatus.includes('_completed') || flowStatus === 'completed' || flowStatus === 'validation_completed';
          const isCurrent = currentIdx === idx && !flowStatus.includes('_completed') && flowStatus !== 'completed' && flowStatus !== 'validation_completed';
          
          let statusBg = 'bg-slate-800 text-slate-500 border-slate-700';
          if (isDone) statusBg = 'bg-emerald-950/40 text-emerald-400 border-emerald-500/50';
          if (isCurrent) statusBg = 'bg-cyan-950/60 text-cyan-300 border-cyan-400 animate-pulse';

          return (
            <div key={step} className={`p-3 rounded-lg border flex flex-col items-center text-center transition-all ${statusBg}`}>
              <span className="text-xs uppercase font-semibold tracking-wider mb-1">
                {step.replace('_', ' ')}
              </span>
              <span className="text-[10px] opacity-75">
                {isDone ? 'COMPLETED' : isCurrent ? 'RUNNING...' : 'PENDING'}
              </span>
            </div>
          );
        })}
      </div>

      {/* Live Engagement Log Stream */}
      <div className="bg-slate-950 rounded-lg p-4 border border-slate-800 font-mono text-xs max-h-48 overflow-y-auto">
        <div className="text-slate-500 mb-2 pb-1 border-b border-slate-900 flex justify-between">
          <span>ENGAGEMENT LOG STREAM</span>
          <span>{engagementLog.length} events</span>
        </div>
        {engagementLog.length === 0 ? (
          <p className="text-slate-600 italic">Awaiting agent dispatch events...</p>
        ) : (
          engagementLog.map((log, i) => (
            <div key={i} className="py-1 flex gap-2 border-b border-slate-900/50 last:border-none">
              <span className="text-cyan-500">[{log.step || 'agent'}]</span>
              <span className="text-slate-300 flex-1">
                {log.status && <span className="text-emerald-400 font-bold mr-2">[{log.status.toUpperCase()}]</span>}
                {log.finding || log.target || 'Processing task state...'}
              </span>
              {log.reproof && <span className="text-amber-400">Reproof: {log.reproof}</span>}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
