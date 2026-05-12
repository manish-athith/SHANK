import { ShieldAlert } from 'lucide-react';

function severityClass(severity) {
  return {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-amber-500 text-slate-950',
    low: 'bg-teal-600 text-white'
  }[severity] || 'bg-slate-600 text-white';
}

export function AlertTable({ alerts, filter }) {
  const filtered = alerts.filter((alert) => {
    const haystack = `${alert.title} ${alert.description} ${alert.severity}`.toLowerCase();
    return haystack.includes(filter.toLowerCase());
  });

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800">
        <thead className="bg-slate-900">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-400">Alert</th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-400">Severity</th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-400">Risk</th>
            <th className="px-4 py-3 text-left text-xs font-medium uppercase text-slate-400">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-slate-950">
          {filtered.map((alert) => (
            <tr key={alert.id}>
              <td className="px-4 py-3">
                <div className="flex items-center gap-3">
                  <ShieldAlert className="h-5 w-5 text-amber-400" aria-hidden="true" />
                  <div>
                    <p className="font-medium text-slate-100">{alert.title}</p>
                    <p className="line-clamp-1 text-sm text-slate-400">{alert.description}</p>
                  </div>
                </div>
              </td>
              <td className="px-4 py-3">
                <span className={`rounded px-2 py-1 text-xs font-semibold ${severityClass(alert.severity)}`}>
                  {alert.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-slate-200">{alert.risk_score}</td>
              <td className="px-4 py-3 text-sm text-slate-400">
                {new Date(alert.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td className="px-4 py-8 text-center text-slate-500" colSpan="4">
                No alerts match the current filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

