export function MetricTile({ label, value, tone = 'neutral' }) {
  const tones = {
    neutral: 'border-slate-700 bg-slate-900 text-slate-100',
    success: 'border-teal-700 bg-teal-950 text-teal-50',
    warning: 'border-amber-700 bg-amber-950 text-amber-50',
    danger: 'border-red-700 bg-red-950 text-red-50'
  };

  return (
    <section className={`rounded-lg border p-4 ${tones[tone]}`}>
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-2 text-3xl font-semibold">{value}</p>
    </section>
  );
}

