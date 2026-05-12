import { useState } from 'react';
import { Search, Send } from 'lucide-react';
import { detectUrl } from '../lib/api.js';

export function DetectionForm({ onResult }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function submit(event) {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await detectUrl(url);
      onResult(result);
      setUrl('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Detection request failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3 rounded-lg border border-slate-800 bg-slate-950 p-4">
      <label className="text-sm font-medium text-slate-300" htmlFor="url-input">
        Analyze URL
      </label>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-5 w-5 text-slate-500" aria-hidden="true" />
          <input
            id="url-input"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="h-10 w-full rounded-md border border-slate-700 bg-slate-900 pl-10 pr-3 text-slate-100 outline-none focus:border-teal-500"
            placeholder="https://example.com/login"
            required
          />
        </div>
        <button
          type="submit"
          className="inline-flex h-10 items-center gap-2 rounded-md bg-teal-600 px-4 font-semibold text-white hover:bg-teal-500 disabled:opacity-60"
          disabled={loading}
          title="Submit URL for analysis"
        >
          <Send className="h-4 w-4" aria-hidden="true" />
          {loading ? 'Scanning' : 'Scan'}
        </button>
      </div>
      {error && <p className="text-sm text-red-400">{error}</p>}
    </form>
  );
}

