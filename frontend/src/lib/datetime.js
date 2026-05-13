export function normalizeBackendTimestamp(timestamp) {
  if (!timestamp) return null;
  const value = String(timestamp);
  // Backend timestamps are UTC; older rows may omit the trailing timezone marker.
  const normalized = /(?:z|[+-]\d{2}:?\d{2})$/i.test(value) ? value : `${value}Z`;
  return new Date(normalized);
}

export function formatLocalDateTime(timestamp) {
  const date = normalizeBackendTimestamp(timestamp);
  if (!date || Number.isNaN(date.getTime())) return 'Unknown';
  return date.toLocaleString();
}
