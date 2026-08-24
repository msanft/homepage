const formatter = new Intl.DateTimeFormat('en-US', { dateStyle: 'long' });

/** @param {string} value */
export function formatDate(value) {
  return formatter.format(new Date(value));
}
