import { rssResponse } from '$lib/server/feed.js';

export const prerender = true;
export const trailingSlash = 'never';

export function GET() {
  return rssResponse();
}
