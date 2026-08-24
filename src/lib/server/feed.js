import { listDocuments } from '$lib/server/content.js';
import { site } from '$lib/site.js';

/** @param {string} value */
function escapeXml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

export async function rssResponse() {
  const posts = await listDocuments('blog');
  const items = posts
    .map((post) => {
      const url = `${site.url}/blog/${post.slug}/`;
      const date = post.date ? `<pubDate>${new Date(post.date).toUTCString()}</pubDate>` : '';

      return `<item><title>${escapeXml(post.title)}</title><link>${url}</link><guid>${url}</guid>${date}<description>${escapeXml(post.description)}</description></item>`;
    })
    .join('');

  const xml = `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${site.title}</title><link>${site.url}/blog/</link><description>Security research and CTF writeups by Moritz Sanft.</description>${items}</channel></rss>`;

  return new Response(xml, {
    headers: { 'content-type': 'application/rss+xml; charset=utf-8' }
  });
}
