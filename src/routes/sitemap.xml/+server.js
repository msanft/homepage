import { listDocuments } from '$lib/server/content.js';
import { site } from '$lib/site.js';

export const prerender = true;
export const trailingSlash = 'never';

/** @param {string} value */
function entry(value) {
  return `<url><loc>${value}</loc></url>`;
}

export async function GET() {
  const [posts, talks] = await Promise.all([listDocuments('blog'), listDocuments('talks')]);
  const urls = [
    `${site.url}/`,
    `${site.url}/blog/`,
    ...posts.map((post) => `${site.url}/blog/${post.slug}/`),
    `${site.url}/talks/`,
    ...talks.map((talk) => `${site.url}/talks/${talk.slug}/`)
  ];
  const xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(entry).join('')}</urlset>`;

  return new Response(xml, {
    headers: { 'content-type': 'application/xml; charset=utf-8' }
  });
}
