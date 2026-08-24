import { listDocuments, readSection } from '$lib/server/content.js';

export async function load() {
  const [{ metadata, html }, posts] = await Promise.all([
    readSection('blog'),
    listDocuments('blog')
  ]);

  return {
    title: metadata.title,
    html,
    posts
  };
}
