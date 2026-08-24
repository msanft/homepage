import { listDocuments, readSection } from '$lib/server/content.js';

export async function load() {
  const [{ metadata, html }, talks] = await Promise.all([
    readSection('talks'),
    listDocuments('talks')
  ]);

  return {
    title: metadata.title,
    html,
    talks
  };
}
