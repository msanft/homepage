import { readMarkdown } from '$lib/server/content.js';

export async function load() {
  const { metadata, html } = await readMarkdown('_index.md');

  return {
    title: metadata.title,
    html
  };
}
