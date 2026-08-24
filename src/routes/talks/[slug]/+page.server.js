import { error } from '@sveltejs/kit';
import { listDocuments, readDocument } from '$lib/server/content.js';

export async function entries() {
  return (await listDocuments('talks')).map(({ slug }) => ({ slug }));
}

export async function load({ params }) {
  const talk = await readDocument('talks', params.slug);
  if (!talk) error(404, 'Talk not found');

  return talk;
}
