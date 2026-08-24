import { error } from '@sveltejs/kit';
import { listDocuments, readDocument } from '$lib/server/content.js';

export async function entries() {
  return (await listDocuments('blog')).map(({ slug }) => ({ slug }));
}

export async function load({ params }) {
  const post = await readDocument('blog', params.slug);
  if (!post) error(404, 'Post not found');

  return post;
}
