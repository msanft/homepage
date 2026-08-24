import { error } from '@sveltejs/kit';
import { listAssets, readAsset } from '$lib/server/content.js';

/** @type {Record<string, string>} */
const contentTypes = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp'
};

export const prerender = true;
export const trailingSlash = 'never';

export async function entries() {
  return (await listAssets()).map(({ slug, asset }) => ({ slug, asset }));
}

export async function GET({ params }) {
  const body = await readAsset(params.slug, params.asset);
  if (!body) error(404, 'Asset not found');

  const extension = params.asset.split('.').pop()?.toLowerCase() ?? '';

  return new Response(body, {
    headers: {
      'content-type': contentTypes[extension] ?? 'application/octet-stream',
      'cache-control': 'public, max-age=31536000, immutable'
    }
  });
}
