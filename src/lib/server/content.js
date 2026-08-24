import { readFile, readdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { Marked } from 'marked';
import markedFootnote from 'marked-footnote';
import { gfmHeadingId } from 'marked-gfm-heading-id';
import { parse } from 'smol-toml';

const contentRoot = resolve('content');
const markdown = new Marked({ gfm: true }).use(markedFootnote(), gfmHeadingId());
const inlineMarkdown = new Marked({ gfm: true });

/** @typedef {{ title: string, date?: Date, draft?: boolean, params?: { video?: string, slides?: string } }} Frontmatter */
/** @typedef {{ slug: string, title: string, date: string | null, draft: boolean, params: { video?: string, slides?: string }, description: string, image: string | null, html: string }} Document */
/** @typedef {{ slug: string, asset: string, path: string }} ContentAsset */

/** @param {string} source */
function parseMarkdown(source) {
  const match = source.match(/^\+\+\+\r?\n([\s\S]*?)\r?\n\+\+\+\r?\n?([\s\S]*)$/);

  if (!match) {
    throw new Error('Markdown file is missing TOML front matter');
  }

  return {
    metadata: /** @type {Frontmatter} */ (/** @type {unknown} */ (parse(match[1]))),
    body: match[2],
    html: String(markdown.parse(match[2]))
  };
}

/** @param {string} body */
function descriptionFrom(body) {
  const paragraph = body
    .split(/\r?\n\s*\r?\n/)
    .map((block) => block.trim())
    .find((block) => block && !/^(?:#|>|```|~~~|- |\* |\d+\. |!\[)/.test(block));

  if (!paragraph) return '';

  const plain = String(
    inlineMarkdown.parseInline(paragraph.replace(/\[\^[^\]]+\]/g, '').replace(/\r?\n/g, ' '))
  )
    .replace(/<[^>]+>/g, '')
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replace(/\s+/g, ' ')
    .trim();

  if (plain.length <= 160) return plain;
  return `${plain.slice(0, 159).replace(/\s+\S*$/, '')}…`;
}

/** @param {string} body */
function imageFrom(body) {
  const match = body.match(/!\[[^\]]*\]\((?:\.\/)?([^\s)]+)(?:\s+"[^"]*")?\)/);
  return match ? basename(match[1]) : null;
}

/** @param {string} path @param {string} slug */
async function readDocumentFile(path, slug) {
  const { metadata, body, html } = parseMarkdown(await readFile(path, 'utf8'));

  if (typeof metadata.title !== 'string') {
    throw new Error(`${path} is missing a title`);
  }

  return /** @type {Document} */ ({
    slug,
    title: metadata.title,
    date: metadata.date?.toISOString() ?? null,
    draft: metadata.draft ?? false,
    params: metadata.params ?? {},
    description: descriptionFrom(body),
    image: imageFrom(body),
    html
  });
}

/** @param {string} section */
async function documentPaths(section) {
  const sectionPath = join(contentRoot, section);
  const entries = await readdir(sectionPath, { withFileTypes: true });
  /** @type {{ slug: string, path: string }[]} */
  const paths = [];

  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith('.md') && entry.name !== '_index.md') {
      paths.push({ slug: entry.name.slice(0, -3), path: join(sectionPath, entry.name) });
    } else if (entry.isDirectory()) {
      paths.push({ slug: entry.name, path: join(sectionPath, entry.name, '_index.md') });
    }
  }

  return paths;
}

/** @param {string} relativePath */
export async function readMarkdown(relativePath) {
  const source = await readFile(join(contentRoot, relativePath), 'utf8');
  return parseMarkdown(source);
}

/** @param {string} section */
export async function readSection(section) {
  return readMarkdown(`${section}/_index.md`);
}

/** @param {string} section */
export async function listDocuments(section) {
  const documents = await Promise.all(
    (await documentPaths(section)).map(({ path, slug }) => readDocumentFile(path, slug))
  );

  return documents
    .filter((document) => !document.draft)
    .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
    .map(({ html: _html, draft: _draft, ...document }) => document);
}

/** @param {string} section @param {string} slug */
export async function readDocument(section, slug) {
  const match = (await documentPaths(section)).find((document) => document.slug === slug);
  if (!match) return null;

  const document = await readDocumentFile(match.path, match.slug);
  return document.draft ? null : document;
}

export async function listAssets() {
  const bundled = (await documentPaths('blog')).filter(
    (document) => basename(document.path) === '_index.md'
  );
  /** @type {ContentAsset[]} */
  const assets = [];

  for (const document of bundled) {
    const directory = dirname(document.path);
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isFile() && entry.name !== '_index.md') {
        assets.push({
          slug: document.slug,
          asset: entry.name,
          path: join(directory, entry.name)
        });
      }
    }
  }

  return assets;
}

/** @param {string} slug @param {string} asset */
export async function readAsset(slug, asset) {
  const match = (await listAssets()).find((item) => item.slug === slug && item.asset === asset);
  if (!match) return null;

  return new Uint8Array(await readFile(match.path));
}
