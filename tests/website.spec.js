import { expect, test } from '@playwright/test';

test('homepage renders and client-side navigation works', async ({ page }) => {
  /** @type {string[]} */
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));

  // Wait for the initial modules to load before exercising Svelte navigation.
  const response = await page.goto('/', { waitUntil: 'networkidle' });
  expect(response?.status()).toBe(200);
  await expect(page).toHaveTitle('Moritz Sanft');
  await expect(page.getByRole('main')).toContainText('Hello, my name is Moritz.');
  await expect(page.getByRole('heading', { name: 'Academic publications' })).toBeVisible();
  await page.evaluate(() => { document.documentElement.dataset.navigationTest = 'loaded'; });

  await page.getByRole('navigation').getByRole('link', { name: 'Blog' }).click();
  await expect(page).toHaveURL(/\/blog\/$/);
  const post = page.locator('main h2 a').first();
  const postTitle = await post.innerText();
  await post.click();
  await expect(page.getByRole('main').getByRole('heading', { level: 1 })).toHaveText(postTitle);

  await page.getByRole('navigation').getByRole('link', { name: 'Talks' }).click();
  await expect(page).toHaveURL(/\/talks\/$/);
  const talk = page.locator('main h2 a').first();
  const talkTitle = await talk.innerText();
  await talk.click();
  await expect(page.getByRole('main').getByRole('heading', { level: 1 })).toHaveText(talkTitle);

  await page.getByRole('link', { name: 'Moritz Sanft', exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('main')).toContainText('Hello, my name is Moritz.');
  // A full-page reload would lose this marker, masking a broken client router.
  await expect(page.locator('html')).toHaveAttribute('data-navigation-test', 'loaded');
  expect(errors).toEqual([]);
});

test('every published page, internal link, and image loads', async ({ page, request, baseURL }) => {
  if (!baseURL) throw new Error('A local preview baseURL is required');
  /** @type {string[]} */
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('response', (response) => {
    if (response.url().startsWith(baseURL) && response.status() >= 400) {
      errors.push(`${response.status()} ${response.url()}`);
    }
  });
  page.on('requestfailed', (request) => {
    if (request.url().startsWith(baseURL)) errors.push(`Failed to load ${request.url()}`);
  });

  const sitemap = await request.get('/sitemap.xml');
  expect(sitemap.status()).toBe(200);
  const paths = [...(await sitemap.text()).matchAll(/<loc>([^<]+)<\/loc>/g)]
    .map(([, url]) => new URL(url).pathname);
  expect(paths).toEqual(expect.arrayContaining(['/', '/blog/', '/talks/']));
  expect(paths.some((path) => /^\/blog\/[^/]+\/$/.test(path))).toBe(true);
  expect(paths.some((path) => /^\/talks\/[^/]+\/$/.test(path))).toBe(true);
  expect(paths).not.toContain('/blog/test-post/');

  const internalLinks = new Set();
  for (const path of paths) {
    const response = await page.goto(path, { waitUntil: 'networkidle' });
    expect(response?.status(), path).toBe(200);
    await expect(page.getByRole('main')).toBeVisible();
    await expect(page.locator('main .markdown')).not.toBeEmpty();
    await expect(page).toHaveTitle(/Moritz Sanft/);

    for (const image of await page.locator('main img').all()) {
      await image.scrollIntoViewIfNeeded();
      await expect(image).toBeVisible();
      await expect.poll(() => image.evaluate((element) =>
        element instanceof HTMLImageElement && element.complete && element.naturalWidth > 0
      )).toBe(true);
    }

    const links = await page.locator('a[href]').evaluateAll((anchors) => anchors
      .filter((anchor) => anchor instanceof HTMLAnchorElement && anchor.origin === location.origin)
      .map((anchor) => anchor.getAttribute('href')));
    for (const href of links) {
      if (href) internalLinks.add(new URL(href, page.url()).pathname);
    }
  }

  for (const path of internalLinks) {
    expect((await request.get(path)).status(), path).toBe(200);
  }
  expect(errors).toEqual([]);
});

test('RSS feeds and static assets are present', async ({ request }) => {
  for (const path of ['/index.xml', '/blog/index.xml']) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
    expect(response.headers()['content-type']).toMatch(/xml/);
    const xml = await response.text();
    expect(xml).toContain('<rss version="2.0">');
    expect(xml).toContain('<item>');
    expect(xml).not.toContain('/blog/test-post/');
  }
  for (const path of ['/pgp.txt', '/robots.txt', '/og.png']) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
    expect((await response.body()).length, path).toBeGreaterThan(0);
  }
});
