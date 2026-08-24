<script>
  import { site } from '$lib/site.js';

  let { data } = $props();
</script>

<svelte:head>
  <title>{site.title}</title>
  <meta name="description" content={site.description} />
  <link rel="canonical" href={`${site.url}/`} />
  <link rel="alternate" type="application/rss+xml" title={site.title} href={`${site.url}/index.xml`} />
  <meta property="og:type" content="website" />
  <meta property="og:title" content={site.title} />
  <meta property="og:description" content={site.description} />
  <meta property="og:url" content={`${site.url}/`} />
  <meta property="og:image" content={`${site.url}/og.png`} />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content={site.title} />
  <meta name="twitter:description" content={site.description} />
  <meta name="twitter:image" content={`${site.url}/og.png`} />
</svelte:head>

<article class="markdown">{@html data.html}</article>
