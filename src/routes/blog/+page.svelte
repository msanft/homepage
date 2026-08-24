<script>
  import { base } from '$app/paths';
  import { formatDate } from '$lib/date.js';
  import { site } from '$lib/site.js';

  let { data } = $props();
</script>

<svelte:head>
  <title>{data.title} | {site.title}</title>
  <meta name="description" content="Security research and CTF writeups by Moritz Sanft." />
  <link rel="canonical" href={`${site.url}/blog/`} />
  <link rel="alternate" type="application/rss+xml" title={site.title} href={`${site.url}/blog/index.xml`} />
  <meta property="og:type" content="website" />
  <meta property="og:title" content={`${data.title} | ${site.title}`} />
  <meta property="og:description" content="Security research and CTF writeups by Moritz Sanft." />
  <meta property="og:url" content={`${site.url}/blog/`} />
  <meta property="og:image" content={`${site.url}/og.png`} />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content={`${data.title} | ${site.title}`} />
  <meta name="twitter:description" content="Security research and CTF writeups by Moritz Sanft." />
  <meta name="twitter:image" content={`${site.url}/og.png`} />
</svelte:head>

<article class="markdown">{@html data.html}</article>

<ul class="section-list">
  {#each data.posts as post}
    <li>
      <h2><a href={`${base}/blog/${post.slug}/`}>{post.title}</a></h2>
      {#if post.date}
        <time datetime={post.date}>{formatDate(post.date)}</time>
      {/if}
    </li>
  {/each}
</ul>
