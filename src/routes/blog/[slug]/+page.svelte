<script>
  import { formatDate } from '$lib/date.js';
  import { site } from '$lib/site.js';

  let { data } = $props();
  const canonical = $derived(`${site.url}/blog/${data.slug}/`);
  const image = $derived(data.image ? `${site.url}/blog/${data.slug}/${data.image}` : null);
</script>

<svelte:head>
  <title>{data.title} | {site.title}</title>
  <meta name="description" content={data.description} />
  <link rel="canonical" href={canonical} />
  <meta property="og:type" content="article" />
  <meta property="og:title" content={data.title} />
  <meta property="og:description" content={data.description} />
  <meta property="og:url" content={canonical} />
  <meta name="twitter:card" content={image ? 'summary_large_image' : 'summary'} />
  <meta name="twitter:title" content={data.title} />
  <meta name="twitter:description" content={data.description} />
  {#if image}
    <meta property="og:image" content={image} />
    <meta name="twitter:image" content={image} />
  {/if}
</svelte:head>

<article>
  <header class="post-header">
    <h1>{data.title}</h1>
    {#if data.date}
      <time datetime={data.date}>{formatDate(data.date)}</time>
    {/if}
  </header>
  <div class="markdown">{@html data.html}</div>
</article>
