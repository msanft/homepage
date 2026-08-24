<script>
  import { formatDate } from '$lib/date.js';
  import { site } from '$lib/site.js';

  let { data } = $props();
  const canonical = $derived(`${site.url}/talks/${data.slug}/`);
</script>

<svelte:head>
  <title>{data.title} | {site.title}</title>
  <meta name="description" content={data.description} />
  <link rel="canonical" href={canonical} />
  <meta property="og:type" content="article" />
  <meta property="og:title" content={data.title} />
  <meta property="og:description" content={data.description} />
  <meta property="og:url" content={canonical} />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content={data.title} />
  <meta name="twitter:description" content={data.description} />
</svelte:head>

<article>
  <header class="post-header">
    <h1>{data.title}</h1>
    <ul class="talk-meta">
      {#if data.date}
        <li><time datetime={data.date}>{formatDate(data.date)}</time></li>
      {/if}
      {#if data.params.slides?.startsWith('http')}
        <li><a href={data.params.slides}>Slides</a></li>
      {/if}
      {#if data.params.video?.startsWith('http')}
        <li><a href={data.params.video}>Video</a></li>
      {/if}
    </ul>
  </header>
  <div class="markdown">{@html data.html}</div>
</article>
