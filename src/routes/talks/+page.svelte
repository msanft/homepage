<script>
  import { base } from '$app/paths';
  import { formatDate } from '$lib/date.js';
  import { site } from '$lib/site.js';

  let { data } = $props();
</script>

<svelte:head>
  <title>{data.title} | {site.title}</title>
  <meta name="description" content="Conference talks by Moritz Sanft." />
  <link rel="canonical" href={`${site.url}/talks/`} />
  <meta property="og:type" content="website" />
  <meta property="og:title" content={`${data.title} | ${site.title}`} />
  <meta property="og:description" content="Conference talks by Moritz Sanft." />
  <meta property="og:url" content={`${site.url}/talks/`} />
  <meta property="og:image" content={`${site.url}/og.png`} />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content={`${data.title} | ${site.title}`} />
  <meta name="twitter:description" content="Conference talks by Moritz Sanft." />
  <meta name="twitter:image" content={`${site.url}/og.png`} />
</svelte:head>

<article class="markdown">{@html data.html}</article>

<ul class="section-list">
  {#each data.talks as talk}
    <li>
      <h2><a href={`${base}/talks/${talk.slug}/`}>{talk.title}</a></h2>
      <ul class="talk-meta">
        {#if talk.date}
          <li><time datetime={talk.date}>{formatDate(talk.date)}</time></li>
        {/if}
        {#if talk.params.slides?.startsWith('http')}
          <li><a href={talk.params.slides}>Slides</a></li>
        {/if}
        {#if talk.params.video?.startsWith('http')}
          <li><a href={talk.params.video}>Video</a></li>
        {/if}
      </ul>
    </li>
  {/each}
</ul>
