<script>
  import { site } from '#lib/site.js';

  const publications = [
    {
      year: 2026,
      title: 'SEMSAN: a Configurable Sanitizer for Detecting System-Level Semantic Bugs',
      authors: 'Moritz Sanft and Flavio Toffalini',
      venue: '20th USENIX WOOT Conference on Offensive Technologies (WOOT 26)',
      url: 'https://www.usenix.org/conference/woot26/presentation/sanft'
    }
  ];
</script>

<svelte:head>
  <title>Academic publications | {site.title}</title>
  <meta name="description" content="Academic publications by Moritz Sanft." />
  <link rel="canonical" href={`${site.url}/publications/`} />
  <meta property="og:type" content="website" />
  <meta property="og:title" content={`Academic publications | ${site.title}`} />
  <meta property="og:description" content="Academic publications by Moritz Sanft." />
  <meta property="og:url" content={`${site.url}/publications/`} />
  <meta property="og:image" content={`${site.url}/og.png`} />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content={`Academic publications | ${site.title}`} />
  <meta name="twitter:description" content="Academic publications by Moritz Sanft." />
  <meta name="twitter:image" content={`${site.url}/og.png`} />
</svelte:head>

<article class="markdown">
  <p>Find my academic publications here.</p>
</article>

<ul class="section-list">
  {#each publications as publication}
    <li>
      <h2><a href={publication.url}>{publication.title}</a></h2>
      <div><time datetime={String(publication.year)}>{publication.year}</time></div>
      <div>{publication.authors}</div>
      <div>{publication.venue}</div>
    </li>
  {/each}
</ul>
