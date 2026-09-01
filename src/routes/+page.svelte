<script>
  import { site } from '$lib/site.js';

  let { data } = $props();

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

<section class="publications" aria-labelledby="publications-heading">
  <div class="publications-heading">
    <h2 id="publications-heading">Academic publications</h2>
  </div>

  <ol class="publication-list">
    {#each publications as publication}
      <li class="publication">
        <time class="publication-year" datetime={String(publication.year)}>{publication.year}</time>
        <article>
          <h3>
            <cite><a href={publication.url}>{publication.title}</a></cite>
          </h3>
          <p class="publication-authors">{publication.authors}</p>
          <p class="publication-venue">{publication.venue}</p>
        </article>
      </li>
    {/each}
  </ol>
</section>

<style>
  .publications {
    max-width: 65ch;
    margin-top: clamp(3.5rem, 9vw, 6rem);
  }

  .publications-heading {
    display: flex;
    gap: 1rem;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .publications-heading::after {
    flex: 1;
    border-top: 1px solid var(--rule, #aaa89f);
    content: '';
  }

  .publications h2 {
    margin: 0;
    font-size: clamp(1.5rem, 3vw, 1.85rem);
    font-weight: 600;
    line-height: 1.2;
    letter-spacing: -0.015em;
  }

  .publication-list {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .publication {
    display: grid;
    grid-template-columns: 3.5rem minmax(0, 1fr);
    gap: 1rem;
    padding: 1.25rem 0;
    border-bottom: 1px solid var(--rule, #aaa89f);
  }

  .publication-year {
    padding-top: 0.2rem;
    color: var(--muted, #696b69);
    font-size: 0.95rem;
    font-variant-numeric: tabular-nums;
  }

  .publication article,
  .publication h3,
  .publication p {
    margin: 0;
  }

  .publication h3 {
    font-size: clamp(1.2rem, 2.5vw, 1.45rem);
    font-weight: 600;
    line-height: 1.25;
  }

  .publication cite {
    font-style: normal;
  }

  .publication .publication-authors {
    margin-top: 0.55rem;
  }

  .publication .publication-venue {
    margin-top: 0.15rem;
    color: var(--muted, #696b69);
    font-size: 0.95rem;
  }

  @media (max-width: 420px) {
    .publication {
      grid-template-columns: 1fr;
      gap: 0.3rem;
    }

    .publication-year {
      padding-top: 0;
    }
  }
</style>
