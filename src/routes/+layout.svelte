<script>
  import { base } from '$app/paths';
  import { site } from '$lib/site.js';
  import '../app.css';

  let { children } = $props();
</script>

<div class="site">
  <header>
    <h1 class="site-title"><a href={`${base}/`}>{site.title}</a></h1>
    <nav aria-label="Main navigation">
      <ul>
        <li><a href={`${base}/blog/`}>Blog</a></li>
        <li><a href={`${base}/talks/`}>Talks</a></li>
      </ul>
    </nav>
  </header>

  <main>{@render children()}</main>

  <footer>
    <ul>
      <li>{site.email}</li>
      {#each site.links as [label, href]}
        <li><a {href}>{label}</a></li>
      {/each}
    </ul>
  </footer>
</div>
