# Homepage

A small, statically generated SvelteKit site.

```sh
pnpm install
pnpm dev
```

`pnpm check` checks the source and `pnpm build` writes the deployable site to `build/`.

## Content

Content stays in Markdown under `content/`, with TOML front matter between `+++` markers.

- Edit `content/_index.md` for the homepage.
- Add a blog post as `content/blog/my-post.md`.
- To keep images beside a post, use `content/blog/my-post/_index.md` and reference them with `./image.png`.
- Set `draft = true` to keep a post out of the site.

Talks use the same format under `content/talks/`.
