# Homepage

A small, statically generated SvelteKit site.

```sh
pnpm install
pnpm dev
```

`pnpm check` checks the source and `pnpm build` writes the deployable site to `build/`.

## Website checks and dependency updates

Pull requests run `pnpm check`, a production build, and Playwright smoke tests in
desktop and mobile Chromium. The tests cover client-side navigation, every page
in the sitemap, internal links, images, RSS feeds, and public static assets.

Run the same checks locally with the pnpm version in `packageManager`:

```sh
pnpm install --frozen-lockfile
pnpm exec playwright install chromium
pnpm check
pnpm build
pnpm test
```

The `main` branch requires the GitHub Actions **Website checks** status check.
Keep this protection enabled: it is part of the dependency auto-merge gate.

After successful PR CI, `Dependabot auto-merge` runs the same website checks on
the PR combined with the latest `main`. Its read-only test job has no write
credentials while it installs dependencies or runs PR code. A separate merge
job squash-merges verified Dependabot patch and minor updates only when the PR
and `main` still match the commits it tested. Major updates, failed checks, and
conflicting PRs stay open for review. The merge workflow explicitly dispatches
the Pages deployment because merges made with `GITHUB_TOKEN` do not trigger push
workflows. No additional token or secret is needed.

## Content

Content stays in Markdown under `content/`, with TOML front matter between `+++` markers.

- Edit `content/_index.md` for the homepage.
- Add a blog post as `content/blog/my-post.md`.
- To keep images beside a post, use `content/blog/my-post/_index.md` and reference them with `./image.png`.
- Set `draft = true` to keep a post out of the site.

Talks use the same format under `content/talks/`.
