# kevinmata92.github.io

Personal security research and engineering site - built with Jekyll and the
Minima theme, hosted on GitHub Pages.

## Local development

Requires Ruby (with the DevKit on Windows) and Bundler.

```bash
bundle install
bundle exec jekyll serve --livereload
```

The site is served at <http://localhost:4000>. To build without serving:

```bash
bundle exec jekyll build
```

Output goes to `_site/` (git-ignored).

## Structure

```
_config.yml    site config and navigation
index.md       homepage
research.md    research index
projects.md    projects
about.md       about
_posts/        write-ups (served at /research/<slug>/)
assets/        styles, images, and downloadable files
```

## Adding a write-up

1. Create `_posts/YYYY-MM-DD-<slug>.md` - the date prefix is required.
2. Add an entry to `research.md`.
