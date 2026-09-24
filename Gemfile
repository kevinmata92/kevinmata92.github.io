source "https://rubygems.org"

# Pins Jekyll and every plugin to the exact versions GitHub Pages runs, so a
# local build matches the published site. Bundles minima, jekyll-feed,
# jekyll-seo-tag and jekyll-sitemap.
gem "github-pages", group: :jekyll_plugins

# Windows and JRuby do not ship a zoneinfo database.
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", "~> 1.2"
  gem "tzinfo-data"
end

# Required by Jekyll 3.x on Ruby 3.x.
gem "webrick", "~> 1.8"
