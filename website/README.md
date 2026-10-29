# Cloudsneeker marketing website

A self-contained static site: HTML, one stylesheet (`assets/css/site.css`) and one small script (`assets/js/site.js`). There is no build step, no framework and no external JavaScript. The only external request is Google Fonts.

```
website/
  index.html  platform.html  services.html  pricing.html  security.html
  about.html  contact.html  privacy.html  terms.html  404.html
  favicon.svg  robots.txt  sitemap.xml  .well-known/security.txt
  assets/css/site.css  assets/js/site.js
```

The header and footer are copied into every page. If you change one, change it on all pages.

## Preview

Open `index.html` in a browser, or serve the folder so the links behave as they will in production:

```bash
cd website
python -m http.server 8000
# then open http://localhost:8000
```

`404.html` uses root-relative links (`/assets/...`) so it works at any missing path. It only renders correctly when served over HTTP, not from `file://`.

## Deploy to Amazon S3 + CloudFront (high level)

1. Create a private S3 bucket, for example `cloudsneeker-website`. Keep Block Public Access on.
2. Upload the contents of `website/` (not the folder itself), including `.well-known/`:
   ```bash
   aws s3 sync website/ s3://cloudsneeker-website/ --delete --exclude README.md
   ```
3. Create a CloudFront distribution with the bucket as origin, using Origin Access Control so only CloudFront can read the bucket.
4. Set the default root object to `index.html`.
5. Add custom error responses: 403 and 404 return `/404.html` with status 404.
6. Request an ACM certificate in `us-east-1` for your domain, attach it to the distribution, redirect HTTP to HTTPS, and point your DNS (Route 53 alias or CNAME) at CloudFront.
7. Optional: add a response headers policy (HSTS, `X-Content-Type-Options`, `Referrer-Policy`). If you add a Content-Security-Policy, allow `https://fonts.googleapis.com` (styles), `https://fonts.gstatic.com` (fonts), and the small inline theme script in each page's `<head>` (use its hash or `'unsafe-inline'` for `script-src`).
8. After each upload, invalidate the cache: `aws cloudfront create-invalidation --distribution-id <ID> --paths "/*"`.

Any other static host (Netlify, GitHub Pages, Nginx) works too: serve the folder and map missing pages to `404.html`.

## Placeholders to fill before launch

Search the folder for `TODO`, `example.com`, `cloudsneeker.example` and `[` to find them all.

| Placeholder | Where |
|---|---|
| `[Company legal name]` | Footer of every page, about, privacy, terms |
| `[Registered address]`, `[Registration number]`, `[Year]` | about, contact, privacy |
| `[Founder name, title and a short bio]` | about |
| `[response time]` | contact |
| `hello@example.com` (sales / general contact) | contact form `action` and `data-mailto`, contact, about |
| `security@example.com` (security contact) | security.html, `.well-known/security.txt` |
| `https://cloudsneeker.example` (production domain) | canonical and `og:url` tags on every page, `sitemap.xml`, `robots.txt`, `.well-known/security.txt` |
| `Expires` date | `.well-known/security.txt` |
| Privacy notice: contact email, other data categories, purposes and legal bases, sub-processors, retention, transfers, supervisory authority, date | privacy.html (template, have counsel review) |
| Terms: fees, professional services, warranties and liability, termination, governing law, legal contact, date | terms.html (template, have counsel review) |
| Google Fonts: confirm in the privacy notice, or self-host the fonts | privacy.html, `<head>` of every page |
| Social share image: export a 1200x630 PNG and add `og:image` / `twitter:image` tags (the site ships without one because most networks do not accept SVG) | `<head>` of every page |

## Content rules

- Only claim features the product has today. Items not yet in place are listed as roadmap on `security.html`; update that page as they ship.
- Dashboard, Attack Paths, Seeker AI, report and governance visuals are CSS and SVG mockups with illustrative sample data, not real customer data.
- Do not name the scanning engines behind the product anywhere on the site.
