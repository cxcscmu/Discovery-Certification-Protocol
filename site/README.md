# DCP project website

The public project page lives at
<https://cxcscmu.github.io/Discovery-Certification-Protocol/>.
`public/` is the complete, dependency-free static site. GitHub Pages receives
only that directory. The verifier, harness, and frozen audit bundles are
unchanged by the website.

## Preview and check

```bash
cd site
npm ci
npx playwright install chromium
npm test
npm run serve
```

Open <http://127.0.0.1:4173/>. The browser checks also exercise the actual
`/Discovery-Certification-Protocol/` project-site prefix. They cover five
viewport sizes, element overlaps, internal links, result values against the
existing certificates, copy controls, keyboard tabs, paused animation,
reduced-motion preferences, and readable content with JavaScript disabled.
Screenshots and a JSON report appear in `test-output/`.

## Publish and maintain

The `Project website` workflow validates changes and deploys `public/` on
pushes to `main`. Set the repository's Pages source to **GitHub Actions**.
The workflow uses a separate `github-pages` environment and never invokes
the PyPI publishing jobs.

The paper link points to `public/assets/dcp-paper.pdf`, the public manuscript
copied from the paper workspace's `paper/arxiv/manuscript.pdf`. Update this
asset after a new public manuscript build. Once an arXiv identifier is
assigned, add its real abstract URL and eprint metadata to `index.html` and
the citation. The current entry is honestly labeled a public preprint.
The PDF's title page links back to this homepage alongside the two PyPI
packages and the GitHub repository. The homepage's package strip uses larger
PyPI-branded buttons for direct installation entry points.
The paper's homepage button is also available independently as
`public/assets/homepage-button.svg`, `.pdf`, and `.png`. The navy-violet artwork
uses vector gradients and a beveled D mark; the standalone SVG embeds Inter
and its license, and the PNG is a preview rendered from the vector PDF.

The hero constellation illustrates research iteration; it is decorative
protocol geometry rather than experimental measurements. Result cards use
the existing SQLite-Web and virtual-catalyst certificates. Keep each task's
model and score meaning beside its numbers. The task-specific runners
produced these records; the public harness is the reusable capture interface.

Fonts are self-hosted Inter and EB Garamond under their bundled SIL Open Font
Licenses. The GitHub mark is distributed under the bundled Octicons MIT
license. The page sends no analytics, model requests, or credentials and
loads no third-party runtime scripts. The original paper retains its own
publication licensing; the repository's Apache-2.0 license covers code.
