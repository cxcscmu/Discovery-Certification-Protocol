import assert from "node:assert/strict";
import http from "node:http";
import { readFile, mkdir, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const publicDir = path.join(root, "public");
const output = path.join(root, "test-output");
await mkdir(output, { recursive: true });
const prefix = "/Discovery-Certification-Protocol/";
const mime = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".pdf": "application/pdf",
  ".woff2": "font/woff2",
  ".otf": "font/otf",
};
const server = http.createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(
      new URL(request.url, "http://localhost").pathname,
    );
    if (!pathname.startsWith(prefix)) throw Error("Wrong base path");
    const relative = pathname.slice(prefix.length) || "index.html";
    const file = path.resolve(publicDir, relative);
    if (!file.startsWith(`${publicDir}/`)) throw Error("Invalid path");
    const contents = await readFile(file);
    response.writeHead(200, {
      "Content-Type": mime[path.extname(file)] || "text/plain",
    });
    response.end(contents);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const local = `http://127.0.0.1:${server.address().port}`;
const base = `${local}${prefix}`;
const browser = await chromium.launch({ headless: true });
const errors = [];
const results = [];

try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    deviceScaleFactor: 1,
    permissions: ["clipboard-read", "clipboard-write"],
  });
  const page = await context.newPage();
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("response", (response) => {
    if (response.status() >= 400)
      errors.push(`${response.status()} ${response.url()}`);
  });
  await page.goto(base, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  assert.equal(await page.locator("h1").count(), 1);
  assert.equal(await page.locator(".canvas-ready").count(), 1);

  // All local resources and anchor targets must resolve under a project-site base path.
  const targets = await page
    .locator("a")
    .evaluateAll((links) => links.map((link) => link.getAttribute("href")));
  for (const target of new Set(targets)) {
    if (target.startsWith("#"))
      assert.equal(
        await page.locator(`[id="${target.slice(1)}"]`).count(),
        1,
        target,
      );
    else if (!target.startsWith("http"))
      assert.equal(
        (await context.request.get(new URL(target, base).href)).status(),
        200,
        target,
      );
  }
  assert.ok(targets.includes("https://pypi.org/project/dcp-audit/"));
  assert.ok(targets.includes("https://pypi.org/project/dcp-harness/"));
  assert.ok(
    !targets.some((target) =>
      /XXXX|latest\/download|javascript:/i.test(target),
    ),
  );
  assert.ok(
    (await stat(path.join(publicDir, "assets/dcp-paper.pdf"))).size > 100000,
  );

  // Compare displayed numerical values directly with the existing frozen records.
  for (const name of ["sqlite-web", "virtual-catalyst"]) {
    const certificate = JSON.parse(
      await readFile(
        path.join(root, `../examples/audits/${name}/payload/certificate.json`),
        "utf8",
      ),
    );
    const card = page.locator(`[data-case="${name}"]`);
    assert.equal(
      await card.locator("[data-value=main]").textContent(),
      certificate.validity.x.toFixed(3),
    );
    assert.equal(
      await card.locator("[data-value=baseline]").textContent(),
      (certificate.validity.x - certificate.validity.effect_mean).toFixed(3),
    );
    assert.equal(certificate.verdict.core, "certified");
    assert.equal(certificate.verdict.evidence, "certified");
    assert.equal(certificate.feedback_test.n_pairs_analyzed, 30);
    assert.equal(certificate.feedback_test.effect_mean, 1);
    assert.equal(certificate.feedback_test.neutral_recovery.admissible_hits, 0);
    assert.equal(certificate.no_feedback_recovery.n_ind, 96);
    assert.equal(certificate.no_feedback_recovery.admissible_hits, 0);
    assert.equal(certificate.no_feedback_recovery.positive_control.successes, 45);
    assert.equal(certificate.no_feedback_recovery.positive_control.trials, 45);
    assert.equal(certificate.feedback_test.sham_n, 60);
    assert.equal(certificate.feedback_test.sham_adequacy, "pass");
    assert.equal(certificate.no_feedback_recovery.p_upper.toFixed(4), "0.0468");
  }

  await page.locator("[data-stage=feedback]").click();
  assert.match(
    await page.locator("#scene-description").textContent(),
    /paired controls/,
  );
  assert.equal(
    await page.locator("[data-stage=feedback]").getAttribute("aria-pressed"),
    "true",
  );
  await page.locator("[data-stage=start]").click();
  await page.locator("#tab-python").click();
  assert.equal(await page.locator("#code-replay").isVisible(), false);
  assert.equal(await page.locator("#code-python").isVisible(), true);
  await page.locator("#tab-python").press("ArrowRight");
  assert.equal(await page.locator("#code-capture").isVisible(), true);
  await page.locator("#tab-capture").press("Home");
  assert.equal(await page.locator("#code-replay").isVisible(), true);
  await page.locator("[data-copy=snippet-replay]").click();
  assert.match(
    await page.evaluate(() => navigator.clipboard.readText()),
    /dcp verify examples\/audits\/sqlite-web/,
  );
  await page.locator("[data-copy=citation]").click();
  assert.match(
    await page.evaluate(() => navigator.clipboard.readText()),
    /ning2026dcp/,
  );

  // Motion controls and live canvas activity are tested separately from the static screenshots.
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(700);
  const before = await page
    .locator("canvas")
    .evaluate((canvas) => canvas.toDataURL());
  await page.waitForTimeout(160);
  const after = await page
    .locator("canvas")
    .evaluate((canvas) => canvas.toDataURL());
  assert.notEqual(before, after, "Canvas should animate in view");
  await page.locator(".motion-toggle").click();
  const paused = await page
    .locator("canvas")
    .evaluate((canvas) => canvas.toDataURL());
  await page.waitForTimeout(180);
  assert.equal(
    paused,
    await page.locator("canvas").evaluate((canvas) => canvas.toDataURL()),
    "Motion pause must stop animation",
  );

  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: width < 600 ? 844 : 1000 });
    await page.evaluate(() => {
      document
        .querySelectorAll(".reveal")
        .forEach((el) => el.classList.add("is-visible"));
      window.scrollTo(0, 0);
    });
    await page.waitForTimeout(180);
    const layout = await page.evaluate(() => {
      const overflow = document.documentElement.scrollWidth > innerWidth + 1;
      const nodes = [...document.querySelectorAll(".orbit-node")].map((el) => ({
        name: el.dataset.stage,
        rect: el.getBoundingClientRect(),
      }));
      const overlaps = [];
      for (let i = 0; i < nodes.length; i++)
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i].rect,
            b = nodes[j].rect;
          if (
            Math.min(a.right, b.right) > Math.max(a.left, b.left) &&
            Math.min(a.bottom, b.bottom) > Math.max(a.top, b.top)
          )
            overlaps.push(`${nodes[i].name}/${nodes[j].name}`);
        }
      const clipped = [
        ...document.querySelectorAll(
          ".orbit-node,.hero-actions>a,.case-card,.nav-paper",
        ),
      ]
        .filter((el) => {
          const r = el.getBoundingClientRect();
          return r.left < -0.5 || r.right > innerWidth + 0.5;
        })
        .map((el) => el.className);
      return { overflow, overlaps, clipped };
    });
    assert.equal(layout.overflow, false, `Horizontal overflow at ${width}`);
    assert.deepEqual(layout.overlaps, [], `Overlapping nodes at ${width}`);
    assert.deepEqual(layout.clipped, [], `Clipped content at ${width}`);
    await page.screenshot({
      path: path.join(output, `homepage-${width}.png`),
      fullPage: true,
    });
    if (width === 1440) {
      // Screenshot rendering can temporarily enlarge the viewport for tall
      // sections; avoid a retained focused control in presentation previews.
      await page.evaluate(() => document.activeElement?.blur());
      await page.screenshot({ path: path.join(output, "hero-desktop.png") });
      for (const id of ["protocol", "evidence", "start", "paper"]) {
        await page.locator(`#${id}`).screenshot({ path: path.join(output, `${id}-desktop.png`) });
      }
    }
    if (width === 390) {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: path.join(output, "hero-mobile.png") });
    }
    results.push({ width, ...layout });
  }

  const reduced = await browser.newContext({
    reducedMotion: "reduce",
    viewport: { width: 390, height: 844 },
  });
  const reducedPage = await reduced.newPage();
  await reducedPage.goto(base, { waitUntil: "networkidle" });
  assert.equal(
    await reducedPage.locator(".motion-toggle").getAttribute("aria-pressed"),
    "true",
  );
  assert.equal(
    await reducedPage
      .locator(".reveal")
      .first()
      .evaluate((el) => getComputedStyle(el).opacity),
    "1",
  );
  await reduced.close();

  const noJS = await browser.newContext({
    javaScriptEnabled: false,
    viewport: { width: 390, height: 844 },
  });
  const noJSPage = await noJS.newPage();
  await noJSPage.goto(base);
  assert.equal(
    await noJSPage
      .locator(".reveal")
      .first()
      .evaluate((el) => getComputedStyle(el).opacity),
    "1",
  );
  assert.equal(await noJSPage.locator("[data-case]").count(), 2);
  await noJS.close();

  const share = await browser.newPage({
    viewport: { width: 1200, height: 760 },
    reducedMotion: "reduce",
  });
  await share.goto(base, { waitUntil: "networkidle" });
  await share.evaluate(() => document.fonts.ready);
  await share.screenshot({
    path: path.join(publicDir, "assets/social-preview.png"),
    clip: { x: 0, y: 0, width: 1200, height: 630 },
  });
  await share.close();
  assert.deepEqual(errors, [], "Browser errors");
  await writeFile(
    path.join(output, "checks.json"),
    JSON.stringify(
      {
        passed: true,
        responsive: results,
        browserErrors: errors,
        copiedCommands: true,
        evidenceValues: true,
        reducedMotion: true,
        noJavaScript: true,
      },
      null,
      2,
    ),
  );
  console.log(
    "PASS · 5 viewports · project-path links · frozen result values · copy/tabs · animated/paused/reduced motion · no-JS content",
  );
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
