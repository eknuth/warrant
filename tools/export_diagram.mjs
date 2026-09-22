// Exports a standalone SVG or PNG from a delivered archify diagram HTML,
// used by `make diagrams` (see the Makefile and docs/diagrams/diagrams.txt).
//
// archify's CLI (bin/archify.mjs) renders HTML but has no `export svg` or
// `export png` subcommand; the SVG/PNG downloads live entirely in the
// delivered page's own viewer JavaScript (references/viewer-runtime.md:
// "export menu ... download full-diagram PNG ... download a dual-theme
// SVG"), behind a click on the export menu. This script drives archify's
// own bundled headless-Chrome driver (bin/visual-check.mjs's
// ChromeVisualBrowser) to load the page and call that same in-page
// function for SVG -- `Archify.exportMenu.run('svg')` -- so the SVG is
// exactly what a person clicking "Download SVG" in that page would get,
// not a reimplementation of it.
//
// PNG is not that. The real 'png' export rasterizes at up to 4x scale for
// on-screen crispness, which for a tall diagram can produce a file larger
// than this project wants to commit, and it is never called here. Instead
// this script takes the genuine SVG bytes captured above and rasterizes
// them itself, at natural (1x) size, with a plain canvas (new Image() from
// a blob: URL of the SVG, drawImage, canvas.toBlob) -- the same technique
// archify's own rasterize() uses internally, just run here at a smaller
// scale rather than through `Archify.exportMenu.run('png')`.
//
// Theme: `Archify.exportMenu.run('svg')` always emits a dual-theme SVG
// whose *base* `:root, svg { ... }` rule is dark and whose
// `@media (prefers-color-scheme: light)` block is the override --
// hardcoded in archify's own template (assets/template.html: "Dual-theme
// SVG. Dark is the default ... light swaps in via media query"), not a
// `meta` field or export option this project can pass in. Committed on
// GitHub, that base-dark SVG follows the *reader's* OS color-scheme rather
// than GitHub's own light page chrome, so a reader on dark-mode macOS gets
// a black diagram panel dropped into a white README. `lightFirstSvg()`
// below swaps the two blocks after capture -- base becomes light, dark
// moves under `@media (prefers-color-scheme: dark)` -- on the genuine
// captured SVG text, not a re-render, so every other rule (per-preset
// blocks, the explicit `svg[data-theme="light"|"dark"]` overrides) is
// untouched. PNG then rasterizes that already-light-first SVG under
// headless Chrome's unmodified (light) preference, so it needs no
// `Emulation.setEmulatedMedia` override to match: the SVG is light-first,
// so the PNG just is.
//
// Usage: node tools/export_diagram.mjs <archify_root> <input.html> <output.(svg|png)> [svg|png]
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , archifyRoot, htmlPath, outPath, format] = process.argv;
if (!archifyRoot || !htmlPath || !outPath) {
  console.error('usage: export_diagram.mjs <archify_root> <input.html> <output.(svg|png)> [svg|png]');
  process.exit(2);
}
const fmt = format || (outPath.endsWith('.png') ? 'png' : 'svg');

// Swaps archify's hardcoded dark-base / light-override dual-theme block for
// a light-base / dark-override one, so the SVG matches GitHub's (light)
// page chrome by default and only goes dark under the reader's own
// `prefers-color-scheme: dark`. Operates on the exact two `:root, svg { ... }`
// var blocks the exporter writes (assets/template.html's `autoTheme` path);
// everything else in the document (per-preset rules, the explicit
// `svg[data-theme="..."]` overrides) is left as captured.
function lightFirstSvg(svgString) {
  const baseRe = /:root, svg \{ ([^}]*) \}/;
  const lightMediaRe = /@media \(prefers-color-scheme: light\) \{ :root, svg \{ ([^}]*) \} \}/;
  const baseMatch = svgString.match(baseRe);
  const lightMediaMatch = svgString.match(lightMediaRe);
  if (!baseMatch || !lightMediaMatch) {
    throw new Error(
      'lightFirstSvg: could not find the expected dual-theme :root rules to flip -- ' +
      'archify may have changed its export template',
    );
  }
  const darkVars = baseMatch[1];
  const lightVars = lightMediaMatch[1];
  return svgString
    .replace(baseRe, `:root, svg { ${lightVars} }`)
    .replace(lightMediaRe, `@media (prefers-color-scheme: dark) { :root, svg { ${darkVars} } }`);
}

const visualCheckPath = path.join(path.resolve(archifyRoot), 'bin', 'visual-check.mjs');
const { ChromeVisualBrowser, findChrome } = await import(pathToFileURL(visualCheckPath).href);

const chrome = findChrome();
if (!chrome) {
  console.error('Chrome not available (checked ARCHIFY_CHROME, then the usual install paths).');
  process.exit(1);
}

const browser = new ChromeVisualBrowser(chrome);
try {
  await browser.inspect({
    artifactPath: path.resolve(htmlPath),
    width: 1440,
    height: 900,
    theme: 'dark',
  });
  const sessionId = await browser.sessionPromise;

  const captureSvgExpr = `(async () => {
    let captured = null;
    const orig = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => { captured = blob; return orig(blob); };
    await Archify.exportMenu.run('svg');
    if (!captured) throw new Error('no blob captured from exportMenu.run(svg)');
    return await captured.text();
  })()`;
  const svgResponse = await browser.cdp.send('Runtime.evaluate', {
    expression: captureSvgExpr,
    returnByValue: true,
    awaitPromise: true,
  }, sessionId);
  if (svgResponse.exceptionDetails) {
    throw new Error(svgResponse.exceptionDetails.exception?.description || svgResponse.exceptionDetails.text);
  }
  const svgString = lightFirstSvg(svgResponse.result.value);

  if (fmt === 'svg') {
    fs.writeFileSync(outPath, svgString + '\n');
    console.log(JSON.stringify({ ok: true, output: outPath, bytes: Buffer.byteLength(svgString) }));
  } else if (fmt === 'png') {
    // No color-scheme emulation needed: svgString is already light-first,
    // so headless Chrome's unmodified (light) preference already matches it.
    const rasterExpr = `(async () => {
      const svgString = ${JSON.stringify(svgString)};
      const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
      const svgUrl = URL.createObjectURL(svgBlob);
      try {
        const img = new Image();
        const loaded = new Promise((resolve, reject) => {
          img.onload = resolve;
          img.onerror = reject;
        });
        img.src = svgUrl;
        await loaded;
        const canvas = document.createElement('canvas');
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const blob = await new Promise((resolve, reject) => {
          canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('toBlob returned null'))), 'image/png');
        });
        const buf = await blob.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
      } finally {
        URL.revokeObjectURL(svgUrl);
      }
    })()`;
    const pngResponse = await browser.cdp.send('Runtime.evaluate', {
      expression: rasterExpr,
      returnByValue: true,
      awaitPromise: true,
    }, sessionId);
    if (pngResponse.exceptionDetails) {
      throw new Error(pngResponse.exceptionDetails.exception?.description || pngResponse.exceptionDetails.text);
    }
    const buffer = Buffer.from(pngResponse.result.value, 'base64');
    fs.writeFileSync(outPath, buffer);
    console.log(JSON.stringify({ ok: true, output: outPath, bytes: buffer.length }));
  } else {
    throw new Error('unknown format: ' + fmt);
  }
} finally {
  await browser.close();
}
