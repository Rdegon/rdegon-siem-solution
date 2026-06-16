const esbuild = require("esbuild");
const path = require("path");
const fs = require("fs");

const root = __dirname;
const outdir = path.join(root, "dist");
const assetsDir = path.join(outdir, "assets");
const brandDir = path.join(root, "src", "assets", "brand");
const brandAssetVersion = "20260327j";
const shouldMinify = process.env.SIEM_SHELL_MINIFY !== "false";
const shouldGenerateSourceMaps = process.env.SIEM_SHELL_SOURCEMAP !== "false";

if (fs.existsSync(outdir)) {
  fs.rmdirSync(outdir, { recursive: true });
}
fs.mkdirSync(outdir, { recursive: true });

esbuild
  .build({
    entryPoints: {
      app: path.join(root, "src", "main.tsx"),
    },
    bundle: true,
    sourcemap: shouldGenerateSourceMaps,
    minify: shouldMinify,
    splitting: true,
    format: "esm",
    target: ["chrome96", "firefox96", "safari15"],
    outdir: assetsDir,
    entryNames: "[name]-[hash]",
    chunkNames: "chunks/[name]-[hash]",
    assetNames: "[name]-[hash]",
    jsx: "automatic",
    loader: {
      ".ts": "ts",
      ".tsx": "tsx",
      ".css": "css",
      ".ttf": "file",
      ".svg": "file"
    },
    define: {
      "process.env.NODE_ENV": "\"production\""
    }
  })
  .then(() => {
    const builtAssets = fs.readdirSync(assetsDir);
    const jsFile = builtAssets.find((name) => /^app-.*\.js$/.test(name));
    const cssFile = builtAssets.find((name) => /^app-.*\.css$/.test(name));
    if (!jsFile || !cssFile) {
      throw new Error("Unable to locate built React shell assets");
    }
    fs.copyFileSync(path.join(brandDir, "favicon.svg"), path.join(outdir, "favicon.svg"));
    fs.copyFileSync(path.join(brandDir, "favicon.ico"), path.join(outdir, "favicon.ico"));
    fs.copyFileSync(path.join(brandDir, "mark.svg"), path.join(outdir, "mark.svg"));
    const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#06111d" />
    <title>Rdegon Sentinel</title>
    <link rel="icon" type="image/x-icon" href="/app/favicon.ico?v=${brandAssetVersion}" sizes="any" />
    <link rel="icon" type="image/svg+xml" href="/app/favicon.svg?v=${brandAssetVersion}" />
    <link rel="shortcut icon" type="image/x-icon" href="/app/favicon.ico?v=${brandAssetVersion}" />
    <link rel="apple-touch-icon" href="/app/favicon.ico?v=${brandAssetVersion}" />
    <link rel="stylesheet" href="/app/assets/${cssFile}" />
    <script type="module" src="/app/assets/${jsFile}"></script>
  </head>
  <body>
    <div id="root">
      <div class="react-bootstrap-error">
        <div class="react-bootstrap-error-card">
          <div class="react-top-kicker">Rdegon Sentinel</div>
          <h1>Loading operator workspace</h1>
          <p>Preparing the /app control plane. If this screen stays visible, refresh the workspace and sign in again.</p>
          <div class="react-actions react-wrap">
            <a class="react-link-button" href="/auth/login">Login</a>
            <a class="react-link-button" href="/app">Open /app</a>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>`;
    fs.writeFileSync(path.join(outdir, "index.html"), html, "utf8");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
