import {build} from 'esbuild';
import {copyFile, mkdir, readFile} from 'node:fs/promises';

// The workspace CSP is style-src 'self'. xterm's DOM renderer applies 24-bit
// ("truecolor") colours and minimum-contrast colours with
// setAttribute('style', ...), which that policy blocks, so those colours were
// silently dropped. Rewrite that one helper to use CSSOM (element.style),
// which CSP does not govern. Fail the build if xterm changes the helper.
const cspSafeXterm = {
  name: 'csp-safe-xterm',
  setup(builder) {
    builder.onLoad({filter: /@xterm[\\/]xterm[\\/]lib[\\/]xterm\.mjs$/}, async args => {
      const source = await readFile(args.path, 'utf8');
      const pattern = /_addStyle\((\w+),(\w+)\)\{\1\.setAttribute\("style",`\$\{\1\.getAttribute\("style"\)\|\|""\}\$\{\2\};`\)\}/;
      if (!pattern.test(source)) throw new Error('xterm _addStyle changed: update the CSP patch in build.mjs');
      return {contents: source.replace(pattern, '_addStyle($1,$2){$1.style.cssText+=`${$2};`}'), loader: 'js'};
    });
  },
};

await build({entryPoints:['src/hilait/static/terminal-entry.js'],bundle:true,minify:true,format:'iife',target:['es2022'],outfile:'src/hilait/static/vendor/xterm.js',plugins:[cspSafeXterm]});
await mkdir('src/hilait/static/fonts', {recursive:true});
for (const subset of ['latin', 'latin-ext']) {
  for (const weight of [400, 700]) {
    const name = `jetbrains-mono-${subset}-${weight}-normal.woff2`;
    await copyFile(`node_modules/@fontsource/jetbrains-mono/files/${name}`, `src/hilait/static/fonts/${name}`);
  }
}
await copyFile('node_modules/@fontsource/jetbrains-mono/LICENSE', 'licenses/jetbrains-mono-OFL.txt');
for (const subset of ['latin', 'latin-ext']) {
  const name = `inter-${subset}-wght-normal.woff2`;
  await copyFile(`node_modules/@fontsource-variable/inter/files/${name}`, `src/hilait/static/fonts/${name}`);
}
await copyFile('node_modules/@fontsource-variable/inter/LICENSE', 'licenses/inter-OFL.txt');
