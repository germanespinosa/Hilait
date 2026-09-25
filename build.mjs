import {build} from 'esbuild';
import {copyFile, mkdir} from 'node:fs/promises';
await build({entryPoints:['src/hilait/static/terminal-entry.js'],bundle:true,minify:true,format:'iife',target:['es2022'],outfile:'src/hilait/static/vendor/xterm.js'});
await mkdir('src/hilait/static/fonts', {recursive:true});
for (const subset of ['latin', 'latin-ext']) {
  for (const weight of [400, 700]) {
    const name = `jetbrains-mono-${subset}-${weight}-normal.woff2`;
    await copyFile(`node_modules/@fontsource/jetbrains-mono/files/${name}`, `src/hilait/static/fonts/${name}`);
  }
}
await copyFile('node_modules/@fontsource/jetbrains-mono/LICENSE', 'licenses/jetbrains-mono-OFL.txt');
