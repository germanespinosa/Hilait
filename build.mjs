import {build} from 'esbuild';
await build({entryPoints:['src/hilait/static/terminal-entry.js'],bundle:true,minify:true,format:'iife',target:['es2022'],outfile:'src/hilait/static/vendor/xterm.js'});
