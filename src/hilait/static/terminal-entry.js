import {Terminal} from '@xterm/xterm';
import {FitAddon} from '@xterm/addon-fit';
import {SearchAddon} from '@xterm/addon-search';
import {Unicode11Addon} from '@xterm/addon-unicode11';
import {UnicodeGraphemesAddon} from '@xterm/addon-unicode-graphemes';

const terminalTheme = {background:'#000000',foreground:'#e8f0ec',cursor:'#e8f0ec',selectionBackground:'#31594b',black:'#121a16',red:'#ff9998',green:'#8fd1aa',yellow:'#e5c681',blue:'#92b9ef',magenta:'#d3a7e4',cyan:'#8bd1d0',white:'#e8f0ec',brightBlack:'#8fa9a0'};
const terminalFonts = {
  jetbrains:'"Hilait Mono", ui-monospace, monospace',
  system:'ui-monospace, "Cascadia Mono", "SFMono-Regular", Consolas, monospace',
  consolas:'Consolas, ui-monospace, monospace',
  courier:'"Courier New", ui-monospace, monospace'
};
const terminalAppearance = {
  get font(){const value=localStorage.getItem('hilait-terminal-font');return terminalFonts[value]?value:'jetbrains';},
  get size(){const value=Number(localStorage.getItem('hilait-terminal-size'));return Number.isInteger(value)&&value>=10&&value<=24?value:14;},
  set(font,size){if(!terminalFonts[font]||!Number.isInteger(size)||size<10||size>24)return;localStorage.setItem('hilait-terminal-font',font);localStorage.setItem('hilait-terminal-size',String(size));dispatchEvent(new CustomEvent('hilait-terminal-appearance-change'));}
};
window.HilaitTerminalAppearance=terminalAppearance;

class HilaitTerminal {
  constructor(element) {
    this.element = element;
    this.disposed = false;
    this.opened = false;
    this.fitFrame = 0;
    this.term = new Terminal({allowProposedApi:true,fontFamily:terminalFonts[terminalAppearance.font],fontSize:terminalAppearance.size,fontWeight:400,fontWeightBold:700,lineHeight:1.12,letterSpacing:0,cursorBlink:true,scrollback:20000,screenReaderMode:true,
      theme:terminalTheme});
    this._appearanceListener=()=>{this.term.options.fontFamily=terminalFonts[terminalAppearance.font];this.term.options.fontSize=terminalAppearance.size;this.scheduleFit();};
    addEventListener('hilait-terminal-appearance-change',this._appearanceListener);
    this.fitAddon = new FitAddon(); this.searchAddon = new SearchAddon();
    this.term.loadAddon(this.fitAddon); this.term.loadAddon(this.searchAddon); this.term.loadAddon(new Unicode11Addon()); this.term.loadAddon(new UnicodeGraphemesAddon()); this.term.unicode.activeVersion='11';
    this.term.onData(data=>this.onInput?.(data)); this.term.onBinary(data=>this.onBinary?.(btoa(data)));
    this.term.onResize(({cols,rows})=>this.onResize?.(cols,rows));
    this.term.attachCustomKeyEventHandler(e=>this._keys(e));
    this.ready = document.fonts.load('400 14px "Hilait Mono"').catch(()=>[]).then(()=>{
      if(this.disposed)return;
      this.term.open(element);
      this.opened=true;
      this.element.addEventListener('contextmenu',this._context=e=>{e.preventDefault();this._menu(e);});
      this.observer=new ResizeObserver(()=>this.scheduleFit()); this.observer.observe(element);
      this.fit();
    });
  }
  _keys(e){
    if(e.type!=='keydown'||!e.ctrlKey||e.altKey||e.metaKey||e.isComposing)return true;
    if(e.code==='KeyC'&&(e.shiftKey||this.term.hasSelection())){e.preventDefault();this.copy();return false;}
    if(e.code==='KeyV'){e.preventDefault();this.paste();return false;}
    if(e.code==='KeyF'){e.preventDefault();const query=prompt('Find in terminal');if(query)this.searchAddon.findNext(query);return false;}
    if(e.code==='KeyU'){e.preventDefault();this.term.unicode.activeVersion=this.term.unicode.activeVersion==='11'?'15-graphemes':'11';this.onStatus?.('Unicode width: '+this.term.unicode.activeVersion);return false;}
    if(e.key==='+'||e.key==='='||e.code==='NumpadAdd'){e.preventDefault();terminalAppearance.set(terminalAppearance.font,Math.min(24,terminalAppearance.size+1));return false;}
    if(e.key==='-'||e.code==='NumpadSubtract'){e.preventDefault();terminalAppearance.set(terminalAppearance.font,Math.max(10,terminalAppearance.size-1));return false;}
    return true;
  }
  _menu(e){const existing=document.querySelector('.terminal-context');existing?.remove();const box=document.createElement('div');box.className='context-menu terminal-context';box.style.left=e.clientX+'px';box.style.top=e.clientY+'px';for(const [label,callback] of [['Copy',()=>this.copy()],['Paste',()=>this.paste()]]){const button=document.createElement('button');button.textContent=label;button.onclick=()=>{box.remove();callback();};box.appendChild(button);}document.body.appendChild(box);setTimeout(()=>document.addEventListener('click',()=>box.remove(),{once:true}),0);}
  async copy(){const selection=this.term.getSelection();if(selection)await navigator.clipboard.writeText(selection);}
  async paste(){try{const text=await navigator.clipboard.readText();if(text.includes('\n')&&!confirm('Paste multiple lines into the remote terminal? They may execute commands.'))return;this.term.paste(text);}catch{this.onStatus?.('Clipboard access was denied by the browser.');}}
  scheduleFit(){if(this.fitFrame||this.disposed)return;this.fitFrame=requestAnimationFrame(()=>{this.fitFrame=0;this.fit();});}
  fit(){if(this.opened&&this.element.clientWidth>0&&this.element.clientHeight>0)this.fitAddon.fit();}
  focus(){this.term.focus();}
  columns(){return this.term.cols;}
  rows(){return this.term.rows;}
  write(base64){if(base64)this.term.write(Uint8Array.from(atob(base64),char=>char.charCodeAt(0)));}
  screen(){const buffer=this.term.buffer.active;return {columns:this.term.cols,rows:this.term.rows,cursorX:buffer.cursorX,cursorY:buffer.cursorY,buffer:buffer.type,
    lines:Array.from({length:this.term.rows},(_,row)=>buffer.getLine(buffer.baseY+row)?.translateToString(true)??'')};}
  dispose(){this.disposed=true;if(this.fitFrame)cancelAnimationFrame(this.fitFrame);this.observer?.disconnect();if(this._context)this.element.removeEventListener('contextmenu',this._context);removeEventListener('hilait-terminal-appearance-change',this._appearanceListener);this.term.dispose();}
}
window.HilaitTerminal=HilaitTerminal;
