(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const escaped = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  let token = sessionStorage.getItem('hilait-token') || '';
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.get('token')) { token = fragment.get('token'); sessionStorage.setItem('hilait-token', token); history.replaceState(null, '', location.pathname); }
  let state = null, selectedProfile = null, selectedSession = null, terminal = null, terminalSocket = null, eventsSocket = null, currentFile = null, currentFilePath = '/', contextMenu = null;
  let draggedMachine = null, dragPlaceholder = null;

  function status(message) { $('#status').textContent = message; }
  function toast(message, bad = false) { const box = $('#toast'); box.textContent = message; box.classList.remove('hidden'); box.style.borderColor = bad ? 'var(--danger)' : 'var(--accent)'; setTimeout(() => box.classList.add('hidden'), 4800); }
  async function api(path, method = 'GET', body) {
    const headers = {...(path.startsWith('/api/auth/') ? {} : {'Authorization': 'Bearer ' + token}), ...(body === undefined ? {} : {'Content-Type': 'application/json'})};
    const response = await fetch(path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(data.error || data.detail?.message || data.detail || `Request failed (${response.status})`); error.details = data; throw error; }
    return data;
  }
  async function refresh() { state = await api('/api/state'); if (selectedProfile && !state.profiles.some(p => p.id === selectedProfile)) selectedProfile = null; if (selectedSession && !state.sessions.some(s => s.id === selectedSession)) selectedSession = null; render(); }
  async function action(task) { try { await task(); await refresh(); } catch (error) { if (error.details?.fingerprint) { showHostKey(error.details, task); return; } toast(error.message, true); status(error.message); } }
  let modalReturnFocus = null;
  function openModal(markup, narrow = false) { const modal = $('#modal'); if ($('#modal-backdrop').classList.contains('hidden')) modalReturnFocus = document.activeElement; modal.innerHTML = markup; modal.classList.toggle('narrow', narrow); $('#modal-backdrop').classList.remove('hidden'); modal.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click', closeModal)); requestAnimationFrame(() => modal.querySelector('button, input, select, textarea')?.focus()); }
  function closeModal() { $('#modal-backdrop').classList.add('hidden'); $('#modal').innerHTML = ''; modalReturnFocus?.focus(); modalReturnFocus = null; }
  function head(title, subtitle = '') { return `<div class="modal-header"><div><h2 id="modal-title">${escaped(title)}</h2>${subtitle ? `<p>${escaped(subtitle)}</p>` : ''}</div><button class="text-button" data-close aria-label="Close">×</button></div>`; }
  function field(label, name, value = '', type = 'text', extra = '') { return `<label>${escaped(label)}<input name="${name}" type="${type}" value="${escaped(value)}" ${extra}></label>`; }
  function formData(form) { return Object.fromEntries(new FormData(form).entries()); }
  function selectedMachine() { return state?.profiles.find(p => p.id === selectedProfile); }
  function selectedConnection() { return state?.sessions.find(s => s.id === selectedSession); }
  function menu(items, x, y) { contextMenu?.remove(); contextMenu = document.createElement('div'); contextMenu.className = 'context-menu'; contextMenu.style.left = Math.min(x, innerWidth - 220) + 'px'; contextMenu.style.top = Math.min(y, innerHeight - 230) + 'px'; for (const [label, callback] of items) { const button = document.createElement('button'); button.textContent = label; button.onclick = () => { contextMenu.remove(); contextMenu = null; callback(); }; contextMenu.appendChild(button); } document.body.appendChild(contextMenu); }
  document.addEventListener('click', event => { if (contextMenu && !contextMenu.contains(event.target)) { contextMenu.remove(); contextMenu = null; } });

  function render() {
    renderMachines(); renderSessions(); renderSelected();
    const requestForm = $('#request-form');
    if (requestForm && !state.grants.some(grant => grant.access === requestForm.dataset.access && grant.state === 'Pending')) closeModal();
    const hasProfiles = state.profiles.length > 0;
    const ready = state.otpEnabled;
    $('#new-profile').disabled = !ready;
    $('#new-profile').title = ready ? 'New connection' : 'Set up an authenticator first';
    $('#welcome-title').textContent = !ready ? 'Set up an authenticator first' : hasProfiles ? (matchMedia('(pointer: coarse)').matches ? 'Tap a machine to connect' : 'Double-click a machine to connect') : 'Add a connection';
    $('#welcome-copy').textContent = ready ? 'Save a machine to start a terminal session.' : 'Your saved connections will be encrypted with its key.';
    $('#welcome-copy').classList.toggle('hidden', ready && hasProfiles);
    $('#welcome-new').textContent = ready ? 'New connection' : 'Set up authenticator';
    $('#welcome-new').classList.toggle('hidden', ready && hasProfiles);
  }
  function renderMachines() {
    const list = $('#machine-list'); list.innerHTML = '';
    const search = $('#search-profiles').value.toLowerCase();
    for (const profile of state.profiles.filter(p => (p.name + ' ' + p.host).toLowerCase().includes(search))) {
      const row = document.createElement('div'); row.className = 'machine' + (selectedProfile === profile.id ? ' selected' : ''); row.draggable = true; row.dataset.id = profile.id; row.tabIndex = 0; row.setAttribute('role','button'); row.setAttribute('aria-label',`Connection ${profile.name}`);
      row.innerHTML = `<strong>${state.sessions.some(s => s.profile === profile.id) ? '<i class="connected-dot"></i>' : ''}${escaped(profile.name)}</strong><small>${escaped(profile.username)}@${escaped(profile.host)}:${profile.port}</small>`;
      row.onclick = () => { if (matchMedia('(pointer: coarse)').matches && !state.sessions.some(s => s.profile === profile.id)) { connect(profile.id); return; } selectedProfile = profile.id; selectedSession = state.sessions.filter(s => s.profile === profile.id).at(-1)?.id || null; render(); };
      row.ondblclick = () => { const existing=state.sessions.filter(item=>item.profile===profile.id).at(-1); existing ? disconnect(existing.id) : connect(profile.id); };
      row.onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); const existing=state.sessions.filter(item=>item.profile===profile.id).at(-1); existing ? disconnect(existing.id) : connect(profile.id); } else if (event.key === ' ') { event.preventDefault(); row.click(); } };
      row.oncontextmenu = event => { event.preventDefault(); selectedProfile = profile.id; render(); menu([...(state.sessions.some(item=>item.profile===profile.id) ? [["Disconnect", () => disconnect(state.sessions.filter(item=>item.profile===profile.id).at(-1).id)], ["New session", () => connect(profile.id)]] : [["Connect", () => connect(profile.id)]]), ["Open in Files", () => { const found = state.sessions.find(s => s.profile === profile.id); if (found) { selectedSession = found.id; render(); showFiles(); } else connect(profile.id); }], ["Edit connection", () => profileDialog(profile)], ["Delete connection", () => deleteProfile(profile)]], event.clientX, event.clientY); };
      row.ondragstart = event => { draggedMachine = profile; event.dataTransfer.effectAllowed = 'move'; event.dataTransfer.setData('text/plain', profile.id); dragPlaceholder = document.createElement('div'); dragPlaceholder.className = 'machine-placeholder'; dragPlaceholder.textContent = profile.name; requestAnimationFrame(() => { row.classList.add('dragging'); row.after(dragPlaceholder); }); };
      row.ondragover = event => { if (!draggedMachine || draggedMachine.id === profile.id) return; event.preventDefault(); const before = event.clientY < row.getBoundingClientRect().top + row.offsetHeight / 2; row.parentNode.insertBefore(dragPlaceholder, before ? row : row.nextSibling); };
      row.ondragend = () => { draggedMachine = null; dragPlaceholder?.remove(); dragPlaceholder = null; row.classList.remove('dragging'); };
      list.appendChild(row);
    }
    list.ondragover = event => { if (draggedMachine) event.preventDefault(); };
    list.ondrop = event => { event.preventDefault(); if (!draggedMachine || !dragPlaceholder) return; const ids = [...list.children].filter(el => el === dragPlaceholder || (el.classList.contains('machine') && el.dataset.id !== draggedMachine.id)).map(el => el === dragPlaceholder ? draggedMachine.id : el.dataset.id); const hidden = state.profiles.map(p => p.id).filter(id => !ids.includes(id)); action(async () => api('/api/profiles/order', 'POST', {ids: [...ids, ...hidden]})); };
  }
  function renderSessions() {
    const list = $('#session-list'); list.innerHTML = '';
    const sessions = state.sessions.filter(s => s.profile === selectedProfile).sort((a, b) => b.createdUtc.localeCompare(a.createdUtc));
    $('#workspace').classList.toggle('no-sessions', sessions.length === 0);
    for (const session of sessions) { const row = document.createElement('div'); row.className = 'session-row' + (selectedSession === session.id ? ' selected' : ''); row.tabIndex = 0; row.setAttribute('role','button'); row.innerHTML = `<strong>${escaped(session.owner === 'You' ? 'Your session' : session.owner)}</strong><small>${new Date(session.createdUtc).toLocaleTimeString([], {hour:'numeric',minute:'2-digit'})} · ${escaped(session.state)}</small><small title="${escaped(session.purpose)}">${escaped(session.purpose)}</small>`; row.onclick = () => { selectedSession = session.id; render(); }; row.onkeydown = event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectedSession = session.id; render(); } }; row.oncontextmenu = event => { event.preventDefault(); menu([["Open files", () => { selectedSession = session.id; render(); showFiles(); }], ["Disconnect", () => disconnect(session.id)]], event.clientX, event.clientY); }; list.appendChild(row); }
  }
  function renderSelected() {
    const session = selectedConnection();
    $('#welcome').classList.toggle('hidden', !!session); $('#session-view').classList.toggle('hidden', !session);
    if (!session) { if (terminalSocket) { terminalSocket.close(); terminalSocket = null; } if (terminal) { terminal.dispose(); terminal = null; } return; }
    $('#terminal-title').textContent = session.connection + ' · ' + session.id.slice(0,6);
    $('#terminal-subtitle').textContent = session.owner + ' · ' + session.purpose;
    const grant = state.grants.find(g => g.session === session.id);
    const strip = $('#agent-strip'); strip.classList.toggle('hidden', !grant);
    if (grant) { strip.innerHTML = `<span>${escaped(grant.agent)} · ${escaped(grant.state)}</span><div class="actions"></div>`; const actions = strip.querySelector('.actions'); for (const [label, kind] of [['Pause','pause'], ['Take over','takeover'], ['Resume','resume'], ['Revoke','revoke']]) { if (kind === 'resume' && grant.state !== 'Paused' || ['pause','takeover'].includes(kind) && grant.state !== 'Approved' || kind === 'revoke' && ['Revoked','Closed'].includes(grant.state)) continue; const button = document.createElement('button'); button.textContent = label; button.onclick = () => action(() => api(`/api/grants/${grant.access}/${kind}`, 'POST', {})); actions.appendChild(button); } }
    if (!terminal || terminal.sessionId !== session.id) openTerminal(session.id);
    if (!$('#files-pane').classList.contains('hidden')) loadFiles();
  }
  async function openTerminal(sessionId) {
    terminalSocket?.close(); terminal?.dispose(); $('#terminal').innerHTML = '';
    const profileId = state.sessions.find(item=>item.id===sessionId)?.profile;
    const platform = state.profiles.find(item=>item.id===profileId)?.platform;
    const current = new window.HilaitTerminal($('#terminal'),platform); current.sessionId = sessionId; terminal = current;
    await current.ready;
    if (terminal !== current || selectedSession !== sessionId) return;
    const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/terminal/${sessionId}?token=${encodeURIComponent(token)}`;
    const socket = new WebSocket(url); terminalSocket = socket;
    socket.onopen = () => { current.fit(); current.focus(); socket.send(JSON.stringify({type:'resize', columns:current.columns(), rows:current.rows()})); };
    socket.onmessage = event => { if (terminal !== current) return; const item = JSON.parse(event.data); if (item.type === 'output') current.write(item.base64); else if (item.type === 'screen_request') socket.send(JSON.stringify({type:'screen_response', id:item.id, screen:current.screen()})); else if (item.type === 'closed') refresh(); };
    current.onInput = data => { if (socket.readyState === 1) socket.send(JSON.stringify({type:'input', text:data})); };
    current.onBinary = base64 => { if (socket.readyState === 1) socket.send(JSON.stringify({type:'input', base64})); };
    current.onResize = (columns, rows) => { if (socket.readyState === 1) socket.send(JSON.stringify({type:'resize', columns, rows})); };
    current.onStatus = status;
  }
  function connect(profileId) { action(async () => { const profile = state.profiles.find(p => p.id === profileId); let secret; if (!profile.has_saved_secret) { secret = prompt(`SSH password or private-key passphrase for ${profile.name} (leave blank for an unencrypted key)`); if (secret === null) return; } const result = await api('/api/sessions', 'POST', {profile:profileId, secret}); selectedProfile = profileId; selectedSession = result.session; status(`Connected · ${profile.name}`); }); }
  function disconnect(sessionId) { if (!confirm('Disconnect this SSH session? Any running foreground command and active file operation may be interrupted.')) return; action(() => api(`/api/sessions/${sessionId}`, 'DELETE')); }
  function deleteProfile(profile) { if (!confirm(`Delete saved connection “${profile.name}”? Saved credentials and permissions for this machine will be removed.`)) return; action(() => api(`/api/profiles/${profile.id}`, 'DELETE')); }
  function showHostKey(details, retry) { openModal(head('Verify server identity', `Compare this fingerprint with a trusted source before connecting to ${details.host}.`) + `<div class="setting-row"><strong>Presented SHA-256 fingerprint</strong><div class="code">${escaped(details.fingerprint)}</div>${details.previous ? `<p class="error">This server key changed. Previously trusted: ${escaped(details.previous)}</p>` : '<p>This server has not been trusted before.</p>'}</div><div class="actions"><button data-close>Cancel</button><button id="trust-host" class="primary">Trust key and connect</button></div>`, true); $('#trust-host').onclick = () => action(async () => { await api('/api/hosts/trust', 'POST', {host:details.host, fingerprint:details.fingerprint}); closeModal(); await retry(); }); }

  function profileDialog(profile) {
    if (!state?.otpEnabled) { if (state) settings('otp'); return; }
    const existing = !!profile; const p = profile || {};
    openModal(head(existing ? 'Edit connection' : 'New connection') + `<form id="profile-form"><div class="form-grid">${field('Name','name',p.name)}${field('Host','host',p.host)}${field('Username','username',p.username)}${field('Port','port',p.port || 22,'number')}${field('Private key path (server)','private_key',p.private_key || '')}<label>Remote platform<select name="platform"><option value="unix">Unix / Linux / macOS</option><option value="windows">Windows SSH</option></select></label><label>Remote shell<select name="shell"><option value="default">Default shell</option><option value="powershell7">PowerShell 7</option><option value="powershell5">Windows PowerShell 5.1</option></select></label>${field('Agent inactivity timeout (minutes)','agent_idle_timeout_minutes',p.agent_idle_timeout_minutes ?? 10,'number')}${field('Save SSH password / key passphrase','secret','','password','autocomplete="new-password"')}${field('Save sudo password','sudo_secret','','password','autocomplete="new-password"')}<label>Sudo approval<select name="sudo_policy"><option value="per_request">Every request</option><option value="per_connection">Once per connection</option><option value="per_authorization">Once per authorization period</option><option value="never">Automatic</option></select></label><label>Agent access<select name="agent_access"><option value="all">All agents, including future agents</option><option value="selected">Selected agents only</option></select></label><div class="full" id="agent-choices">${state.agents.filter(a=>a.active).map(a=>`<label class="toggle setting-row">${escaped(a.name)}<input type="checkbox" value="${escaped(a.id)}" ${p.allowed_agent_ids?.includes(a.id) ? 'checked' : ''}></label>`).join('') || '<small>No agents registered yet.</small>'}</div></div><div class="actions"><button type="button" data-close>Cancel</button><button type="submit" class="primary">Save connection</button></div></form>`);
    const form = $('#profile-form'); form.platform.value = p.platform || 'unix'; form.shell.value = p.shell || 'default'; form.sudo_policy.value = p.sudo_policy || 'per_request'; form.agent_access.value = p.allowed_agent_ids === null || p.allowed_agent_ids === undefined ? 'all' : 'selected';
    const updateChoices = () => $('#agent-choices').classList.toggle('hidden', form.agent_access.value === 'all'); form.agent_access.onchange = updateChoices; updateChoices();
    form.onsubmit = event => { event.preventDefault(); const data = formData(form); data.id = p.id; data.port = Number(data.port); data.agent_idle_timeout_minutes = Number(data.agent_idle_timeout_minutes); data.allowed_agent_ids = data.agent_access === 'all' ? null : [...$('#agent-choices').querySelectorAll('input:checked')].map(el => el.value); delete data.agent_access; if (!data.secret) delete data.secret; if (!data.sudo_secret) delete data.sudo_secret; action(async () => { const saved = await api('/api/profiles', 'POST', data); selectedProfile = saved.id; closeModal(); }); };
  }

  function showFiles() { if (!selectedSession) return; $('#files-pane').classList.remove('hidden'); loadFiles(); }
  function fileExtras(entry, full) { const choices = [["Copy to another session", () => { const available=state.sessions.filter(s=>s.id!==selectedSession); if(!available.length){toast('Open another session first',true);return;} const target=prompt('Destination session ID\n'+available.map(s=>`${s.connection}: ${s.id}`).join('\n'),available[0].id); if(!target||!available.some(s=>s.id===target))return; const destination=prompt('Absolute destination path',full); if(destination)action(async()=>{await api(`/api/sessions/${selectedSession}/copy`,'POST',{direction:'remote',path:full,destination,destinationSession:target});toast('Remote copy completed');}); }]]; const session=selectedConnection(); if(session && state.profiles.find(p=>p.id===session.profile)?.platform!=='windows'){ choices.push(["Change permissions",()=>{const mode=prompt('POSIX mode (octal)',entry.mode?.replace('0o','')||'644');if(mode)action(async()=>{await api(`/api/sessions/${selectedSession}/files`,'POST',{action:'chmod',path:full,mode});await loadFiles();});}]); } return choices; }
  async function loadFiles() { if (!selectedSession || $('#files-pane').classList.contains('hidden')) return; currentFilePath = $('#files-path').value || '/'; try { const result = await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'list',path:currentFilePath}); const list = $('#files-list'); list.innerHTML = ''; for (const entry of result.entries) { const row = document.createElement('div'); row.className = 'file-row'; row.innerHTML = `<span>${entry.directory ? '▣' : entry.symlink ? '↗' : '▤'} ${escaped(entry.name)}</span><small>${entry.directory ? '' : entry.size}</small>`; row.onclick = () => { currentFile = entry; list.querySelectorAll('.file-row').forEach(e=>e.classList.remove('selected')); row.classList.add('selected'); }; row.ondblclick = () => { if (entry.directory) { $('#files-path').value = currentFilePath.replace(/\/$/,'') + '/' + entry.name; loadFiles(); } }; row.oncontextmenu = event => { event.preventDefault(); currentFile = entry; const full = currentFilePath.replace(/\/$/,'') + '/' + entry.name; menu([["Rename", () => { const name = prompt('New name', entry.name); if (name) action(async () => { await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'rename',path:full,destination:currentFilePath.replace(/\/$/,'')+'/'+name}); await loadFiles(); }); }], ["Delete", () => { if (confirm(`Delete “${entry.name}”${entry.directory ? ' and its contents' : ''}?`)) action(async () => { await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'delete',path:full,recursive:true}); await loadFiles(); }); }], ["Copy path", () => navigator.clipboard.writeText(full)], ...fileExtras(entry, full)], event.clientX, event.clientY); }; list.appendChild(row); } } catch (error) { toast(error.message, true); } }
  async function uploadFile(file) { if (!selectedSession) return; const path = currentFilePath.replace(/\/$/,'') + '/' + file.name; let offset = 0; if (file.size === 0) await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'write',path,base64:''}); while (offset < file.size) { const bytes = new Uint8Array(await file.slice(offset, offset + 262144).arrayBuffer()); let raw = ''; bytes.forEach(byte => raw += String.fromCharCode(byte)); await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'write',path,base64:btoa(raw),overwrite:offset > 0,offset}); offset += bytes.length; status(`Uploading ${file.name}: ${Math.round(offset/file.size*100)}%`); } await loadFiles(); status(`Uploaded ${file.name}`); }
  async function downloadFile() { if (!currentFile || currentFile.directory || !selectedSession) return; const path = currentFilePath.replace(/\/$/,'') + '/' + currentFile.name; const pieces = []; for(let offset=0;;){ const result = await api(`/api/sessions/${selectedSession}/files`, 'POST', {action:'read',path,offset,count:262144}); const bytes = Uint8Array.from(atob(result.base64), char=>char.charCodeAt(0)); pieces.push(bytes); offset+=bytes.length; if(bytes.length<262144)break; } const url=URL.createObjectURL(new Blob(pieces)); const a=document.createElement('a'); a.href=url; a.download=currentFile.name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),5000); }

  function settings(tab='agents') { openModal(head('Settings')+`<div class="settings-layout"><nav class="settings-nav" aria-label="Settings sections"><button data-tab="appearance">Appearance</button><button data-tab="agents">Agent Access</button><button data-tab="authorizations">Authorizations</button><button data-tab="review">Activity review</button><button data-tab="notifications">Notifications</button><button data-tab="otp">Authenticator</button></nav><div id="settings-content"></div></div>`); $('#modal .settings-nav').onclick = event => { const next=event.target.dataset.tab; if(next) settingsTab(next); }; settingsTab(tab); }
  function agentAccessSettings(box) {
    const requests=state.tokenRequests||[];
    const setup={mcpServers:{hilait:{command:'hilait',args:['mcp','--server',location.origin]}}};
    box.innerHTML=`<div class="setting-row"><strong>Agent enrollment</strong><p>Give an agent this server URL. It can request a token; you approve the identity and its machines here.</p><code>${escaped(location.origin)}</code><div class="actions"><button id="copy-agent-setup">Copy MCP setup</button></div></div>
      ${requests.length?`<h3>Token requests · ${requests.length}</h3>${requests.map(request=>`<div class="setting-row token-request" data-token-request="${escaped(request.id)}"><strong>${escaped(request.name)}</strong><small>Requested ${escaped(new Date(request.created_utc).toLocaleString())}</small><p>${escaped(request.reason)}</p><div class="token-machine-choices"><strong>Allowed machines</strong><small>None are selected by default. Each connection still needs separate approval.</small>${state.profiles.map(profile=>`<label class="toggle setting-row">${escaped(profile.name)}<input type="checkbox" value="${escaped(profile.id)}"></label>`).join('')||'<p class="empty-message">No machines saved.</p>'}</div><div class="actions"><button data-enrollment-action="reject">Reject</button><button data-enrollment-action="approve" class="primary">Approve agent</button></div></div>`).join('')}`:''}
      <div class="setting-row"><div class="actions"><button id="create-agent" class="primary">Create agent access</button></div></div>
      ${state.agents.length?state.agents.map(a=>`<div class="setting-row" data-agent="${escaped(a.id)}"><strong>${escaped(a.name)} ${a.active?'':'· revoked'}</strong><div class="actions"><button data-agent-action="config">Copy configuration</button><button data-agent-action="permissions">Allowed connections</button><button data-agent-action="revoke">Revoke token</button><button class="danger" data-agent-action="delete">Delete agent access</button></div></div>`).join(''):'<p class="empty-message">No agent access configured.</p>'}`;
    $('#copy-agent-setup').onclick=()=>action(async()=>{await navigator.clipboard.writeText(JSON.stringify(setup,null,2));toast('MCP setup copied');});
    $('#create-agent').onclick=()=>{const name=prompt('Agent access name');if(name)action(async()=>{const result=await api('/api/agents','POST',{name});settings('agents');showConfig(result.config);});};
    box.onclick=e=>{
      const enrollment=e.target.closest('[data-enrollment-action]');
      if(enrollment){const row=enrollment.closest('[data-token-request]'),id=row.dataset.tokenRequest,kind=enrollment.dataset.enrollmentAction;
        if(kind==='reject'&&!confirm('Reject this agent token request?'))return;
        const connection_ids=[...row.querySelectorAll('.token-machine-choices input:checked')].map(input=>input.value);
        action(async()=>{await api(`/api/agent-enrollment/${id}/${kind}`,'POST',kind==='approve'?{connection_ids}:{});await refresh();settingsTab('agents');toast(kind==='approve'?'Agent approved':'Request rejected');});return;}
      const button=e.target.closest('[data-agent-action]');if(!button)return;
      const id=button.closest('[data-agent]').dataset.agent,kind=button.dataset.agentAction;
      if(kind==='config')action(async()=>showConfig(await api(`/api/agents/${id}/config`)));
      if(kind==='permissions')showPermissions(id);
      if(kind==='revoke'&&confirm('Revoke this agent token and its active access?'))action(async()=>{await api(`/api/agents/${id}/revoke`,'POST',{});settings('agents');});
      if(kind==='delete'&&confirm('Delete this agent access and its permissions? Recorded logs remain.'))action(async()=>{await api(`/api/agents/${id}`,'DELETE');settings('agents');});
    };
  }
  function settingsTab(tab) { $('#modal .settings-nav').querySelectorAll('button').forEach(b=>{b.classList.toggle('active',b.dataset.tab===tab);b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false');}); const box=$('#settings-content'); if(tab==='appearance'){appearanceSettings();}
    else if(tab==='agents') { agentAccessSettings(box); }
    else if(tab==='authorizations'){box.innerHTML=`<button id="add-authorization" class="primary">＋ New authorization</button>${state.authorizations.map(a=>`<div class="setting-row"><strong>${escaped(state.agents.find(x=>x.id===a.agent_id)?.name||a.agent_id)} · ${escaped(a.connection)}</strong><small>${a.revoked?'Revoked':new Date(a.expires_utc)<new Date()?'Expired':'Until '+new Date(a.expires_utc).toLocaleString()} · ${escaped(a.file_access)}</small><div class="actions"><button data-extend="${escaped(a.id)}">Extend</button><button data-revoke="${escaped(a.id)}">Revoke</button></div></div>`).join('')}`; $('#add-authorization').onclick=authorizationDialog; box.onclick=e=>{const id=e.target.dataset.extend||e.target.dataset.revoke;if(!id)return;if(e.target.dataset.extend){const hours=Number(prompt('Add how many hours?','1'));if(hours>0)action(async()=>{await api(`/api/authorizations/${id}/extend`,'POST',{hours});settings('authorizations');});}else if(confirm('Revoke this authorization and active agent access?'))action(async()=>{await api(`/api/authorizations/${id}/revoke`,'POST',{});settings('authorizations');});};}
    else if(tab==='otp'){otpSettings();}
    else if(tab==='notifications'){notificationSettings();}
    else {reviewSettings();}
  }
  function reviewSettings(){
    const saved=state.reviewSettings;
    const defaults={local:'http://localhost:11434/v1',openai:'https://api.openai.com/v1',anthropic:'https://api.anthropic.com/v1',grok:'https://api.x.ai/v1'};
    const alertRow=(axis,label)=>`<label>${label}<select name="alert_${axis}"><option value="">Off</option>${Array.from({length:11},(_,score)=>`<option value="${score}">At or below ${score}/10</option>`).join('')}</select></label>`;
    const box=$('#settings-content');
    box.innerHTML=`<form id="review-form">
      <h3 class="settings-heading">Model connection</h3>
      <div class="form-grid">
        <label>Provider<select name="provider"><option value="local">Local / Ollama</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="grok">Grok (xAI)</option></select></label>
        ${field('Server URL','endpoint',saved.endpoint||defaults[saved.provider||'local'],'url','autocomplete="url"')}
        ${field(saved.has_api_key?'API key (saved; leave blank to keep)':'API key','api_key','','password','autocomplete="new-password"')}
        <label>Model<select name="model" id="review-model" disabled></select></label>
      </div>
      <div class="actions review-connect"><button type="button" id="connect-models">Connect and load models</button></div>
      <h3>Review</h3>
      <div class="form-grid">
        <label>Depth<select name="review_level"><option value="light">Light · inputs and prompts</option><option value="deep">Deep · full activity</option></select></label>
        <label>Frequency<select name="mode"><option value="on_demand">On demand</option><option value="automatic">Automatic</option></select></label>
      </div>
      <p class="setting-hint" id="review-depth-hint"></p>
      <h3>Score alerts</h3>
      <p class="setting-hint">Send an ntfy alert when a score meets a threshold. Configure the server and topic in Notifications. Alerts include a brief model summary.</p>
      <div class="form-grid">${alertRow('safety','Safety')}${alertRow('purpose_alignment','Purpose alignment')}${alertRow('correctness','Correctness')}</div>
      <div class="actions"><button type="submit" class="primary">Save settings</button></div>
    </form>`;
    const form=$('#review-form');
    form.provider.value=saved.provider||'local';
    form.review_level.value=saved.review_level||'deep';
    form.mode.value=saved.mode||'on_demand';
    for(const axis of ['safety','purpose_alignment','correctness'])form['alert_'+axis].value=saved.alert_thresholds?.[axis]??'';
    const model=$('#review-model');
    const sameConnection=()=>form.provider.value===(saved.provider||'local')&&form.endpoint.value===(saved.endpoint||defaults[saved.provider||'local']);
    const updateKeyLabel=()=>{form.api_key.closest('label').firstChild.textContent=sameConnection()&&saved.has_api_key?'API key (saved; leave blank to keep)':'API key';};
    const updateDepth=()=>{
      const light=form.review_level.value==='light';
      form.alert_correctness.disabled=light;
      $('#review-depth-hint').textContent=light
        ? 'Sends the reason, agent inputs, and short preceding menu or prompt excerpts. No command results are sent; correctness is not scored.'
        : 'Also sends terminal output and file-operation results to the selected model. Output may contain sensitive data.';
    };
    updateDepth();
    form.review_level.onchange=updateDepth;
    form.provider.onchange=()=>{form.endpoint.value=defaults[form.provider.value];form.api_key.value='';updateKeyLabel();model.replaceChildren();model.disabled=true;};
    form.endpoint.onchange=()=>{updateKeyLabel();model.replaceChildren();model.disabled=true;};
    $('#connect-models').onclick=async()=>{
      try{
        const found=await api('/api/review/models','POST',{provider:form.provider.value,endpoint:form.endpoint.value,api_key:form.api_key.value});
        model.replaceChildren();
        for(const name of found.models){const option=document.createElement('option');option.value=option.textContent=name;model.appendChild(option);}
        model.disabled=!found.models.length;
        if(sameConnection()&&found.models.includes(saved.model))model.value=saved.model;
        toast(found.models.length?`${found.models.length} models loaded`:'No models returned by this server',!found.models.length);
      }catch(error){toast(error.message,true);}
    };
    form.endpoint.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();$('#connect-models').click();}};
    form.onsubmit=e=>{e.preventDefault();action(async()=>{
      const chosen=model.value||(sameConnection()?saved.model:'');
      if(!chosen)throw new Error('Connect and select a model first.');
      const thresholds=Object.fromEntries(['safety','purpose_alignment','correctness'].map(axis=>[axis,form['alert_'+axis].value||null]));
      await api('/api/review/settings','POST',{provider:form.provider.value,endpoint:form.endpoint.value,api_key:form.api_key.value,
        model:chosen,mode:form.mode.value,review_level:form.review_level.value,alert_thresholds:thresholds});
      closeModal();toast('Review settings saved');
    });};
  }
  function appearanceSettings(){
    const choice=window.HilaitTheme.preference, terminal=window.HilaitTerminalAppearance;
    $('#settings-content').innerHTML=`<h3 class="settings-heading">Color mode</h3><div class="theme-options" role="group" aria-label="Color mode">${[['light','Light','Bright workspace'],['dark','Dark','Dim workspace']].map(([value,label,description])=>`<button type="button" data-theme-choice="${value}" aria-pressed="${choice===value}"><strong>${label}</strong><small>${description}</small></button>`).join('')}</div><h3>Terminal</h3><div class="form-grid"><label>Font<select id="terminal-font"><option value="jetbrains">JetBrains Mono</option><option value="system">System monospace</option><option value="consolas">Consolas</option><option value="courier">Courier New</option></select></label><label>Font size<select id="terminal-size">${[10,11,12,13,14,15,16,17,18,19,20,21,22,23,24].map(size=>`<option value="${size}">${size} px</option>`).join('')}</select></label></div><div class="terminal-preview-label">Preview</div><div id="terminal-preview" class="terminal-preview" aria-label="Terminal font preview"><div><span class="preview-prompt">user@server:~$</span> ls</div><div><span class="preview-directory">projects</span>  notes.txt</div><div><span class="preview-prompt">user@server:~$</span> <span class="preview-cursor"> </span></div></div>`;
    $('#terminal-font').value=terminal.font;$('#terminal-size').value=String(terminal.size);
    const updatePreview=()=>{const preview=$('#terminal-preview');preview.style.fontFamily=terminal.family;preview.style.fontSize=terminal.size+'px';};
    updatePreview();
    $('#settings-content').onclick=event=>{const button=event.target.closest('[data-theme-choice]');if(!button)return;window.HilaitTheme.set(button.dataset.themeChoice);appearanceSettings();};
    $('#terminal-font').onchange=()=>{terminal.set($('#terminal-font').value,Number($('#terminal-size').value));updatePreview();};
    $('#terminal-size').onchange=()=>{terminal.set($('#terminal-font').value,Number($('#terminal-size').value));updatePreview();};
  }
  async function notificationSettings() {
    const box=$('#settings-content');box.innerHTML='<p>Loading notification settings…</p>';
    let saved;try{saved=await api('/api/notifications/ntfy');}catch(error){box.innerHTML=`<p class="error">${escaped(error.message)}</p>`;return;}
    if(!box.isConnected||!$('#modal .settings-nav button[data-tab="notifications"]')?.classList.contains('active'))return;
    box.innerHTML=`<p>ntfy can notify you about access requests and low review scores. Score thresholds are set in Activity review.</p><form id="ntfy-form"><label class="setting-row toggle">Notify about access requests<input name="enabled" type="checkbox" ${saved.enabled?'checked':''}></label><div class="form-grid">${field('ntfy server URL','server_url',saved.server_url,'url','placeholder="https://ntfy.sh"')}${field('Topic','topic',saved.topic,'text','autocomplete="off"')}${field('Hilait URL reachable from your phone','hilait_url',saved.hilait_url,'url','class="full" placeholder="https://hilait.example"')}${field(saved.has_token?'ntfy access token (leave blank to keep saved token)':'ntfy access token (if required)','token','','password','autocomplete="new-password"')}<label class="toggle">Remove saved ntfy token<input name="clear_token" type="checkbox"></label></div><p class="setting-hint">Use a private topic. Access request notifications include the agent, machine, file scope and a short purpose preview. Review alerts include scores and a short summary. Your phone must be able to reach the Hilait URL over HTTPS. Save before sending a test.</p><div class="actions"><button type="button" id="ntfy-test">Send test</button><button type="submit" class="primary">Save settings</button></div></form>`;
    const form=$('#ntfy-form');form.onsubmit=async e=>{e.preventDefault();try{await api('/api/notifications/ntfy','PUT',{...formData(form),enabled:form.enabled.checked,clear_token:form.clear_token.checked});toast('Notification settings saved');await notificationSettings();}catch(error){toast(error.message,true);}};
    $('#ntfy-test').onclick=async()=>{try{await api('/api/notifications/ntfy/test','POST',{});toast('Test notification sent');}catch(error){toast(error.message,true);}};
  }
  async function otpSettings() {
    const box=$('#settings-content');box.innerHTML='<p>Loading OTP settings…</p>';
    let current;try{current=await api('/api/otp');}catch(error){box.innerHTML=`<p class="error">${escaped(error.message)}</p>`;return;}
    if(!box.isConnected || !$('#modal .settings-nav button[data-tab="otp"]')?.classList.contains('active'))return;
    if(current.pending){
      const secret=current.secret.match(/.{1,4}/g).join(' ');
      box.innerHTML=`<div class="setting-row otp-panel"><strong>Scan this code with Google Authenticator</strong><p>${current.enabled?'Replacing this key will permanently delete saved connections, trusted host keys, and machine authorizations when you activate it. Your current key remains active until then.':'Enter a code from the app to activate this key. Existing connections will be encrypted with it.'}</p><div class="otp-setup-grid"><img class="otp-qr" src="${escaped(current.qr)}" alt="Authenticator setup QR code"><div><p>Manual setup key</p><code class="otp-seed">${escaped(secret)}</code><form id="otp-confirm-form"><label>Six-digit code<input name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></label><div class="actions"><button type="button" id="otp-cancel">Cancel setup</button><button class="primary">${current.enabled?'Replace key and delete connections':'Activate OTP'}</button></div></form></div></div></div>`;
      $('#otp-confirm-form').onsubmit=async e=>{e.preventDefault();try{const result=await api('/api/otp/confirm','POST',{code:e.target.code.value});token=result.session;sessionStorage.setItem('hilait-token',token);eventStream();await refresh();await otpSettings();toast('OTP enabled');}catch(error){toast(error.message,true);}};
      $('#otp-cancel').onclick=async()=>{try{await api('/api/otp/cancel','POST',{});await otpSettings();}catch(error){toast(error.message,true);}};
    }else if(current.enabled){
      box.innerHTML=`<div class="setting-row otp-panel"><strong>Authenticator is on</strong><p>A six-digit authenticator code opens the workspace. The admin token is not requested while OTP is enabled. Verified browser sessions last up to 12 hours and end when Hilait restarts.</p><form id="otp-manage-form"><label>Current authenticator code<input name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></label><div class="actions"><button type="button" id="otp-replace">Replace authenticator</button><button type="button" id="otp-disable" class="danger">Turn off OTP</button></div></form></div>`;
      const form=$('#otp-manage-form');
      $('#otp-replace').onclick=async()=>{if(!form.reportValidity()||!confirm('Replace the authenticator key? Once you activate the new key, all saved connections, trusted host keys, and machine authorizations will be permanently deleted. Disconnect any active sessions first.'))return;try{await api('/api/otp/setup','POST',{current_code:form.code.value});await otpSettings();}catch(error){toast(error.message,true);}};
      $('#otp-disable').onclick=async()=>{if(!form.reportValidity()||!confirm('Turn off OTP and permanently delete all saved connections, trusted host keys, and machine authorizations? The admin token alone will open Hilait afterward. Disconnect any active sessions first.'))return;try{await api('/api/otp/disable','POST',{code:form.code.value});token='';sessionStorage.removeItem('hilait-token');eventsSocket?.close();closeModal();await login();}catch(error){toast(error.message,true);}};
    }else{
      box.innerHTML=`<div class="setting-row otp-panel"><strong>Add an authenticator code</strong><p>Scan a locally generated QR code with Google Authenticator or another TOTP app. Once confirmed, a six-digit authenticator code will open Hilait instead of the admin token.</p><button id="otp-generate" class="primary">Generate OTP seed</button></div>`;
      $('#otp-generate').onclick=async()=>{try{await api('/api/otp/setup','POST',{});await otpSettings();}catch(error){toast(error.message,true);}};
    }
  }
  function showConfig(config){openModal(head('Agent MCP configuration','Copy this into the agent’s MCP server settings.')+`<div class="code" id="config-text">${escaped(JSON.stringify(config,null,2))}</div><div class="actions"><button data-close>Close</button><button id="copy-config" class="primary">Copy configuration</button></div>`);$('#copy-config').onclick=()=>navigator.clipboard.writeText(JSON.stringify(config,null,2)).then(()=>toast('Configuration copied'));}
  function showPermissions(agentId){const agent=state.agents.find(a=>a.id===agentId);openModal(head(`Allowed connections · ${agent.name}`,'The agent sees names only. Every connection still requires approval.')+`<form id="permissions-form">${state.profiles.map(p=>`<label class="setting-row toggle">${escaped(p.name)}<input type="checkbox" value="${escaped(p.id)}" ${(p.allowed_agent_ids===null||p.allowed_agent_ids?.includes(agentId))?'checked':''}></label>`).join('')}<div class="actions"><button type="button" data-close>Cancel</button><button class="primary">Save permissions</button></div></form>`,true);$('#permissions-form').onsubmit=e=>{e.preventDefault();action(async()=>{await api(`/api/agents/${agentId}/permissions`,'POST',{connection_ids:[...$('#permissions-form').querySelectorAll('input:checked')].map(i=>i.value)});settings('agents');});};}
  function authorizationDialog(){openModal(head('New authorization','Future requests from this agent on this machine can be approved until expiry.')+`<form id="authorization-form" class="form-grid"><label>Agent<select name="agent_id">${state.agents.filter(a=>a.active).map(a=>`<option value="${escaped(a.id)}">${escaped(a.name)}</option>`).join('')}</select></label><label>Machine<select name="profile_id">${state.profiles.map(p=>`<option value="${escaped(p.id)}">${escaped(p.name)}</option>`).join('')}</select></label>${field('Hours','hours','1','number','min="0.01" max="8760" step="0.01"')}<label>File access<select name="file_access"><option>None</option><option>Remote</option><option>LocalTransfers</option></select></label>${field('Server local transfer folder (if needed)','local_folder','','text','class="full"')}<div class="actions full"><button type="button" data-close>Cancel</button><button class="primary">Create authorization</button></div></form>`,true);$('#authorization-form').onsubmit=e=>{e.preventDefault();const data=formData(e.target);action(async()=>{await api('/api/authorizations','POST',data);settings('authorizations');});};}

  function requestModal(grant) { if (!grant || grant.state !== 'Pending') return; openModal(head('Connection request')+`<div class="request-row"><strong>${escaped(grant.agent)} → ${escaped(grant.connection)}</strong><p>${escaped(grant.purpose)}</p><small>Requested file access: ${escaped(grant.fileAccess)}</small></div><form id="request-form" data-access="${escaped(grant.access)}"><div class="form-grid"><label>Authorization duration<select name="duration_hours"><option value="">This request only</option><option value="0.083333">5 minutes</option><option value="0.25">15 minutes</option><option value="0.5">30 minutes</option><option value="1">1 hour</option><option value="2">2 hours</option><option value="4">4 hours</option><option value="8">8 hours</option><option value="24">24 hours</option></select></label>${grant.fileAccess==='LocalTransfers'?field('Local transfer folder on this server','local_folder','','text','required'):''}${field('SSH password / key passphrase if not saved','secret','','password')}</div><div class="actions"><button type="button" id="reject-request" class="danger">Reject</button><button type="submit" class="primary">Authorize</button></div></form>`,true);$('#reject-request').onclick=()=>action(async()=>{await api(`/api/grants/${grant.access}/reject`,'POST',{});closeModal();});$('#request-form').onsubmit=e=>{e.preventDefault();const data=formData(e.target);if(data.duration_hours)data.duration_hours=Number(data.duration_hours);else delete data.duration_hours; if(!data.secret)delete data.secret;action(async()=>{const approved=await api(`/api/grants/${grant.access}/approve`,'POST',data);selectedProfile=approved.profile;selectedSession=approved.session;closeModal();});}; }
  function sudoModal(request){openModal(head('Agent requests sudo',`${request.agent} · ${request.connection}`)+`<p>${escaped(request.reason)}</p><div class="code">${escaped(request.command)}</div><form id="sudo-form">${request.hasSavedPassword?'<p>Approve use of the saved sudo password.</p>':field('Sudo password','password','','password','required')}<div class="actions"><button type="button" id="sudo-deny" class="danger">Deny</button><button class="primary">Approve sudo</button></div></form>`,true);selectedProfile=state.sessions.find(s=>s.id===request.session)?.profile||selectedProfile;selectedSession=request.session;render();$('#sudo-deny').onclick=()=>action(async()=>{await api(`/api/sudo/${request.id}/decide`,'POST',{approved:false});closeModal();});$('#sudo-form').onsubmit=e=>{e.preventDefault();action(async()=>{await api(`/api/sudo/${request.id}/decide`,'POST',{approved:true,password:e.target.password?.value||''});closeModal();});};}

  async function showLogs(){
    const logs=await api('/api/logs');
    const pending=logs.some(log=>log.needsReview);
    openModal(head('Agent session logs')+`${pending?'<div class="actions"><button id="review-all" class="primary">Review all pending</button></div>':''}<div id="logs-list"></div>`);
    if(pending)$('#review-all').onclick=()=>action(async()=>{await api('/api/review-all','POST',{});toast('Pending reviews started');});
    if(!logs.length){$('#logs-list').innerHTML='<p class="empty-message">No agent sessions recorded yet.</p>';return;}
    for(const log of logs){
      const row=document.createElement('div');row.className='log-row';row.tabIndex=0;row.setAttribute('role','button');
      row.innerHTML=`<strong>${escaped(log.agent||'Agent')} · ${escaped(log.connection||'Connection')}</strong><small>${escaped(log.purpose||'')} · ${new Date(log.lastUtc).toLocaleString()}${log.review?' · '+escaped(log.review.level||'Deep')+' review':''}</small><div class="scores">${['safety','purpose_alignment','correctness'].map(axis=>{const score=log.review?.[axis];return `<span class="score ${score==null?'':score<4?'low':score<7?'mid':'high'}">${escaped(axis.replace('_',' '))} ${score??'—'}</span>`;}).join('')}</div>${log.review?.summary?`<p class="review-summary">${escaped(log.review.summary)}</p>`:''}`;
      row.onclick=()=>showLogDetail(log.grant);
      row.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showLogDetail(log.grant);}};
      row.oncontextmenu=e=>{e.preventDefault();menu([...(log.needsReview||log.review?.schema_version!==3?[[`${log.review?'Update':'Run'} ${state.reviewSettings.review_level||'deep'} review`,()=>reviewSession(log.grant)]]:[]),["Export for analysis",()=>exportLog(log.grant)],["Delete log",()=>deleteLog(log.grant)]],e.clientX,e.clientY);};
      $('#logs-list').appendChild(row);
    }
  }
  function logTime(value){const date=new Date(value);return Number.isNaN(date.getTime())?String(value||'Unknown time'):date.toLocaleString();}
  function logBytes(value){
    try{const bytes=Uint8Array.from(atob(value||''),char=>char.charCodeAt(0));return new TextDecoder('utf-8').decode(bytes);}
    catch{return '[Recorded terminal data could not be decoded]';}
  }
  function logTerminalText(value){
    return value.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g,'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'')
      .replace(/\x1b[()][A-Za-z0-9]/g,'').replace(/\r\n/g,'\n').replace(/\r/g,'\n')
      .replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'');
  }
  function logFileContent(value){
    if(value==null)return '';
    try{
      const bytes=Uint8Array.from(atob(value),char=>char.charCodeAt(0));
      if(!bytes.length)return '<p>Empty file content</p>';
      const content=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
      if(/[\x00-\x08\x0b\x0e-\x1f]/.test(content))return `<p>Binary content · ${bytes.length} bytes</p>`;
      return `<pre class="log-file-content">${escaped(content)}</pre>`;
    }catch{return '<p>Binary or invalid recorded content</p>';}
  }
  function axisTitle(axis){return axis==='purpose_alignment'?'Purpose alignment':axis==='safety'?'Safety':'Correctness';}
  function scoreTone(score){return score<4?'low':score<7?'mid':'high';}
  function reviewReferences(events,review){
    const available=new Set(events.map(event=>event.sequence));
    const map=new Map();
    if(!review)return map;
    for(const axis of ['safety','purpose_alignment','correctness']){
      if(review[axis]==null)continue;
      let references=review.evidence_refs?.[axis];
      if(!Array.isArray(references)||!references.length){
        references=[];
        const rationale=review.rationale?.[axis]||'';
        for(const match of rationale.matchAll(/(?:#|(?:commands?|events?|inputs?)\s+(?:in\s+)?)(\d+(?:\s*(?:,|and)\s*\d+)*)/gi)){
          references.push(...(match[1].match(/\d+/g)||[]).map(Number));
        }
      }
      for(const sequence of references){if(!available.has(sequence))continue;if(!map.has(sequence))map.set(sequence,new Set());map.get(sequence).add(axis);}
    }
    for(const finding of review.findings||[]){for(const axis of finding.axes||[]){if(available.has(finding.sequence)&&review[axis]!=null){if(!map.has(finding.sequence))map.set(finding.sequence,new Set());map.get(finding.sequence).add(axis);}}}
    return map;
  }
  function logEventLabel(event){
    const data=event.data||{};
    if(event.kind==='terminal_input_sent')return 'Terminal input · '+logTerminalText(logBytes(data.base64)).trim().split('\n')[0].slice(0,100);
    if(event.kind==='sudo_requested')return 'Sudo · '+String(data.command||'').slice(0,100);
    if(event.kind==='file_request'||event.kind==='file_result'||event.kind==='file_error')return 'File '+(data.action||'operation')+' · '+(data.path||'');
    if(event.kind==='copy_completed')return 'File transfer · '+(data.path||'');
    if(event.kind==='session_closed')return 'Session closed';
    if(event.kind==='terminal_output'||event.kind==='sudo_output')return 'Terminal output';
    return event.kind.replaceAll('_',' ');
  }
  function logMarkers(sequence,review,references){
    if(!review)return '';
    const finding=(review.findings||[]).find(item=>item.sequence===sequence);
    let markers='';
    for(const axis of references.get(sequence)||[]){
      const score=review[axis];
      markers+=`<button type="button" class="event-score ${scoreTone(score)}" data-axis="${axis}" aria-expanded="false" aria-label="${escaped(axisTitle(axis))} score ${score} out of 10. Show rationale">${escaped(axisTitle(axis))} ${score}/10</button><p class="finding-note" hidden>${escaped(review.rationale?.[axis]||'')}</p>`;
    }
    if(finding){const label=['wrong','unnecessary','problematic','dangerous'].includes(finding.label)?finding.label:'problematic';markers+=`<button type="button" class="event-flag ${label}" aria-expanded="false" aria-label="${escaped(label)} finding. Show reason">${escaped(label)}</button><p class="finding-note" hidden>${escaped(finding.rationale)}</p>`;}
    return markers;
  }
  function menuChoice(input,precedingOutput){
    if(!/(?:enter|select|choose)[^\n]{0,40}(?:option|choice|number)\s*:/i.test(precedingOutput.slice(-1800)))return '';
    const choice=input.trim().split('\n')[0].trim();
    if(!/^\d{1,2}$/.test(choice))return '';
    for(const line of precedingOutput.split('\n').slice(-40)){
      for(const match of line.matchAll(/(\d{1,2})\)\s+(.+?)(?=\s+\d{1,2}\)|$)/g)){
        if(match[1]===choice)return `Menu choice ${choice} → ${match[2].trim()}`;
      }
    }
    return '';
  }
  function logActivity(events,review){
    const references=reviewReferences(events,review);
    const rows=[];
    let precedingOutput='';
    for(const event of events){
      const data=event.data||{}, sequence=event.sequence, flag=logMarkers(sequence,review,references);
      const stamp=`<time datetime="${escaped(event.utc)}">${escaped(logTime(event.utc))}</time>`;
      if(event.kind==='terminal_input_sent'){
        const input=logTerminalText(logBytes(data.base64));
        const choice=menuChoice(input,precedingOutput);
        rows.push(`<section class="log-entry command" data-sequence="${sequence}"><div class="log-entry-head"><span>Agent input · ${stamp}</span>${flag}</div>${choice?`<p class="input-context">${escaped(choice)}</p>`:''}<pre>${escaped(input)}</pre></section>`);
        precedingOutput='';
      }else if(event.kind==='terminal_output'){
        const output=logTerminalText(logBytes(data.base64));
        precedingOutput=(precedingOutput+output).slice(-8192);
        rows.push(`<section class="log-entry output" data-sequence="${sequence}">${flag?`<div class="log-entry-head"><span>Terminal · ${stamp}</span>${flag}</div>`:''}<pre>${escaped(output)}</pre></section>`);
      }else if(event.kind==='human_terminal_input'){
        rows.push(`<section class="log-entry human" data-sequence="${sequence}"><div class="log-entry-head"><span>You typed · ${stamp}</span>${flag}</div><p>Keystrokes hidden to protect passwords.</p></section>`);
        precedingOutput='';
      }else if(event.kind==='sudo_requested'){
        rows.push(`<section class="log-entry operation" data-sequence="${sequence}"><div class="log-entry-head"><span>Sudo requested · ${stamp}</span>${flag}</div><pre>${escaped(data.command||'')}</pre>${data.reason?`<p>${escaped(data.reason)}</p>`:''}</section>`);
      }else if(event.kind==='sudo_output'){
        rows.push(`<section class="log-entry output" data-sequence="${sequence}"><div class="log-entry-head"><span>Sudo output · exit ${escaped(data.exitCode??'unknown')} · ${stamp}</span>${flag}</div><pre>${escaped(logTerminalText(logBytes(data.base64)))}</pre></section>`);
      }else if(event.kind==='file_request'){
        rows.push(`<section class="log-entry operation" data-sequence="${sequence}"><div class="log-entry-head"><span>File ${escaped(data.action||'operation')} · ${stamp}</span>${flag}</div><p class="log-path">${escaped(data.path||'')}</p>${data.destination?`<p>Destination: ${escaped(data.destination)}</p>`:''}${data.action==='write'?logFileContent(data.base64):''}</section>`);
      }else if(event.kind==='file_result'){
        const result=data.result||{};
        const summary=result.entries?`${result.entries.length} items returned`:[result.size!=null?`${result.size} bytes`:null,result.count!=null?`${result.count} bytes read`:null,result.written!=null?`${result.written} bytes written`:null,result.mode?`Mode ${result.mode}`:null,result.created||result.deleted||result.destination||null].filter(Boolean).join(' · ')||'Completed';
        const listing=result.entries?`<ul class="log-file-list">${result.entries.map(item=>`<li>${escaped(item.name||'Unnamed entry')}</li>`).join('')}</ul>`:'';
        rows.push(`<section class="log-entry operation result" data-sequence="${sequence}"><div class="log-entry-head"><span>File ${escaped(data.action||'operation')} completed · ${stamp}</span>${flag}</div><p class="log-path">${escaped(data.path||'')}</p><p>${escaped(summary)}</p>${listing}${data.action==='read'?logFileContent(result.base64):''}</section>`);
      }else if(event.kind==='file_error'||event.kind==='session_error'){
        rows.push(`<section class="log-entry operation failed" data-sequence="${sequence}"><div class="log-entry-head"><span>${event.kind==='file_error'?'File operation failed':'Session error'} · ${stamp}</span>${flag}</div><p>${escaped(data.path||'')}${data.path?' · ':''}${escaped(data.error||'Unknown error')}</p></section>`);
      }else if(event.kind==='copy_completed'){
        rows.push(`<section class="log-entry operation result" data-sequence="${sequence}"><div class="log-entry-head"><span>File transfer completed · ${stamp}</span>${flag}</div><p class="log-path">${escaped(data.path||'')} → ${escaped(data.destination||'')}</p><p>${escaped(data.direction||'Transfer')}${data.bytes!=null?` · ${escaped(data.bytes)} bytes`:''}</p></section>`);
      }else if(event.kind==='session_closed'){
        rows.push(`<section class="log-entry lifecycle" data-sequence="${sequence}"><div class="log-entry-head"><span>Session closed · ${stamp}</span>${flag}</div>${data.reason?`<p>${escaped(data.reason)}</p>`:''}</section>`);
      }
    }
    const scores=review?`<div class="activity-scores"><span>Session scores</span>${['safety','purpose_alignment','correctness'].filter(axis=>review[axis]!=null).map(axis=>`<span class="score ${scoreTone(review[axis])}">${escaped(axisTitle(axis))} ${review[axis]}/10</span>`).join('')}</div>`:'';
    return `<div class="activity-intro"><strong>Recorded activity</strong><span>Terminal output is from the shared session and may include human activity.</span></div>${scores}${review?'<p class="activity-key">Score badges mark evidence cited by the review. Click one to see why it matters.</p>':''}<div class="activity-transcript">${rows.join('')||'<p class="empty-message">No terminal or file activity was recorded.</p>'}</div>`;
  }
  function logDetails(events){
    const first=events.find(event=>event.kind==='access_requested')||events[0];
    if(!first)return '<p class="empty-message">No session details were recorded.</p>';
    const context=first.context||{}, request=first.data||{};
    const opened=events.find(event=>event.kind==='session_opened');
    const states=events.filter(event=>event.kind==='access_state_changed'||event.kind.startsWith('automatic_approval_'));
    const lastState=[...states].reverse().find(event=>event.data?.state);
    const line=(label,value)=>value==null||value===''?'':`<div class="detail-item"><dt>${escaped(label)}</dt><dd>${escaped(value)}</dd></div>`;
    const timeline=states.map(event=>`<li><time datetime="${escaped(event.utc)}">${escaped(logTime(event.utc))}</time><strong>${escaped(event.data?.state||event.kind.replaceAll('_',' '))}</strong>${event.data?.reason?`<span>${escaped(event.data.reason)}</span>`:''}${event.data?.expires_utc?`<span>Until ${escaped(logTime(event.data.expires_utc))}</span>`:''}</li>`).join('');
    const closed=events.find(event=>event.kind==='session_closed');
    return `<div class="detail-section"><h3>Connection</h3><dl class="detail-grid">${line('Machine',context.connection)}${line('Endpoint',opened?.data?.endpoint)}${line('Session ID',opened?.context?.session||context.session)}${line('Connection ID',context.profile)}</dl></div>
      <div class="detail-section"><h3>Request</h3><dl class="detail-grid">${line('Agent',context.agent)}${line('Agent ID',context.agentId)}${line('Requested',logTime(first.utc))}${line('File access',request.fileAccess||context.fileAccess||'None')}${line('Request ID',context.grant)}</dl><div class="detail-purpose"><strong>Reason for request</strong><p>${escaped(request.purpose||context.purpose||'None recorded')}</p></div></div>
      <div class="detail-section"><h3>Authorization</h3><dl class="detail-grid">${line('Last recorded state',lastState?.data?.state||(closed?'Closed':'Pending'))}${line('Session closed',closed?logTime(closed.utc):null)}${line('Close reason',closed?.data?.reason)}</dl>${timeline?`<ol class="detail-timeline">${timeline}</ol>`:'<p>No authorization decision was recorded.</p>'}</div>`;
  }
  async function showLogDetail(grantId, tab='activity'){
    const detail=await api(`/api/logs/${grantId}`);
    openModal(head('Agent session')+
      `<nav class="modal-tabs" aria-label="Session sections"><button type="button" data-tab="activity">Activity</button>${detail.review?'<button type="button" data-tab="review">Review</button>':''}<button type="button" data-tab="details">Details</button></nav><div id="log-detail"></div>`);
    const paint=which=>{
      const box=$('#log-detail');
      $('#modal .modal-tabs').querySelectorAll('button').forEach(button=>button.classList.toggle('active',button.dataset.tab===which));
      if(which==='review'){
        const review=detail.review;
        const axes=['safety','purpose_alignment','correctness'].filter(axis=>review[axis]!=null);
        const references=reviewReferences(detail.events,review);
        const scores=axes.map(axis=>`<span class="score ${scoreTone(review[axis])}">${escaped(axisTitle(axis))} ${review[axis]}/10</span>`).join('');
        const rationales=axes.map(axis=>{
          const linked=detail.events.filter(event=>references.get(event.sequence)?.has(axis)).slice(0,3);
          const links=linked.map(event=>`<button type="button" class="evidence-link" data-find-sequence="${event.sequence}" data-axis="${axis}">${escaped(logEventLabel(event))}<span>View in activity →</span></button>`).join('');
          return `<div class="setting-row review-axis"><div class="review-axis-head"><strong>${escaped(axisTitle(axis))}</strong><span class="score ${scoreTone(review[axis])}">${review[axis]}/10</span></div><p>${escaped(review.rationale?.[axis]||'')}</p>${links?`<div class="evidence-links">${links}</div>`:''}</div>`;
        }).join('');
        const findings=(review.findings||[]).map(finding=>`<button type="button" class="review-finding ${escaped(finding.label)}" data-find-sequence="${Number(finding.sequence)}"><strong>${escaped(finding.label)} · ${escaped(logEventLabel(detail.events.find(event=>event.sequence===finding.sequence)||{kind:'recorded_event'}))}</strong><span>${escaped(finding.rationale)}</span><small>View in activity →</small></button>`).join('')||'<p>No individual action was flagged.</p>';
        box.innerHTML=`<small class="review-meta">${escaped((review.level||'deep').toUpperCase())} REVIEW · ${escaped(review.provider||'Local')} · ${escaped(review.model||'')}</small><div class="scores">${scores}${review.correctness==null?'<span class="score">Correctness not scored</span>':''}</div>${review.summary?`<div class="setting-row review-overview"><strong>Summary</strong><p>${escaped(review.summary)}</p></div>`:''}${rationales}<h3>Specific findings</h3>${findings}`;
      }else if(which==='details'){
        box.innerHTML=logDetails(detail.events);
      }else{
        box.innerHTML=logActivity(detail.events,detail.review)+`<p id="review-progress" role="status">${escaped(detail.progress||'')}</p>`;
      }
    };
    $('#modal .modal-tabs').onclick=event=>{if(event.target.dataset.tab)paint(event.target.dataset.tab);};
    $('#log-detail').onclick=event=>{
      const link=event.target.closest('[data-find-sequence]');
      if(link){paint('activity');requestAnimationFrame(()=>{const target=$('#log-detail [data-sequence="'+link.dataset.findSequence+'"]');target?.scrollIntoView({block:'center',behavior:'smooth'});target?.classList.add('highlighted');setTimeout(()=>target?.classList.remove('highlighted'),3500);const selector=link.dataset.axis?`.event-score[data-axis="${link.dataset.axis}"]`:'.event-flag';target?.querySelector(selector)?.click();});return;}
      const marker=event.target.closest('.event-flag,.event-score');
      if(marker){const note=marker.nextElementSibling;if(!note?.classList.contains('finding-note'))return;const open=note.hidden;note.hidden=!open;marker.setAttribute('aria-expanded',String(open));}
    };
    paint(tab);
  }
  async function reviewSession(id){closeModal();status('Reviewing session…');try{await api(`/api/review/${id}`,'POST',{});await showLogDetail(id,'review');status('Review complete');}catch(error){status('Review failed: '+error.message);toast(error.message,true);}}
  async function exportLog(id){const response=await fetch(`/api/logs/${id}/export`,{headers:{Authorization:'Bearer '+token}});if(!response.ok){toast('Export failed',true);return;}const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`hilait-${id}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),5000);}
  function deleteLog(id){if(!confirm('Permanently delete this ended session log? Its recorded evidence and review will be removed.'))return;action(async()=>{await api(`/api/logs/${id}`,'DELETE');await showLogs();});}

  function eventStream(){eventsSocket?.close();const socket=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/events?token=${encodeURIComponent(token)}`);eventsSocket=socket;socket.onmessage=async event=>{const data=JSON.parse(event.data);if(data.type==='state'){state=data.state;render();return;}if(data.type==='review_progress'){status(data.message);const line=$('#review-progress');if(line)line.textContent=data.message;return;}if(data.type==='sudo_request'){sudoModal(data.request);return;}await refresh();if(data.type==='agent_token_request') toast('Agent token request · Review in Settings → Agent Access');if(data.type.startsWith('agent_token_') && $('#modal .settings-nav button[data-tab="agents"]')?.classList.contains('active')) settingsTab('agents');if(data.type==='request'){const pending=state.grants.find(g=>g.access===data.grant.access&&g.state==='Pending');if(pending)requestModal(pending);}if(data.type==='session_opened'){selectedProfile=data.profile;selectedSession=data.session;render();}if(data.type==='access'&&data.grant.state==='Approved'&&data.grant.session){selectedProfile=data.grant.profile;selectedSession=data.grant.session;render();}};socket.onclose=e=>{if(eventsSocket!==socket)return;if(e.code===4401){login();return;}setTimeout(()=>{if(token)eventStream();},2500);};}
  async function login(){try{await refresh();$('#login').classList.add('hidden');$('#otp-login').classList.add('hidden');$('#workspace').classList.remove('hidden');eventStream();}catch(error){$('#workspace').classList.add('hidden');let otpEnabled=error.details?.detail?.code==='otp_required';if(!otpEnabled){try{otpEnabled=(await api('/api/auth/mode')).otp_enabled;}catch{}}if(otpEnabled){$('#login').classList.add('hidden');$('#otp-login').classList.remove('hidden');$('#otp-login-error').textContent='';$('#otp-login-code').focus();}else{$('#otp-login').classList.add('hidden');$('#login').classList.remove('hidden');$('#login-error').textContent=error.message;}}}
  $('#login-button').onclick=()=>{token=$('#login-token').value.trim();sessionStorage.setItem('hilait-token',token);login();};$('#login-token').onkeydown=e=>{if(e.key==='Enter')$('#login-button').click();};
  $('#otp-login-form').onsubmit=async e=>{e.preventDefault();$('#otp-login-error').textContent='';try{const result=await api('/api/auth/verify','POST',{code:$('#otp-login-code').value});token=result.session;sessionStorage.setItem('hilait-token',token);$('#otp-login-code').value='';await login();}catch(error){$('#otp-login-error').textContent=error.message;$('#otp-login-code').select();}};
  $('#new-profile').onclick=()=>profileDialog();$('#welcome-new').onclick=()=>profileDialog();$('#open-settings').onclick=()=>settings();$('#open-logs').onclick=()=>action(showLogs);
  $('#search-profiles').oninput=()=>state&&renderMachines();$('#terminal-close').onclick=()=>selectedSession&&disconnect(selectedSession);$('#files-toggle').onclick=()=>$('#files-pane').classList.contains('hidden')?showFiles():$('#files-pane').classList.add('hidden');$('#files-close').onclick=()=>$('#files-pane').classList.add('hidden');$('#files-refresh').onclick=loadFiles;$('#files-path').onkeydown=e=>{if(e.key==='Enter')loadFiles();};$('#files-up').onclick=()=>{$('#files-path').value=$('#files-path').value.replace(/\/$/,'').split('/').slice(0,-1).join('/')||'/';loadFiles();};$('#files-new-folder').onclick=()=>{const name=prompt('New folder name');if(name)action(async()=>{await api(`/api/sessions/${selectedSession}/files`,'POST',{action:'mkdir',path:currentFilePath.replace(/\/$/,'')+'/'+name});await loadFiles();});};$('#files-new-file').onclick=()=>{const name=prompt('New file name');if(name)action(async()=>{await api(`/api/sessions/${selectedSession}/files`,'POST',{action:'write',path:currentFilePath.replace(/\/$/,'')+'/'+name,base64:''});await loadFiles();});};$('#files-new-link').onclick=()=>{const session=selectedConnection();if(state.profiles.find(p=>p.id===session?.profile)?.platform==='windows'){toast('Symbolic links are unavailable on Windows SSH machines',true);return;}const name=prompt('New link name');if(!name)return;const destination=prompt('Link target path');if(destination)action(async()=>{await api(`/api/sessions/${selectedSession}/files`,'POST',{action:'symlink',path:currentFilePath.replace(/\/$/,'')+'/'+name,destination});await loadFiles();});};$('#files-upload').onclick=()=>$('#upload-input').click();$('#upload-input').onchange=e=>{for(const file of e.target.files)action(()=>uploadFile(file));e.target.value='';};$('#files-download').onclick=()=>action(downloadFile);
  document.addEventListener('keydown',e=>{
    const modalOpen=!$('#modal-backdrop').classList.contains('hidden');
    if(e.key==='Escape'&&modalOpen){closeModal();return;}
    if(e.key==='Tab'&&modalOpen){const items=[...$('#modal').querySelectorAll('button,input,select,textarea,a[href]')].filter(el=>!el.disabled&&el.getClientRects().length);if(items.length){const first=items[0],last=items.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}}
    if(e.ctrlKey&&e.key.toLowerCase()==='n'){e.preventDefault();profileDialog();}
  });
  login();
})();
