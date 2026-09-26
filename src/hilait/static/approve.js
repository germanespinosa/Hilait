(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const grantId = location.pathname.split('/').at(-1);
  let token = sessionStorage.getItem('hilait-token') || '';
  let pendingHost = null;

  async function api(path, method = 'GET', body) {
    const headers = {'Accept':'application/json'};
    if (!path.startsWith('/api/auth/')) headers.Authorization = 'Bearer ' + token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {method, headers, body:body === undefined ? undefined : JSON.stringify(body)});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.error || data.detail?.message || data.detail || `Request failed (${response.status})`);
      error.status = response.status;
      error.details = data;
      throw error;
    }
    return data;
  }

  function show(name) {
    for (const id of ['loading','login','request']) $('#' + id).classList.toggle('hidden', id !== name);
  }

  async function showLogin() {
    let otpEnabled = false;
    try { otpEnabled = (await api('/api/auth/mode')).otp_enabled; } catch (error) { $('#login-error').textContent = error.message; }
    $('#login-description').textContent = otpEnabled ? 'Enter your six-digit authenticator code to review this request.' : 'Enter the admin token printed by hilait serve to review this request.';
    $('#login-label').textContent = otpEnabled ? 'Authenticator code' : 'Admin token';
    const input = $('#login-value');
    input.type = otpEnabled ? 'text' : 'password';
    input.inputMode = otpEnabled ? 'numeric' : 'text';
    input.autocomplete = otpEnabled ? 'one-time-code' : 'off';
    input.pattern = otpEnabled ? '[0-9]{6}' : '';
    input.maxLength = otpEnabled ? 6 : 256;
    $('#login-form').dataset.otp = otpEnabled ? 'true' : 'false';
    show('login');
    input.focus();
  }

  function showGrant(grant) {
    show('request');
    $('#request-title').textContent = grant.state === 'Pending' ? 'Review access request' : 'Request ' + grant.state.toLowerCase();
    $('#request-agent').textContent = grant.agent;
    $('#request-machine').textContent = grant.connection;
    $('#request-files').textContent = ({None:'No file access', Remote:'Remote files', LocalTransfers:'Remote files and local transfers'})[grant.fileAccess] || grant.fileAccess;
    $('#request-purpose').textContent = grant.purpose;
    const active = grant.state === 'Pending';
    $('#decision-form').classList.toggle('hidden', !active);
    $('#request-state').classList.toggle('hidden', active);
    if (!active) $('#request-state').textContent = `This request is ${grant.state.toLowerCase()}. No further decision is needed.`;
    $('#folder-field').classList.toggle('hidden', grant.fileAccess !== 'LocalTransfers');
    $('#decision-form').elements.local_folder.required = grant.fileAccess === 'LocalTransfers';
    const choice = new URLSearchParams(location.search).get('choice');
    $('#decision-hint').textContent = choice === 'reject' ? 'Review the request, then choose Deny request to confirm.' : 'Review the request and its file scope before approving.';
    if (choice === 'reject') $('#deny').focus();
  }

  async function load(fromLogin = false) {
    if (!/^[0-9a-f-]{36}$/i.test(grantId)) { show('loading'); $('#loading').textContent = 'Invalid request link.'; return; }
    try { showGrant(await api('/api/grants/' + grantId)); }
    catch (error) {
      if (error.status === 401 || error.status === 403) {
        await showLogin();
        if (fromLogin) $('#login-error').textContent = 'That credential was not accepted.';
      }
      else { show('loading'); $('#loading').textContent = error.message; }
    }
  }

  $('#login-form').onsubmit = async event => {
    event.preventDefault();
    $('#login-error').textContent = '';
    try {
      if (event.currentTarget.dataset.otp === 'true') {
        token = (await api('/api/auth/verify','POST',{code:$('#login-value').value})).session;
      } else token = $('#login-value').value.trim();
      sessionStorage.setItem('hilait-token', token);
      $('#login-value').value = '';
      await load(true);
    } catch (error) { $('#login-error').textContent = error.message; }
  };

  async function decide(action) {
    $('#decision-error').textContent = '';
    $('#host-key').classList.add('hidden');
    const form = $('#decision-form');
    if (action === 'approve' && !form.reportValidity()) return;
    const buttons = form.querySelectorAll('button');
    buttons.forEach(button => button.disabled = true);
    const payload = action === 'approve' ? {
      ...(form.elements.duration_hours.value ? {duration_hours:Number(form.elements.duration_hours.value)} : {}),
      ...(form.elements.local_folder.value ? {local_folder:form.elements.local_folder.value} : {}),
      ...(form.elements.secret.value ? {secret:form.elements.secret.value} : {})
    } : {};
    try {
      const grant = await api(`/api/grants/${grantId}/${action}`,'POST',payload);
      form.elements.secret.value = '';
      history.replaceState(null, '', location.pathname);
      showGrant(grant);
      $('#request-state').textContent = action === 'approve' ? 'Approved. The SSH connection is open in Hilait.' : 'Denied. The agent was not connected.';
    } catch (error) {
      if (error.details?.fingerprint && action === 'approve') {
        pendingHost = error.details;
        $('#fingerprint').textContent = pendingHost.fingerprint;
        $('#previous-key').textContent = pendingHost.previous ? 'Previously trusted: ' + pendingHost.previous : '';
        $('#host-key').classList.remove('hidden');
      } else if (error.status === 401 || error.status === 403 && error.details?.detail?.code === 'otp_required') {
        await showLogin();
      } else $('#decision-error').textContent = error.message;
    } finally { buttons.forEach(button => button.disabled = false); }
  }

  $('#decision-form').onsubmit = event => { event.preventDefault(); decide('approve'); };
  $('#deny').onclick = () => decide('reject');
  $('#host-cancel').onclick = () => { pendingHost = null; $('#host-key').classList.add('hidden'); };
  $('#host-trust').onclick = async () => {
    if (!pendingHost) return;
    try {
      await api('/api/hosts/trust','POST',{host:pendingHost.host,fingerprint:pendingHost.fingerprint});
      pendingHost = null;
      await decide('approve');
    } catch (error) { $('#decision-error').textContent = error.message; }
  };
  load();
})();
