// Passkey (fingerprint) step-up for approvals, shared by the workspace and the
// phone approval page. Each page routes its API calls through attach(), which
// asks the server whether this approval needs a passkey and, if so, adds a
// WebAuthn assertion bound to that exact action and target.
(() => {
  const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
  const id = value => decodeURIComponent(value);

  function stepFor(path, method, body) {
    if (method !== 'POST') return null;
    let match;
    if ((match = path.match(/^\/api\/grants\/([^/]+)\/approve$/))) return {action: 'grant_approve', target: id(match[1])};
    if ((match = path.match(/^\/api\/sudo\/([^/]+)\/decide$/))) return body?.approved ? {action: 'sudo_approve', target: id(match[1])} : null;
    if (path === '/api/authorizations') return {action: 'authorization_create', target: `${body?.agent_id || ''}/${body?.profile_id || ''}/${body?.privilege || ''}`};
    if ((match = path.match(/^\/api\/authorizations\/([^/]+)\/extend$/))) return {action: 'authorization_extend', target: id(match[1])};
    if ((match = path.match(/^\/api\/authorizations\/([^/]+)\/file-access$/))) return {action: 'authorization_file_access', target: id(match[1]), file_access: body?.file_access};
    if ((match = path.match(/^\/api\/agent-enrollment\/([^/]+)\/approve$/))) return {action: 'agent_token_approve', target: id(match[1])};
    return null;
  }

  function friendly(error) {
    if (error?.name === 'NotAllowedError') return new Error('The fingerprint check was cancelled or timed out.');
    if (error?.name === 'SecurityError') return new Error('Passkeys work only at the Hilait address set in Settings → Security.');
    if (error?.name === 'InvalidStateError') return new Error('This passkey is already registered.');
    return error instanceof Error ? error : new Error(String(error));
  }

  function supported() { return Boolean(window.PublicKeyCredential && window.isSecureContext && navigator.credentials); }

  async function assert(options) {
    if (!supported()) throw new Error('This page cannot use passkeys. Open Hilait at its HTTPS address (Settings → Security).');
    let credential;
    try {
      credential = await navigator.credentials.get({publicKey: {...options, challenge: decode(options.challenge),
        allowCredentials: options.allowCredentials.map(item => ({...item, id: decode(item.id)}))}});
    } catch (error) { throw friendly(error); }
    const response = credential.response;
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      response: {clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(response.authenticatorData),
        signature: encode(response.signature), userHandle: response.userHandle ? encode(response.userHandle) : null}};
  }

  async function create(options) {
    if (!supported()) throw new Error('This page cannot use passkeys. Open Hilait at its HTTPS address.');
    let credential;
    try {
      credential = await navigator.credentials.create({publicKey: {...options, challenge: decode(options.challenge),
        user: {...options.user, id: decode(options.user.id)},
        excludeCredentials: options.excludeCredentials.map(item => ({...item, id: decode(item.id)}))}});
    } catch (error) { throw friendly(error); }
    return {id: credential.id, rawId: encode(credential.rawId), type: credential.type,
      response: {clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject)}};
  }

  // call(path, method, body) must send a request without passing back through attach().
  async function attach(path, method, body, call) {
    const step = stepFor(path, method, body);
    if (!step) return body;
    const challenge = await call('/api/passkeys/challenge', 'POST', step);
    if (!challenge.required) return body;
    return {...(body || {}), passkey: await assert(challenge.options)};
  }

  // Sign in with a passkey instead of an authenticator code. Returns a session token.
  async function signIn(call) {
    const options = await call('/api/auth/passkey/options', 'POST', {});
    return (await call('/api/auth/passkey/verify', 'POST', {passkey: await assert(options)})).session;
  }

  // Show a passkey sign-in button only where it can work: passkeys exist and this page is at their address.
  function offerSignIn(mode) {
    return Boolean(mode?.passkey && mode.passkey_origin === location.origin && supported());
  }

  window.HilaitPasskey = {attach, create, supported, signIn, offerSignIn};
})();
