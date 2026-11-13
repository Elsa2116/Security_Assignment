// Keep browser behavior intentionally small: all identity and data decisions remain server-side.
const statusBox = document.querySelector('#status');

// Convert internal RBAC codes into clear product language for end users.
const roleLabels = {
  ADMIN: 'Organization administrator',
  USER: 'Employee',
  MANAGER: 'Department manager',
  SECURITY_ADMIN: 'Security administrator',
  SECURITY_REVIEWER: 'Security reviewer',
  AUDITOR: 'Auditor'
};
const formatRoles = roles => roles?.length ? roles.map(role => roleLabels[role] || role).join(', ') : 'No role assigned';
const viewLabels = { overview: 'Overview', requests: 'My requests', 'new-request': 'New request', admin: 'Admin console', 'admin-security': 'Security center', settings: 'Settings', help: 'Help center' };

// Toggle password visibility locally; the value is never sent anywhere except the auth request.
document.querySelectorAll('.toggle-password').forEach(button => {
  const eye = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"></path><circle cx="12" cy="12" r="2.5"></circle></svg>';
  const eyeOff = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18"></path><path d="M10.6 6.2A10.8 10.8 0 0 1 12 6c6.5 0 10 6 10 6a17.6 17.6 0 0 1-3.2 3.8"></path><path d="M6.2 6.3C3.5 8.1 2 12 2 12s3.5 6 10 6a10.8 10.8 0 0 0 3.4-.5"></path></svg>';
  button.innerHTML = eye;
  button.addEventListener('click', () => {
    const input = document.querySelector(`#${button.dataset.target}`);
    const visible = input.type === 'text';
    input.type = visible ? 'password' : 'text';
    button.innerHTML = visible ? eye : eyeOff;
    button.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
    button.title = visible ? 'Show password' : 'Hide password';
  });
});

// Show non-sensitive feedback from the API without exposing response internals.
const showStatus = (message, error = false) => {
  statusBox.textContent = message;
  statusBox.style.display = 'block';
  statusBox.style.color = error ? '#b42318' : '#b7791f';
};

// Switch between the focused registration and sign-in states without duplicating pages.
function showAuthForm(form) {
  document.querySelector('#register').classList.toggle('hidden', form !== 'register');
  document.querySelector('#login').classList.toggle('hidden', form !== 'login');
  document.querySelector('#forgot-password').classList.toggle('hidden', form !== 'forgot-password');
  document.querySelector('#reset-password').classList.toggle('hidden', form !== 'reset-password');
  document.querySelector('#mfa-challenge').classList.toggle('hidden', form !== 'mfa-challenge');
  statusBox.textContent = '';
  statusBox.style.display = 'none';
}

// Switch workspace panels locally; authorization remains enforced by the API for every data operation.
document.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => {
  const view = item.dataset.view;
  document.querySelector('#current-view-label').textContent = viewLabels[view] || 'Overview';
  document.querySelectorAll('.nav-item').forEach(nav => nav.classList.toggle('active', nav === item));
  const employeeView = ['overview', 'requests', 'new-request'].includes(view);
  document.querySelector('.dashboard-wrap').style.display = employeeView ? 'block' : 'none';
  document.querySelector('#dashboard').style.display = ['requests', 'new-request'].includes(view) ? 'grid' : 'none';
  document.querySelector('#overview-panel').classList.toggle('active', view === 'overview');
  document.querySelector('#request-form').hidden = view !== 'new-request';
  document.querySelector('#requests').closest('.requests-card').hidden = view !== 'requests';
  document.querySelector('#admin-panel').classList.toggle('active', view === 'admin');
  document.querySelector('#admin-security-panel').classList.toggle('active', view === 'admin-security');
  document.querySelector('#settings-panel').classList.toggle('active', view === 'settings');
  document.querySelector('#help-panel').classList.toggle('active', view === 'help');
  if (view === 'admin') void loadAdminPanel();
  if (view === 'admin-security') void loadAdminSecurity();
  if (view === 'settings') void loadSecuritySettings();
  if (view === 'new-request') document.querySelector('#request-form').scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (view === 'requests') document.querySelector('#requests').scrollIntoView({ behavior: 'smooth', block: 'center' });
}));

// Overview quick actions use the same guarded navigation as the sidebar.
document.querySelector('#overview-new-request').addEventListener('click', () => document.querySelector('[data-view="new-request"]').click());
document.querySelector('#overview-my-requests').addEventListener('click', () => document.querySelector('[data-view="requests"]').click());
document.querySelector('#overview-admin-console').addEventListener('click', () => document.querySelector('[data-view="admin"]').click());
document.querySelector('#overview-admin-settings').addEventListener('click', () => document.querySelector('[data-view="settings"]').click());
document.querySelector('#header-new-request').addEventListener('click', () => document.querySelector('[data-view="new-request"]').click());

// Search the currently loaded real request/member rows without inventing client-side data.
document.querySelector('#global-search').addEventListener('input', event => {
  const term = event.target.value.trim().toLowerCase();
  document.querySelectorAll('.admin-item, .request-item').forEach(item => { item.hidden = Boolean(term) && !item.textContent.toLowerCase().includes(term); });
});

// Verification and password-reset redirects return here with short-lived, non-sensitive navigation markers.
const initialQuery = new URLSearchParams(window.location.search);
let pendingResetToken = initialQuery.get('token');
if (initialQuery.get('reset') === '1' && pendingResetToken) {
  showAuthForm('reset-password');
  window.history.replaceState({}, document.title, window.location.pathname);
} else if (initialQuery.get('verified') === '1') {
  showAuthForm('login');
  showStatus('Your email is verified. You can sign in now.');
  window.history.replaceState({}, document.title, window.location.pathname);
} else if (initialQuery.get('signin') === '1') {
  // Sign-out always returns to the sign-in form instead of the registration form.
  showAuthForm('login');
  window.history.replaceState({}, document.title, window.location.pathname);
}

// Load the organization security center from restricted PostgreSQL-backed admin endpoints.
async function loadAdminSecurity() {
  try {
    const [integrity, audit, alerts, incidents] = await Promise.all([api('/api/v1/admin/audit/integrity'), api('/api/v1/admin/audit'), api('/api/v1/admin/alerts'), api('/api/v1/admin/incidents')]);
    document.querySelector('#audit-integrity').textContent = integrity.valid ? `Valid chain · ${integrity.checked} entries checked` : 'Integrity failure detected';
    const render = (selector, rows, empty, mapper) => { const box = document.querySelector(selector); box.replaceChildren(); if (!rows.length) { box.textContent = empty; return; } rows.forEach(row => { const item = document.createElement('div'); item.className = 'security-item'; mapper(row, item); box.append(item); }); };
    render('#audit-list', audit, 'No audit events recorded.', (row, item) => { const title = document.createElement('strong'); title.textContent = row.action; const detail = document.createElement('span'); detail.textContent = `${row.outcome} · ${new Date(row.occurredAt).toLocaleString()}`; item.append(title, detail); });
    render('#alert-list', alerts, 'No security alerts recorded.', (row, item) => { const title = document.createElement('strong'); title.textContent = `${row.severity} · ${row.rule}`; const detail = document.createElement('span'); detail.textContent = row.acknowledgedAt ? `Acknowledged ${new Date(row.acknowledgedAt).toLocaleString()}` : 'Unacknowledged'; item.append(title, detail); if (!row.acknowledgedAt) { const button = document.createElement('button'); button.className = 'secondary'; button.textContent = 'Acknowledge'; button.addEventListener('click', async () => { await api(`/api/v1/admin/alerts/${row.id}`, { method: 'PATCH', headers: csrfHeaders(), body: JSON.stringify({ action: 'ACKNOWLEDGE' }) }); await loadAdminSecurity(); }); item.append(button); } });
    render('#incident-list', incidents, 'No incidents recorded.', (row, item) => { const title = document.createElement('strong'); title.textContent = `${row.severity} · ${row.status}`; const detail = document.createElement('span'); detail.textContent = row.summary; item.append(title, detail); });
  } catch (error) { showStatus(error.message, true); }
}

document.querySelector('#show-login').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('login');
});
document.querySelector('#show-register').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('register');
});
document.querySelector('#show-forgot-password').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('forgot-password');
});
document.querySelector('#back-to-login').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('login');
});
document.querySelector('#reset-back-to-login').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('login');
});
document.querySelector('#mfa-back-to-login').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('login');
});

// Send same-origin JSON requests while preserving Better Auth cookies.
async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'include',
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) { const error = new Error(body?.error?.message || `Request failed (${response.status})`); error.code = body?.error?.code; throw error; }
  return body.data ?? body;
}

// Supply a per-request CSRF proof for state-changing application calls.
function csrfHeaders() {
  return { 'x-csrf-token': crypto.randomUUID() };
}

// Render live MFA and session controls from PostgreSQL-backed API responses; no security state is fabricated in the browser.
async function loadSecuritySettings() {
  const panel = document.querySelector('#settings-panel');
  const grid = panel.querySelector('.settings-grid');
  if (!grid || grid.dataset.loaded === 'true') return;
  grid.dataset.loaded = 'true';
  // Replace the initial presentation-only security rows with live controls below.
  [...grid.querySelectorAll('.settings-row')].filter(row => /Multi-factor authentication|Session security/.test(row.textContent || '')).forEach(row => row.remove());
  const mfaRow = document.createElement('div'); mfaRow.className = 'settings-row';
  const mfaCopy = document.createElement('div'); const mfaTitle = document.createElement('strong'); mfaTitle.textContent = 'Multi-factor authentication'; const mfaHelp = document.createElement('span'); mfaHelp.textContent = 'Protect sign-in with a TOTP authenticator and recovery codes.'; mfaCopy.append(mfaTitle, mfaHelp);
  const mfaActions = document.createElement('div'); mfaActions.className = 'settings-actions'; const mfaStatus = document.createElement('span'); mfaStatus.className = 'status-chip'; mfaStatus.textContent = 'Loading'; const mfaButton = document.createElement('button'); mfaButton.className = 'secondary'; mfaButton.type = 'button'; mfaButton.textContent = 'Set up MFA'; mfaActions.append(mfaStatus, mfaButton); mfaRow.append(mfaCopy, mfaActions);
  const sessionRow = document.createElement('div'); sessionRow.className = 'settings-row'; const sessionCopy = document.createElement('div'); const sessionTitle = document.createElement('strong'); sessionTitle.textContent = 'Active sessions'; const sessionHelp = document.createElement('span'); sessionHelp.textContent = 'Revoke sessions you no longer recognize.'; sessionCopy.append(sessionTitle, sessionHelp); const revokeAll = document.createElement('button'); revokeAll.className = 'secondary'; revokeAll.type = 'button'; revokeAll.textContent = 'Revoke all'; sessionRow.append(sessionCopy, revokeAll);
  const sessions = document.createElement('div'); sessions.className = 'session-list'; sessions.textContent = 'Loading sessions…'; grid.append(mfaRow, sessionRow, sessions);
  try {
    const mfa = await api('/api/v1/auth/mfa/status'); mfaStatus.textContent = mfa.enabled ? `Enabled · ${mfa.recoveryCodesRemaining} codes` : 'Not enabled'; mfaButton.textContent = mfa.enabled ? 'Regenerate setup' : 'Set up MFA';
    mfaButton.addEventListener('click', async () => { try { const enrollment = await api('/api/v1/auth/mfa/enroll', { method: 'POST', headers: csrfHeaders(), body: '{}' }); const code = window.prompt(`Scan this authenticator URI, then enter the six-digit code:\n${enrollment.otpauthUrl}`); if (!code) return; const confirmed = await api('/api/v1/auth/mfa/confirm', { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ code }) }); window.alert(`Save these recovery codes securely:\n${confirmed.recoveryCodes.join('\n')}`); showStatus('MFA enabled successfully.'); await loadSecuritySettings(); } catch (error) { showStatus(error.message, true); } });
    const rows = await api('/api/v1/auth/sessions'); sessions.replaceChildren();
    if (!rows.length) { sessions.textContent = 'No active sessions found.'; } else rows.forEach(session => { const item = document.createElement('div'); item.className = 'session-item'; const label = document.createElement('span'); label.textContent = `${session.userAgent || 'Browser session'} · ${session.ipAddress || 'Unknown IP'}`; const revoke = document.createElement('button'); revoke.className = 'secondary'; revoke.type = 'button'; revoke.textContent = 'Revoke'; revoke.addEventListener('click', async () => { await api(`/api/v1/auth/sessions/${session.id}`, { method: 'DELETE', headers: csrfHeaders() }); item.remove(); showStatus('Session revoked.'); }); item.append(label, revoke); sessions.append(item); });
    revokeAll.addEventListener('click', async () => { if (!window.confirm('Revoke all active sessions? You will need to sign in again.')) return; await api('/api/v1/auth/sessions/revoke-all', { method: 'POST', headers: csrfHeaders(), body: '{}' }); showStatus('All sessions revoked.'); window.location.assign('/?signin=1'); });
  } catch (error) { sessions.textContent = 'Security settings could not be loaded.'; showStatus(error.message, true); }
}

// Build the admin approval queue with real server data and safe text nodes.
async function loadAdminPanel() {
  try {
    const [overview, members, directory] = await Promise.all([api('/api/v1/admin/overview'), api('/api/v1/admin/members'), api('/api/v1/admin/directory')]);
    // Admin overview metrics come from the organization-wide SQL aggregate, not employee-owned requests.
    document.querySelector('#stat-total').textContent = String(overview.totalRequests ?? 0);
    document.querySelector('#stat-pending').textContent = String(overview.pendingRequests ?? 0);
    document.querySelector('#stat-access').textContent = 'Admin';
    document.querySelector('#admin-pending-count').textContent = String(overview.pendingRequests ?? 0);
    document.querySelector('#admin-approved-count').textContent = String(overview.approvedRequests ?? 0);
    const pendingMembers = members.filter(member => member.status === 'PENDING_ADMISSION');
    document.querySelector('#admin-member-count').textContent = String(pendingMembers.length);
    const queue = document.querySelector('#admin-queue'); queue.replaceChildren();
    if (!overview.pending?.length) { const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = 'No requests are waiting for approval.'; queue.append(empty); }
    overview.pending?.forEach(request => {
      const item = document.createElement('article'); item.className = 'admin-item';
      const header = document.createElement('div'); header.className = 'admin-item-header';
      const title = document.createElement('strong'); title.textContent = request.title;
      const status = document.createElement('span'); status.className = 'status-chip'; status.textContent = 'PENDING'; header.append(title, status);
      const description = document.createElement('p'); description.textContent = request.description || 'No description provided.';
      const meta = document.createElement('div'); meta.className = 'admin-meta'; meta.textContent = `${request.requesterName} · ${request.requesterEmail} · ${request.departmentName || 'Unassigned department'}`;
      const actions = document.createElement('div'); actions.className = 'admin-actions';
      const approve = document.createElement('button'); approve.textContent = 'Approve'; approve.addEventListener('click', () => void decideAdminRequest(request, 'approve'));
      const reject = document.createElement('button'); reject.className = 'danger'; reject.textContent = 'Reject'; reject.addEventListener('click', () => void decideAdminRequest(request, 'reject'));
      actions.append(approve, reject); item.append(header, description, meta, actions); queue.append(item);
    });
    const membersBox = document.querySelector('#admin-members'); membersBox.replaceChildren();
    if (!pendingMembers.length) { const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = 'No verified users are waiting for admission.'; membersBox.append(empty); }
    pendingMembers.forEach(member => {
      const item = document.createElement('article'); item.className = 'admin-item';
      const header = document.createElement('div'); header.className = 'admin-item-header';
      const title = document.createElement('strong'); title.textContent = member.name;
      const status = document.createElement('span'); status.className = 'status-chip'; status.textContent = member.emailVerified ? 'VERIFIED' : 'VERIFY EMAIL'; header.append(title, status);
      const email = document.createElement('p'); email.textContent = member.email;
      const organization = document.createElement('select'); directory.organizations.forEach(org => { const option = document.createElement('option'); option.value = org.id; option.textContent = org.name; organization.append(option); });
      const department = document.createElement('select');
      const refreshDepartments = () => { department.replaceChildren(); directory.departments.filter(dep => dep.organizationId === organization.value).forEach(dep => { const option = document.createElement('option'); option.value = dep.id; option.textContent = dep.name; department.append(option); }); };
      organization.addEventListener('change', refreshDepartments); refreshDepartments();
      const actions = document.createElement('div'); actions.className = 'admin-actions';
      const admit = document.createElement('button'); admit.textContent = 'Admit member'; admit.disabled = !member.emailVerified; admit.addEventListener('click', async () => { try { await api(`/api/v1/admin/members/${member.userId}/admit`, { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ organizationId: organization.value, departmentId: department.value }) }); showStatus(`${member.name} was admitted to the organization.`); await loadAdminPanel(); } catch (error) { showStatus(error.message, true); } });
      actions.append(organization, department, admit); item.append(header, email, actions); membersBox.append(item);
    });
  } catch (error) { showStatus(error.message, true); }
}

// Approval decisions always include the server's optimistic version and an idempotency key.
async function decideAdminRequest(request, decision) {
  const reason = decision === 'reject' ? window.prompt('Reason for rejection:') : '';
  if (decision === 'reject' && !reason) return;
  try {
    await api(`/api/v1/requests/${request.id}/${decision}`, { method: 'POST', headers: { ...csrfHeaders(), 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ expectedVersion: request.version, comment: reason || '' , reason: reason || undefined }) });
    showStatus(`Request ${decision === 'approve' ? 'approved' : 'rejected'}.`);
    await loadAdminPanel();
  } catch (error) { showStatus(error.message, true); }
}

// Load real session/profile/request data and switch to the authenticated dashboard.
async function loadDashboard() {
  try {
    const profile = await api('/api/v1/me');
    const requests = await api('/api/v1/requests');
    document.querySelector('#current-user-name').textContent = profile.name || profile.email || 'SecureFlow user';
    document.querySelector('#current-user-role').textContent = formatRoles(profile.roles);
    document.querySelector('#user-avatar').textContent = (profile.name || profile.email || 'S').slice(0, 1).toUpperCase();
    // Render server data as text nodes so user-controlled values cannot become HTML.
    const profileBox = document.querySelector('#profile');
    profileBox.replaceChildren();
    [['Name', profile.name], ['Email', profile.email], ['Status', profile.status], ['Organization', profile.organizationName || 'Not assigned'], ['Department', profile.departmentName || 'Not assigned'], ['Access level', formatRoles(profile.roles)]].forEach(([label, value]) => {
      const row = document.createElement('div');
      row.className = 'profile-row';
      const name = document.createElement('span'); name.className = 'profile-label'; name.textContent = label;
      const detail = document.createElement('span'); detail.className = 'profile-value'; detail.textContent = String(value ?? '—');
      if (label === 'Status') detail.className = 'status-chip';
      row.append(name, detail); profileBox.append(row);
    });
    const requestBox = document.querySelector('#requests');
    requestBox.replaceChildren();
    const requestRows = Array.isArray(requests) ? requests : (requests.items || []);
    // Keep the summary cards derived from the same server response as the request list.
    document.querySelector('#stat-total').textContent = String(requestRows.length);
    document.querySelector('#stat-pending').textContent = String(requestRows.filter(request => ['PENDING', 'SUBMITTED', 'IN_REVIEW'].includes(request.status)).length);
    document.querySelector('#stat-approved').textContent = String(requestRows.filter(request => request.status === 'APPROVED').length);
    document.querySelector('#stat-access').textContent = profile.status === 'ACTIVE' ? 'Active' : 'Pending';
    if (!requestRows.length) {
      const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = 'No requests yet. Create your first request to get started.'; requestBox.append(empty);
    } else requestRows.forEach(request => {
      const item = document.createElement('div'); item.className = 'request-item';
      const title = document.createElement('strong'); title.textContent = request.title || request.type || 'Request';
      const details = document.createElement('span'); details.textContent = `${request.type || 'REQUEST'} · ${request.status || 'SUBMITTED'}`;
      item.append(title, details); requestBox.append(item);
    });
    document.querySelector('#auth').style.display = 'none';
    document.body.classList.add('authenticated');
    document.querySelector('#app-shell').style.display = 'grid';
    document.querySelector('#dashboard').style.display = 'grid';
    document.querySelector('#logout').hidden = false;
    const admin = profile.roles?.some(role => ['ADMIN', 'SECURITY_ADMIN'].includes(role));
    document.querySelector('#admin-nav').hidden = !admin;
    document.querySelector('#admin-security-nav').hidden = !admin;
    // Keep role boundaries visible in the UI: admins manage workflows, employees submit them.
    document.querySelector('#new-request-nav').hidden = admin;
    document.querySelector('#my-requests-nav').hidden = admin;
    document.querySelector('#request-form').hidden = admin;
    document.querySelector('#header-new-request').hidden = admin;
    document.querySelector('#employee-overview-copy').hidden = admin;
    document.querySelector('#admin-overview-copy').hidden = !admin;
    document.querySelector('#workspace-title').textContent = admin ? 'Organization admin dashboard' : `Welcome back, ${profile.name || 'SecureFlow user'}`;
    document.querySelector('#workspace-subtitle').textContent = admin ? 'Review requests, manage members, and protect organization access.' : 'Track your requests and approval decisions in one secure workspace.';
    document.querySelector('#process-title').textContent = admin ? 'Admin responsibilities' : 'How it works';
    document.querySelector('#process-copy').textContent = admin ? 'Review every decision with requester context, admit verified employees, and keep a complete audit trail for your organization.' : 'Submit a request with a clear business reason. Your organization approver reviews it, records a decision, and SecureFlow notifies you of the outcome.';
    const requestedView = new URLSearchParams(window.location.search).get('view');
    if (admin) {
      const target = ['settings', 'help', 'admin-security'].includes(requestedView || '') ? requestedView : 'admin';
      document.querySelector(`[data-view="${target}"]`).click();
      void loadAdminPanel();
    } else {
      const target = ['overview', 'requests', 'new-request', 'settings', 'help'].includes(requestedView || '') ? requestedView : 'overview';
      document.querySelector(`[data-view="${target}"]`).click();
    }
  } catch (error) {
    if (error.code === 'MFA_REQUIRED') { showAuthForm('mfa-challenge'); showStatus('Enter your authenticator code to continue.'); }
    else { showAuthForm('login'); showStatus(error.message || 'Your session could not be opened. Please sign in again.', true); }
  }
}

// Register through Better Auth; verification is delivered to the local Mailpit inbox.
document.querySelector('#register').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const password = document.querySelector('#reg-password').value;
    const confirmation = document.querySelector('#reg-confirm-password').value;
    if (password !== confirmation) {
      showStatus('Passwords do not match. Please check both fields.', true);
      return;
    }
    const data = await api('/api/auth/sign-up/email', {
      method: 'POST',
      body: JSON.stringify({
        name: document.querySelector('#reg-name').value,
        email: document.querySelector('#reg-email').value,
        password,
        confirmPassword: confirmation,
        captchaToken: 'local-development-captcha'
      })
    });
    showStatus(`Registered ${data.user.email}. Verify the email in Mailpit, then sign in.`);
  } catch (error) {
    showStatus(error.message, true);
  }
});

// Start Better Auth's official password-reset flow; the worker delivers the reset email through the configured outbox.
document.querySelector('#forgot-password').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/auth/request-password-reset', { method: 'POST', body: JSON.stringify({ email: document.querySelector('#forgot-email').value, redirectTo: '/?reset=1' }) });
    showStatus('If the account exists, a password reset link was sent. Check Mailpit during local development.');
  } catch (error) {
    showStatus(error.message, true);
  }
});

// Complete the reset token flow through Better Auth; the server revokes existing sessions after success.
document.querySelector('#reset-password').addEventListener('submit', async event => {
  event.preventDefault();
  const password = document.querySelector('#reset-password-value').value;
  if (password !== document.querySelector('#reset-password-confirm').value) { showStatus('Passwords do not match. Please check both fields.', true); return; }
  try {
    await api('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ token: pendingResetToken, newPassword: password }) });
    pendingResetToken = null;
    showAuthForm('login');
    showStatus('Password updated. You can sign in now.');
  } catch (error) { showStatus(error.message, true); }
});

// Sign in through Better Auth and then render the authenticated application state.
document.querySelector('#login').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/auth/sign-in/email', {
      method: 'POST',
      body: JSON.stringify({
        email: document.querySelector('#login-email').value,
        password: document.querySelector('#login-password').value
      })
    });
    await loadDashboard();
  } catch (error) {
    showStatus(error.message, true);
  }
});

// Complete the enforced second factor before loading any protected dashboard data.
document.querySelector('#mfa-challenge').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    await api('/api/v1/auth/mfa/challenge', { method: 'POST', headers: csrfHeaders(), body: JSON.stringify({ code: document.querySelector('#mfa-code').value }) });
    showStatus('Identity verified.');
    await loadDashboard();
  } catch (error) { showStatus(error.message, true); }
});

// Sign out through Better Auth so the server revokes the session and clears cookies.
document.querySelector('#logout').addEventListener('click', async () => {
  try {
    await api('/api/auth/sign-out', { method: 'POST', headers: csrfHeaders(), body: '{}' });
    window.location.assign('/?signin=1');
  } catch (error) {
    showStatus(error.message, true);
  }
});

// Create a persisted request with a unique idempotency key.
document.querySelector('#request-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const result = await api('/api/v1/requests', {
      method: 'POST',
      headers: { ...csrfHeaders(), 'Idempotency-Key': crypto.randomUUID() },
      body: JSON.stringify({
        type: document.querySelector('#request-type').value,
        title: document.querySelector('#request-title').value,
        description: document.querySelector('#request-description').value,
        payload: { details: document.querySelector('#request-details').value }
      })
    });
    showStatus(`Request ${result.id} created.`);
    await loadDashboard();
  } catch (error) {
    showStatus(error.message, true);
  }
});

// Attempt session restoration when the page opens; anonymous users remain on auth forms.
loadDashboard();
