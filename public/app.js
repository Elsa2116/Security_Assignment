// Keep browser behavior intentionally small: all identity and data decisions remain server-side.
const statusBox = document.querySelector('#status');

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
  statusBox.style.color = error ? '#b42318' : '#b7791f';
};

// Switch between the focused registration and sign-in states without duplicating pages.
function showAuthForm(form) {
  document.querySelector('#register').classList.toggle('hidden', form !== 'register');
  document.querySelector('#login').classList.toggle('hidden', form !== 'login');
  statusBox.textContent = '';
}

// Verification redirects back here with a safe, non-sensitive status marker.
if (new URLSearchParams(window.location.search).get('verified') === '1') {
  showAuthForm('login');
  showStatus('Your email is verified. You can sign in now.');
  window.history.replaceState({}, document.title, window.location.pathname);
}

document.querySelector('#show-login').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('login');
});
document.querySelector('#show-register').addEventListener('click', event => {
  event.preventDefault();
  showAuthForm('register');
});

// Send same-origin JSON requests while preserving Better Auth cookies.
async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'include',
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body.data ?? body;
}

// Supply a per-request CSRF proof for state-changing application calls.
function csrfHeaders() {
  return { 'x-csrf-token': crypto.randomUUID() };
}

// Load real session/profile/request data and switch to the authenticated dashboard.
async function loadDashboard() {
  try {
    const profile = await api('/api/v1/me');
    const requests = await api('/api/v1/requests');
    document.querySelector('#profile').textContent = JSON.stringify(profile, null, 2);
    document.querySelector('#requests').textContent = JSON.stringify(requests, null, 2);
    document.querySelector('#auth').style.display = 'none';
    document.querySelector('#dashboard').style.display = 'grid';
    document.querySelector('#logout').hidden = false;
    showStatus('Signed in.');
  } catch {
    // Anonymous visitors stay on the registration/sign-in view.
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

// Sign out through Better Auth so the server revokes the session and clears cookies.
document.querySelector('#logout').addEventListener('click', async () => {
  try {
    await api('/api/auth/sign-out', { method: 'POST', headers: csrfHeaders(), body: '{}' });
    location.reload();
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
        payload: JSON.parse(document.querySelector('#request-payload').value)
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
