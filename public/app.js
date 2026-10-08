const state = {
  pendingLogin: null,
  authenticated: false,
  username: '',
  mfaEnabled: false,
  resetToken: null,
  users: [],
  page: 1,
  pageSize: 10,
  totalPages: 0,
  auditPage: 1,
  auditTotalPages: 0
};

const screenMap = {
  auth: document.getElementById('auth-screen'),
  main: document.getElementById('main-screen'),
  modal: document.getElementById('modal-screen')
};

const authForm = document.getElementById('auth-form');
const mfaLoginForm = document.getElementById('mfa-login-form');
const resetRequestForm = document.getElementById('reset-request-form');
const resetConfirmForm = document.getElementById('reset-confirm-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const authMessage = document.getElementById('auth-message');
const statusMessage = document.getElementById('status-message');
const listContainer = document.getElementById('list-container');
const modalHeader = document.getElementById('modal-header');
const modalBody = document.getElementById('modal-body');
const totalUsersEl = document.getElementById('total-users');
const phoneUsersEl = document.getElementById('phone-users');
const lastUpdatedEl = document.getElementById('last-updated');
const searchInput = document.getElementById('search-input');
const phoneFilter = document.getElementById('phone-filter');
const sortField = document.getElementById('sort-field');
const sortOrder = document.getElementById('sort-order');
const pageSummary = document.getElementById('page-summary');
const auditPanel = document.getElementById('audit-panel');
const auditContainer = document.getElementById('audit-container');
const securityPanel = document.getElementById('security-panel');
const mfaStatus = document.getElementById('mfa-status');
const mfaEnrollment = document.getElementById('mfa-enrollment');
const mfaSetupButton = document.getElementById('mfa-setup-btn');
const mfaDisableForm = document.getElementById('mfa-disable-form');

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function setScreen(name) {
  Object.entries(screenMap).forEach(([key, element]) => {
    const isActive = key === name;
    element.classList.toggle('active', isActive);
    if (key === 'modal') {
      element.classList.toggle('hidden', !isActive);
    }
  });
}

function setMessage(element, text, type = '') {
  element.textContent = text;
  element.className = 'message';
  if (type) {
    element.classList.add(type);
  }
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (error) {
      throw new Error('The server returned an invalid response.');
    }
  }

  if (!response.ok) {
    const message = response.status === 404 && path.startsWith('/api/auth')
      ? 'Authentication API was not found. Restart the updated server and hard-refresh this page.'
      : (payload?.error?.message || 'Request failed.');
    const error = new Error(message);
    error.status = response.status;
    if (response.status === 401 && state.authenticated &&
        (path.startsWith('/api/users') || path === '/api/auth/session')) {
      clearClientSession();
      setMessage(authMessage, 'Your session expired. Sign in again to continue.', 'error');
    }
    throw error;
  }

  return payload;
}

async function authenticate(event) {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    setMessage(authMessage, 'Username and password are required.', 'error');
    return;
  }

  state.pendingLogin = { username, password };
  setMessage(authMessage, 'Signing in…', '');

  try {
    const result = await apiRequest('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.pendingLogin)
    });
    if (result.mfaRequired) {
      authForm.hidden = true;
      document.getElementById('show-reset-btn').hidden = true;
      mfaLoginForm.hidden = false;
      document.getElementById('login-totp-code').focus();
      setMessage(authMessage, 'Enter the current code from your authenticator app.', '');
      return;
    }
    await completeLogin(username);
  } catch (error) {
    state.pendingLogin = null;
    setMessage(authMessage, error.message || 'Authentication failed.', 'error');
  }
}

async function completeLogin(username) {
  state.pendingLogin = null;
  state.authenticated = true;
  state.username = username;
  passwordInput.value = '';
  mfaLoginForm.hidden = true;
  authForm.hidden = false;
  document.getElementById('show-reset-btn').hidden = false;
  document.getElementById('login-totp-code').value = '';
  setMessage(authMessage, '', '');
  setScreen('main');
  document.getElementById('directory-heading').focus();
  try {
    await refreshSecurityStatus();
  } catch (error) {
    setMessage(statusMessage, error.message || 'Signed in, but account security status could not be loaded.', 'error');
  }
  await loadUsers();
}

function clearClientSession() {
  state.authenticated = false;
  state.pendingLogin = null;
  state.username = '';
  state.mfaEnabled = false;
  state.users = [];
  state.page = 1;
  state.totalCount = 0;
  state.totalPages = 0;
  renderSummary();
  listContainer.innerHTML = '';
  document.getElementById('login-totp-code').value = '';
  usernameInput.value = '';
  showAuthForm('login');
  securityPanel.hidden = true;
  showUserDirectory();
  closeModal();
  setScreen('auth');
  usernameInput.focus();
}

function showAuthForm(form) {
  authForm.hidden = form !== 'login';
  document.getElementById('show-reset-btn').hidden = form !== 'login';
  mfaLoginForm.hidden = form !== 'mfa';
  resetRequestForm.hidden = form !== 'reset-request';
  resetConfirmForm.hidden = form !== 'reset-confirm';
  setMessage(authMessage, '', '');
  const focusTargets = {
    login: usernameInput,
    mfa: document.getElementById('login-totp-code'),
    'reset-request': document.getElementById('reset-email'),
    'reset-confirm': document.getElementById('reset-new-password')
  };
  focusTargets[form].focus();
}

async function submitMfaLogin(event) {
  event.preventDefault();
  if (!state.pendingLogin) {
    showAuthForm('login');
    return;
  }

  try {
    await apiRequest('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...state.pendingLogin,
        totpCode: document.getElementById('login-totp-code').value.trim()
      })
    });
    await completeLogin(state.pendingLogin.username);
  } catch (error) {
    setMessage(authMessage, error.message || 'Authenticator verification failed.', 'error');
    document.getElementById('login-totp-code').select();
  }
}

async function requestPasswordReset(event) {
  event.preventDefault();
  try {
    const result = await apiRequest('/api/auth/password-reset/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: document.getElementById('reset-email').value.trim() })
    });
    setMessage(authMessage, result.message, 'success');
  } catch (error) {
    setMessage(authMessage, error.message || 'Unable to request a password reset.', 'error');
  }
}

async function confirmPasswordReset(event) {
  event.preventDefault();
  if (!state.resetToken) {
    setMessage(authMessage, 'This reset link is missing or expired. Request a new one.', 'error');
    return;
  }
  try {
    const result = await apiRequest('/api/auth/password-reset/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: state.resetToken,
        password: document.getElementById('reset-new-password').value
      })
    });
    state.resetToken = null;
    document.getElementById('reset-new-password').value = '';
    window.history.replaceState({}, document.title, window.location.pathname);
    showAuthForm('login');
    setMessage(authMessage, result.message, 'success');
  } catch (error) {
    setMessage(authMessage, error.message || 'Unable to update the password.', 'error');
  }
}

async function refreshSecurityStatus() {
  const result = await apiRequest('/api/auth/session');
  state.mfaEnabled = result.mfaEnabled;
  mfaEnrollment.hidden = true;
  mfaDisableForm.hidden = !state.mfaEnabled;
  mfaSetupButton.hidden = state.mfaEnabled;
  setMessage(
    mfaStatus,
    state.mfaEnabled
      ? 'Authenticator-based multi-factor authentication is enabled.'
      : 'Multi-factor authentication is not enabled.',
    state.mfaEnabled ? 'success' : ''
  );
}

async function showSecuritySettings() {
  try {
    document.querySelector('.content-panel:not(.audit-panel):not(#security-panel)').hidden = true;
    auditPanel.hidden = true;
    securityPanel.hidden = false;
    await refreshSecurityStatus();
  } catch (error) {
    setMessage(mfaStatus, error.message || 'Unable to load security settings.', 'error');
  } finally {
    document.getElementById('security-heading').focus();
  }
}

async function setupMfa() {
  mfaSetupButton.disabled = true;
  try {
    const result = await apiRequest('/api/auth/mfa/setup', { method: 'POST' });
    document.getElementById('mfa-qr-code').src = result.qrCodeDataUrl;
    document.getElementById('mfa-manual-key').textContent = result.secret;
    mfaEnrollment.hidden = false;
    document.getElementById('mfa-setup-code').focus();
    setMessage(mfaStatus, 'Scan the QR code, then verify a current code to enable MFA.', '');
  } catch (error) {
    setMessage(mfaStatus, error.message || 'Unable to start MFA setup.', 'error');
  } finally {
    mfaSetupButton.disabled = false;
  }
}

async function verifyMfaSetup(event) {
  event.preventDefault();
  try {
    await apiRequest('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: document.getElementById('mfa-setup-code').value.trim() })
    });
    state.mfaEnabled = true;
    document.getElementById('mfa-setup-code').value = '';
    document.getElementById('mfa-qr-code').removeAttribute('src');
    document.getElementById('mfa-manual-key').textContent = '';
    mfaEnrollment.hidden = true;
    mfaSetupButton.hidden = true;
    mfaDisableForm.hidden = false;
    setMessage(mfaStatus, 'MFA is enabled. You will need an authenticator code each time you sign in.', 'success');
    mfaStatus.focus();
  } catch (error) {
    setMessage(mfaStatus, error.message || 'Unable to verify the authenticator code.', 'error');
  }
}

async function disableMfa(event) {
  event.preventDefault();
  try {
    await apiRequest('/api/auth/mfa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: document.getElementById('mfa-disable-code').value.trim() })
    });
    state.mfaEnabled = false;
    document.getElementById('mfa-disable-code').value = '';
    mfaDisableForm.hidden = true;
    mfaSetupButton.hidden = false;
    setMessage(mfaStatus, 'MFA is disabled.', 'success');
    mfaStatus.focus();
  } catch (error) {
    setMessage(mfaStatus, error.message || 'Unable to disable MFA.', 'error');
  }
}

function renderSummary() {
  totalUsersEl.textContent = String(state.totalCount ?? state.users.length);
  phoneUsersEl.textContent = String(state.users.filter((user) => user.phone).length);

  const latestUser = [...state.users].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))[0];
  lastUpdatedEl.textContent = latestUser ? new Date(latestUser.updatedAt).toLocaleDateString() : '—';
}

function renderPagination(meta) {
  state.totalPages = meta.totalPages;
  state.totalCount = meta.total;
  pageSummary.textContent = meta.total
    ? `Page ${meta.page} of ${meta.totalPages} · ${meta.total} matching users`
    : 'No matching users';
  document.getElementById('previous-page-btn').disabled = meta.page <= 1;
  document.getElementById('next-page-btn').disabled = meta.page >= meta.totalPages;
}

async function loadUsers() {
  try {
    const params = new URLSearchParams({
      page: String(state.page),
      limit: String(state.pageSize),
      sort: sortField.value,
      order: sortOrder.value
    });
    if (searchInput.value.trim()) params.set('q', searchInput.value.trim());
    if (phoneFilter.value) params.set('hasPhone', phoneFilter.value);

    const payload = await apiRequest(`/api/users?${params.toString()}`);
    if (!Array.isArray(payload.data)) {
      throw new Error('The server returned an invalid user list. Restart the API server and try again.');
    }

    let meta = payload.meta;
    let users = payload.data;
    if (!meta || !Number.isInteger(meta.total) || !Number.isInteger(meta.totalPages)) {
      const search = searchInput.value.trim().toLocaleLowerCase();
      users = users.filter((user) => {
        const matchesSearch = !search ||
          user.name.toLocaleLowerCase().includes(search) ||
          user.email.toLocaleLowerCase().includes(search);
        const matchesPhone = !phoneFilter.value ||
          (phoneFilter.value === 'true' ? Boolean(user.phone) : !user.phone);
        return matchesSearch && matchesPhone;
      });
      users.sort((left, right) => {
        const a = left[sortField.value];
        const b = right[sortField.value];
        const comparison = sortField.value === 'name' || sortField.value === 'email'
          ? String(a).localeCompare(String(b))
          : new Date(a) - new Date(b);
        return sortOrder.value === 'asc' ? comparison : -comparison;
      });
      const total = users.length;
      const totalPages = Math.ceil(total / state.pageSize);
      meta = {
        page: state.page,
        limit: state.pageSize,
        total,
        totalPages,
        sort: sortField.value,
        order: sortOrder.value
      };
      users = users.slice((state.page - 1) * state.pageSize, state.page * state.pageSize);
    }

    if (meta.totalPages > 0 && state.page > meta.totalPages) {
      state.page = meta.totalPages;
      return loadUsers();
    }
    if (meta.totalPages === 0) state.page = 1;
    state.users = users;
    state.totalCount = meta.total;
    state.totalPages = meta.totalPages;
    renderSummary();
    renderUserList();
    renderPagination(meta);
    setMessage(statusMessage, '', '');
  } catch (error) {
    setMessage(statusMessage, error.message || 'Unable to load users.', 'error');
  }
}

async function loadAuditHistory() {
    try {
      const params = new URLSearchParams({ page: String(state.auditPage), limit: '10' });
      const payload = await apiRequest(`/api/users/audit?${params.toString()}`);
      state.auditTotalPages = payload.meta.totalPages;
      renderAuditHistory(payload.data || [], payload.meta);
    } catch (error) {
      auditContainer.textContent = error.message || 'Unable to load audit history.';
    }
}

function renderAuditHistory(entries, meta) {
    auditContainer.innerHTML = '';
    if (!entries.length) {
      auditContainer.innerHTML = '<div class="empty-state"><p>No audit events have been recorded.</p></div>';
    } else {
      const table = document.createElement('table');
      table.className = 'user-table';
      table.innerHTML = `
        <thead><tr><th>Action</th><th>User</th><th>Changed fields</th><th>Operator</th><th>When</th></tr></thead>
        <tbody></tbody>
      `;
      const tbody = table.querySelector('tbody');
      entries.forEach((entry) => {
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><span class="audit-action ${escapeHtml(entry.action)}">${escapeHtml(entry.action)}</span></td>
          <td>${escapeHtml(entry.userEmail)}<small class="subtext">${escapeHtml(entry.userId)}</small></td>
          <td>${escapeHtml((entry.changedFields || []).join(', ') || '—')}</td>
          <td>${escapeHtml(entry.actor)}</td>
          <td>${new Date(entry.createdAt).toLocaleString()}</td>
        `;
        tbody.appendChild(row);
      });
      auditContainer.appendChild(table);
    }

    document.getElementById('audit-page-summary').textContent = meta.total
      ? `Page ${meta.page} of ${meta.totalPages} · ${meta.total} events`
      : 'No audit events';
    document.getElementById('audit-previous-btn').disabled = meta.page <= 1;
    document.getElementById('audit-next-btn').disabled = meta.page >= meta.totalPages;
}

async function showAuditHistory() {
    document.querySelector('.content-panel:not(.audit-panel):not(#security-panel)').hidden = true;
    securityPanel.hidden = true;
    auditPanel.hidden = false;
    await loadAuditHistory();
    document.getElementById('audit-heading').focus();
}

function showUserDirectory() {
    document.querySelector('.content-panel:not(.audit-panel):not(#security-panel)').hidden = false;
    auditPanel.hidden = true;
    securityPanel.hidden = true;
    if (state.authenticated) {
      document.getElementById('add-user-btn').focus();
    }
}

function renderUserList() {
  listContainer.innerHTML = '';

  if (!state.users.length) {
    listContainer.innerHTML = `
      <div class="empty-state">
        <p>${searchInput.value || phoneFilter.value ? 'No users match these filters.' : 'No users found.'}</p>
        <button type="button" class="primary-btn" id="empty-add-user-btn">Add the first user</button>
      </div>
    `;

    const button = document.getElementById('empty-add-user-btn');
    button.addEventListener('click', openCreateModal);
    return;
  }

  const table = document.createElement('table');
  table.className = 'user-table';
  table.innerHTML = `
    <thead>
      <tr>
        <th>Name</th>
        <th>Email</th>
        <th>Phone</th>
        <th>Updated</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const tbody = table.querySelector('tbody');

  state.users.forEach((user) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="user-name">${escapeHtml(user.name)}</span></td>
      <td>${escapeHtml(user.email)}</td>
      <td>${escapeHtml(user.phone || 'Not provided')}</td>
      <td>${new Date(user.updatedAt).toLocaleDateString()}</td>
      <td>
        <div class="action-group">
          <button type="button" class="action-btn view" data-action="view" data-id="${user._id}">View</button>
          <button type="button" class="action-btn edit" data-action="edit" data-id="${user._id}">Edit</button>
          <button type="button" class="action-btn delete" data-action="delete" data-id="${user._id}">Delete</button>
        </div>
      </td>
    `;

    row.querySelectorAll('button').forEach((button) => {
      button.addEventListener('click', () => handleUserAction(button.dataset.action, user._id));
    });

    tbody.appendChild(row);
  });

  listContainer.appendChild(table);
}

async function handleUserAction(action, id) {
  if (action === 'view') {
    await openDetailsModal(id);
    return;
  }

  if (action === 'edit') {
    await openEditModal(id);
    return;
  }

  if (action === 'delete') {
    const user = state.users.find((item) => item._id === id);
    const targetName = user ? (user.name || user.email) : 'this user';
    const confirmDelete = window.confirm(`Delete ${targetName}?`);
    if (!confirmDelete) return;

    try {
      await apiRequest(`/api/users/${id}`, { method: 'DELETE' });
      setMessage(statusMessage, 'User deleted successfully.', 'success');
      await loadUsers();
    } catch (error) {
      setMessage(statusMessage, error.message, 'error');
    }
  }
}

function openCreateModal() {
  modalHeader.innerHTML = '<h3>Create User</h3>';
  modalBody.innerHTML = `
    <form id="user-form">
      <div class="form-grid">
        <label>
          Name
          <input type="text" name="name" placeholder="Full name" required />
        </label>
        <label>
          Email
          <input type="email" name="email" placeholder="user@example.com" required />
        </label>
        <label>
          Phone
          <input type="text" name="phone" placeholder="Optional" />
        </label>
      </div>
      <div class="form-actions">
        <button type="button" class="secondary-btn" id="cancel-form-btn">Cancel</button>
        <button type="submit" class="primary-btn">Save</button>
      </div>
    </form>
  `;

  const form = document.getElementById('user-form');
  document.getElementById('cancel-form-btn').addEventListener('click', closeModal);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = {
      name: form.elements.name.value.trim(),
      email: form.elements.email.value.trim(),
      phone: form.elements.phone.value.trim() || undefined
    };

    try {
      await apiRequest('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      closeModal();
      searchInput.value = '';
      phoneFilter.value = '';
      sortField.value = 'createdAt';
      sortOrder.value = 'desc';
      state.page = 1;
      setMessage(statusMessage, 'User created successfully.', 'success');
      await loadUsers();
    } catch (error) {
      setMessage(statusMessage, error.message, 'error');
    }
  });

  setScreen('modal');
}

async function openDetailsModal(id) {
  try {
    const payload = await apiRequest(`/api/users/${id}`);
    const user = payload.data;
    modalHeader.innerHTML = '<h3>User Details</h3>';
    modalBody.innerHTML = `
      <div class="detail-card">
        <div class="detail-row"><strong>ID</strong><span>${escapeHtml(user._id)}</span></div>
        <div class="detail-row"><strong>Name</strong><span>${escapeHtml(user.name)}</span></div>
        <div class="detail-row"><strong>Email</strong><span>${escapeHtml(user.email)}</span></div>
        <div class="detail-row"><strong>Phone</strong><span>${escapeHtml(user.phone || 'Not provided')}</span></div>
        <div class="detail-row"><strong>Created</strong><span>${new Date(user.createdAt).toLocaleString()} UTC</span></div>
        <div class="detail-row"><strong>Updated</strong><span>${new Date(user.updatedAt).toLocaleString()} UTC</span></div>
      </div>
      <div class="form-actions">
        <button type="button" class="secondary-btn" id="close-details-btn">Back</button>
        <button type="button" class="primary-btn" id="details-edit-btn">Edit</button>
      </div>
    `;

    document.getElementById('close-details-btn').addEventListener('click', closeModal);
    document.getElementById('details-edit-btn').addEventListener('click', () => openEditModal(id));
    setScreen('modal');
  } catch (error) {
    setMessage(statusMessage, error.message, 'error');
  }
}

async function openEditModal(id) {
  try {
    const payload = await apiRequest(`/api/users/${id}`);
    const user = payload.data;
    modalHeader.innerHTML = '<h3>Edit User</h3>';
    modalBody.innerHTML = `
      <form id="edit-form">
        <div class="form-grid">
          <label>
            Name
            <input type="text" name="name" value="${escapeHtml(user.name)}" required />
          </label>
          <label>
            Email
            <input type="email" name="email" value="${escapeHtml(user.email)}" required />
          </label>
          <label>
            Phone
            <input type="text" name="phone" value="${escapeHtml(user.phone || '')}" placeholder="Optional" />
          </label>
        </div>
        <p id="edit-form-error" class="message error" aria-live="polite"></p>
        <div class="form-actions">
          <button type="button" class="secondary-btn" id="cancel-edit-btn">Cancel</button>
          <button type="submit" class="primary-btn" id="save-edit-btn" disabled>Save Changes</button>
        </div>
      </form>
    `;

    const form = document.getElementById('edit-form');
    const saveButton = document.getElementById('save-edit-btn');
    const editError = document.getElementById('edit-form-error');
    const original = {
      name: user.name,
      email: user.email,
      phone: user.phone || ''
    };
    const changedFields = () => ['name', 'email', 'phone'].filter(
      (field) => form.elements[field].value.trim() !== original[field]
    );
    const updateSaveButton = () => {
      saveButton.disabled = changedFields().length === 0;
      editError.textContent = '';
    };
    form.addEventListener('input', updateSaveButton);
    document.getElementById('cancel-edit-btn').addEventListener('click', closeModal);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const changed = changedFields();
      const patchPayload = {};
      changed.forEach((field) => {
        patchPayload[field] = form.elements[field].value.trim();
      });
      if (changed.includes('phone') && !patchPayload.phone) {
        editError.textContent = 'Removing a saved phone number is not supported.';
        return;
      }

      try {
        saveButton.disabled = true;
        await apiRequest(`/api/users/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(patchPayload)
        });
        closeModal();
        state.page = 1;
        setMessage(statusMessage, 'User updated successfully.', 'success');
        await loadUsers();
      } catch (error) {
        editError.textContent = error.message;
      } finally {
        updateSaveButton();
      }
    });

    setScreen('modal');
  } catch (error) {
    setMessage(statusMessage, error.message, 'error');
  }
}

function closeModal() {
  setScreen('main');
  modalHeader.innerHTML = '';
  modalBody.innerHTML = '';
}

authForm.addEventListener('submit', authenticate);
mfaLoginForm.addEventListener('submit', submitMfaLogin);
resetRequestForm.addEventListener('submit', requestPasswordReset);
resetConfirmForm.addEventListener('submit', confirmPasswordReset);
document.getElementById('mfa-verify-form').addEventListener('submit', verifyMfaSetup);
document.getElementById('mfa-disable-form').addEventListener('submit', disableMfa);
document.getElementById('mfa-setup-btn').addEventListener('click', setupMfa);
document.getElementById('security-btn').addEventListener('click', showSecuritySettings);
document.getElementById('close-security-btn').addEventListener('click', showUserDirectory);
document.getElementById('show-reset-btn').addEventListener('click', () => {
  showAuthForm('reset-request');
  document.getElementById('reset-email').focus();
});
document.getElementById('cancel-reset-request-btn').addEventListener('click', () => showAuthForm('login'));
document.getElementById('cancel-reset-confirm-btn').addEventListener('click', () => {
  state.resetToken = null;
  window.history.replaceState({}, document.title, window.location.pathname);
  showAuthForm('login');
});
document.getElementById('back-to-login-btn').addEventListener('click', () => {
  state.pendingLogin = null;
  document.getElementById('login-totp-code').value = '';
  showAuthForm('login');
});
document.getElementById('refresh-btn').addEventListener('click', loadUsers);
document.getElementById('add-user-btn').addEventListener('click', openCreateModal);
document.getElementById('audit-btn').addEventListener('click', showAuditHistory);
document.getElementById('close-audit-btn').addEventListener('click', showUserDirectory);
document.getElementById('previous-page-btn').addEventListener('click', () => {
  if (state.page > 1) {
    state.page -= 1;
    loadUsers();
  }
});
document.getElementById('next-page-btn').addEventListener('click', () => {
  if (state.page < state.totalPages) {
    state.page += 1;
    loadUsers();
  }
});
document.getElementById('audit-previous-btn').addEventListener('click', () => {
  if (state.auditPage > 1) {
    state.auditPage -= 1;
    loadAuditHistory();
  }
});
document.getElementById('audit-next-btn').addEventListener('click', () => {
  if (state.auditPage < state.auditTotalPages) {
    state.auditPage += 1;
    loadAuditHistory();
  }
});
let searchDebounce;
searchInput.addEventListener('input', () => {
  window.clearTimeout(searchDebounce);
  searchDebounce = window.setTimeout(() => {
    state.page = 1;
    loadUsers();
  }, 250);
});
[phoneFilter, sortField, sortOrder].forEach((control) => {
  control.addEventListener('change', () => {
    state.page = 1;
    loadUsers();
  });
});
document.getElementById('signout-btn').addEventListener('click', async () => {
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
    clearClientSession();
    setMessage(authMessage, 'Signed out. Your user records remain saved. Sign in again to continue.', 'success');
  } catch (error) {
    setMessage(statusMessage, error.message || 'Unable to sign out. Please try again.', 'error');
  }
  usernameInput.value = '';
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !screenMap.modal.classList.contains('hidden')) {
    closeModal();
  }
});

async function initializeApp() {
  state.resetToken = new URLSearchParams(window.location.search).get('resetToken');
  if (state.resetToken) {
    showAuthForm('reset-confirm');
    setMessage(authMessage, 'Choose a new password. This reset link can only be used once.', '');
    return;
  }

  showAuthForm('login');
  setMessage(authMessage, 'Use the configured admin credentials to continue.', '');
  try {
    const session = await apiRequest('/api/auth/session');
    state.authenticated = true;
    state.username = session.username;
    state.mfaEnabled = session.mfaEnabled;
    setScreen('main');
    document.getElementById('directory-heading').focus();
    await loadUsers();
  } catch (error) {
    setScreen('auth');
    if (error.status !== 401) {
      setMessage(authMessage, error.message || 'Unable to check the current session.', 'error');
    }
  }
}

initializeApp();
