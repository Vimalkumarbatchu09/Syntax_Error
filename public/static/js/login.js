/**
 * NetGuard AI - Authentication JavaScript
 * Handles login, registration, and password reset form interactions.
 */

document.addEventListener('DOMContentLoaded', () => {
  initLoginForm();
  initRegisterForm();
});

function initLoginForm() {
  const form = document.getElementById('login-form');
  if (!form) return;

  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const errorBanner = document.getElementById('auth-error-banner');
  const successBanner = document.getElementById('auth-success-banner');
  const submitBtn = document.getElementById('btn-login-submit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanners(errorBanner, successBanner);

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      showBanner(errorBanner, 'Please enter both username and password.');
      return;
    }

    try {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Verifying credentials...</span>';

      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed.');
      }

      showBanner(successBanner, 'Authentication successful! Redirecting to NOC...');
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 700);

    } catch (err) {
      showBanner(errorBanner, err.message);
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <span>Authenticate to NOC</span>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
      `;
    }
  });
}

function initRegisterForm() {
  const form = document.getElementById('register-form');
  if (!form) return;

  const fullNameInput = document.getElementById('reg-fullname');
  const emailInput = document.getElementById('reg-email');
  const usernameInput = document.getElementById('reg-username');
  const passwordInput = document.getElementById('reg-password');
  const confirmPasswordInput = document.getElementById('reg-confirm-password');
  const errorBanner = document.getElementById('reg-error-banner');
  const successBanner = document.getElementById('reg-success-banner');
  const submitBtn = document.getElementById('btn-reg-submit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanners(errorBanner, successBanner);

    const full_name = fullNameInput.value.trim();
    const email = emailInput.value.trim();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const confirm_password = confirmPasswordInput.value;

    // Client-side validations
    if (!full_name || !email || !username || !password || !confirm_password) {
      showBanner(errorBanner, 'All fields are required.');
      return;
    }

    if (!email.includes('@') || !email.includes('.')) {
      showBanner(errorBanner, 'Please provide a valid email address.');
      return;
    }

    if (username.length < 3) {
      showBanner(errorBanner, 'Username must be at least 3 characters long.');
      return;
    }

    if (password.length < 6) {
      showBanner(errorBanner, 'Password must be at least 6 characters long.');
      return;
    }

    if (password !== confirm_password) {
      showBanner(errorBanner, 'Passwords do not match. Please re-enter.');
      return;
    }

    try {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Creating operator profile...</span>';

      const response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ full_name, email, username, password, confirm_password })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Registration failed.');
      }

      showBanner(successBanner, 'Account created! Redirecting to NOC Dashboard...');
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 800);

    } catch (err) {
      showBanner(errorBanner, err.message);
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <span>Complete Registration</span>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
      `;
    }
  });
}

function showBanner(banner, msg) {
  if (!banner) return;
  banner.textContent = msg;
  banner.style.display = 'block';
}

function hideBanners(...banners) {
  banners.forEach(b => {
    if (b) {
      b.style.display = 'none';
      b.textContent = '';
    }
  });
}
