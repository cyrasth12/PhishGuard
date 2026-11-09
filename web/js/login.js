// Login / register form: sends the details to /api/v1/auth/*, then opens the dashboard.
let mode = 'login';

const tabLogin = document.getElementById('tabLogin');
const tabRegister = document.getElementById('tabRegister');
const submitBtn = document.getElementById('authSubmit');
const errorBox = document.getElementById('authError');

function setMode(m) {
    mode = m;
    tabLogin.classList.toggle('active', m === 'login');
    tabRegister.classList.toggle('active', m === 'register');
    submitBtn.textContent = m === 'login' ? 'Login' : 'Create account';
    document.getElementById('password').autocomplete = m === 'login' ? 'current-password' : 'new-password';
    errorBox.textContent = '';
}
tabLogin.addEventListener('click', () => setMode('login'));
tabRegister.addEventListener('click', () => setMode('register'));

document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.textContent = '';
    submitBtn.disabled = true;
    try {
        const res = await fetch('/api/v1/auth/' + mode, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: document.getElementById('username').value.trim(),
                password: document.getElementById('password').value
            })
        });
        const data = await res.json();
        if (res.ok) {
            window.location.href = '/';
        } else {
            errorBox.textContent = data.error || 'Something went wrong.';
        }
    } catch (err) {
        errorBox.textContent = 'Cannot reach the server. Is PhishGuard running?';
    } finally {
        submitBtn.disabled = false;
    }
});
