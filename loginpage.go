package main

import "strings"

func renderLoginPage(errMsg string) string {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div class="error">` + errMsg + `</div>`
	}
	return strings.Replace(loginTemplate, "{{ERROR}}", errorHTML, 1)
}

func renderLogoutPage() string {
	return logoutTemplate
}

const loginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Terminal Login</title>
  <style>
    :root {
      --bg: #0f1117;
      --surface: #1a1d27;
      --border: #2a2d3a;
      --accent: #6366f1;
      --red: #ef4444;
      --text: #e2e8f0;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2.5rem;
      width: 100%;
      max-width: 380px;
    }
    .logo { font-size: 2rem; margin-bottom: 1rem; }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.4rem; }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    label {
      display: block;
      font-size: 0.85rem;
      font-weight: 500;
      color: var(--muted);
      margin-bottom: 0.4rem;
    }
    input {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 0.95rem;
      padding: 0.65rem 0.9rem;
      margin-bottom: 1.2rem;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: var(--accent); }
    button {
      width: 100%;
      background: var(--accent);
      border: none;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font-size: 0.95rem;
      font-weight: 600;
      padding: 0.75rem;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    .error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: var(--red);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">⎈</div>
    <h1>Terminal Login</h1>
    <p class="subtitle">Enter your password to access the terminal.</p>
    {{ERROR}}
    <form method="POST" action="/auth/login">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autofocus required>
      <button type="submit">Log in</button>
    </form>
  </div>
</body>
</html>`

const logoutTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Logged out</title>
  <style>
    :root { --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a; --accent: #6366f1; --text: #e2e8f0; --muted: #94a3b8; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 2.5rem; text-align: center; max-width: 380px; }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    p { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    a { color: var(--accent); text-decoration: none; font-weight: 600; }
    a:hover { opacity: 0.85; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Logged out</h1>
    <p>You have been logged out of the terminal.</p>
    <a href="/auth/login">Log in again</a>
  </div>
</body>
</html>`
