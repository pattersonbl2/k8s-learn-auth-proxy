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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0e14;
      --surface: #111820;
      --border: #1e2a3a;
      --accent: #22d3ee;
      --red: #f87171;
      --text: #c9d1d9;
      --muted: #6b7b8d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'IBM Plex Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
      pointer-events: none;
      z-index: 9999;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 2px;
      padding: 2.5rem;
      width: 100%;
      max-width: 380px;
    }
    .logo {
      font-size: 2rem;
      margin-bottom: 1rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent);
    }
    h1 {
      font-size: 1.4rem;
      font-weight: 700;
      margin-bottom: 0.4rem;
      font-family: 'JetBrains Mono', monospace;
    }
    h1::after {
      content: '_';
      animation: blink 1s step-end infinite;
      color: var(--accent);
    }
    @keyframes blink { 50% { opacity: 0; } }
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
      border-radius: 3px;
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
      border-radius: 3px;
      color: #fff;
      cursor: pointer;
      font-size: 0.95rem;
      font-weight: 600;
      padding: 0.75rem;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    .error {
      background: rgba(248, 113, 113, 0.1);
      border: 1px solid rgba(248, 113, 113, 0.3);
      color: var(--red);
      border-radius: 3px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
      margin-bottom: 1rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">&gt;_</div>
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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0e14;
      --surface: #111820;
      --border: #1e2a3a;
      --accent: #22d3ee;
      --red: #f87171;
      --text: #c9d1d9;
      --muted: #6b7b8d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'IBM Plex Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    body::after {
      content: '';
      position: fixed;
      inset: 0;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
      pointer-events: none;
      z-index: 9999;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 2px;
      padding: 2.5rem;
      text-align: center;
      max-width: 380px;
      width: 100%;
    }
    h1 {
      font-size: 1.4rem;
      margin-bottom: 0.5rem;
      font-family: 'JetBrains Mono', monospace;
    }
    h1::after {
      content: '_';
      animation: blink 1s step-end infinite;
      color: var(--accent);
    }
    @keyframes blink { 50% { opacity: 0; } }
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
