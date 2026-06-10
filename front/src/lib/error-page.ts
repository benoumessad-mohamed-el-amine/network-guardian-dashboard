/**
 * Renders a premium, beautifully designed, responsive branded error page (HTML string)
 * for the Network Guardian Dashboard when a server-side rendering error occurs.
 */
export function renderErrorPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>System Alert | Network Guardian</title>
  <!-- Modern premium typography -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #060913;
      --bg-secondary: #0d1222;
      --accent-red: #ff4a5a;
      --accent-red-glow: rgba(255, 74, 90, 0.15);
      --accent-blue: #3b82f6;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --border-color: rgba(255, 255, 255, 0.08);
      --font-outfit: 'Outfit', sans-serif;
      --font-mono: 'Space Grotesk', monospace;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: var(--font-outfit);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
    }

    /* Ambient background glow effects */
    .ambient-glow-1 {
      position: absolute;
      top: -10%;
      left: -10%;
      width: 50vw;
      height: 50vw;
      background: radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%);
      z-index: 1;
      pointer-events: none;
    }

    .ambient-glow-2 {
      position: absolute;
      bottom: -10%;
      right: -10%;
      width: 50vw;
      height: 50vw;
      background: radial-gradient(circle, rgba(255, 74, 90, 0.05) 0%, transparent 70%);
      z-index: 1;
      pointer-events: none;
    }

    .container {
      position: relative;
      z-index: 2;
      max-width: 580px;
      width: 90%;
      padding: 40px 32px;
      background: rgba(13, 18, 34, 0.45);
      border: 1px solid var(--border-color);
      border-radius: 24px;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05);
      text-align: center;
      animation: fadeInUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* Shield / Danger icon styling with pulsing neon glow */
    .icon-container {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 88px;
      height: 88px;
      border-radius: 50%;
      background: rgba(255, 74, 90, 0.06);
      border: 1px solid rgba(255, 74, 90, 0.25);
      margin-bottom: 28px;
      position: relative;
      animation: pulseGlow 3s infinite ease-in-out;
    }

    .icon-container svg {
      width: 44px;
      height: 44px;
      color: var(--accent-red);
      filter: drop-shadow(0 0 8px rgba(255, 74, 90, 0.5));
    }

    h1 {
      font-size: 2rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      margin-bottom: 12px;
      background: linear-gradient(135deg, #ffffff 40%, #d1d5db 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .subtitle {
      font-size: 1rem;
      color: var(--text-muted);
      line-height: 1.6;
      margin-bottom: 32px;
      font-weight: 400;
    }

    /* Diagnostics Block (Console theme) */
    .diagnostic-panel {
      text-align: left;
      background: rgba(5, 7, 15, 0.8);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 32px;
      font-family: var(--font-mono);
      font-size: 0.875rem;
      color: rgba(255, 255, 255, 0.85);
      overflow-x: auto;
      max-height: 160px;
      box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.8);
    }

    .diagnostic-header {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 10px;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent-red);
      font-weight: 600;
    }

    .diagnostic-header::before {
      content: '';
      display: inline-block;
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background-color: var(--accent-red);
      box-shadow: 0 0 6px var(--accent-red);
    }

    .diagnostic-body {
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-all;
    }

    /* Premium interactive CTA buttons */
    .actions {
      display: flex;
      flex-direction: column;
      gap: 12px;
      align-items: center;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      max-width: 280px;
      padding: 14px 28px;
      font-family: var(--font-outfit);
      font-size: 0.95rem;
      font-weight: 600;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.35s cubic-bezier(0.16, 1, 0.3, 1);
      text-decoration: none;
      outline: none;
    }

    .btn-primary {
      background: linear-gradient(135deg, #ff4a5a 0%, #dd2a3c 100%);
      color: white;
      border: none;
      box-shadow: 0 4px 15px rgba(255, 74, 90, 0.3);
    }

    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 22px rgba(255, 74, 90, 0.45);
      background: linear-gradient(135deg, #ff5c6b 0%, #e8384a 100%);
    }

    .btn-primary:active {
      transform: translateY(0);
    }

    .btn-secondary {
      background: transparent;
      color: var(--text-main);
      border: 1px solid var(--border-color);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.04);
      border-color: rgba(255, 255, 255, 0.15);
    }

    /* Keyframe Animations */
    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(24px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes pulseGlow {
      0%, 100% {
        box-shadow: 0 0 15px rgba(255, 74, 90, 0.08), inset 0 0 8px rgba(255, 74, 90, 0.03);
        border-color: rgba(255, 74, 90, 0.2);
      }
      50% {
        box-shadow: 0 0 28px rgba(255, 74, 90, 0.25), inset 0 0 12px rgba(255, 74, 90, 0.08);
        border-color: rgba(255, 74, 90, 0.4);
      }
    }

    /* Responsive adjustments */
    @media (max-width: 480px) {
      .container {
        padding: 32px 20px;
      }
      h1 {
        font-size: 1.75rem;
      }
    }
  </style>
</head>
<body>
  <div class="ambient-glow-1"></div>
  <div class="ambient-glow-2"></div>

  <div class="container">
    <div class="icon-container">
      <!-- Shield Alert SVG Icon -->
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    </div>

    <h1>Guardian Interrupted</h1>
    <p class="subtitle">The Network Guardian security dashboard has encountered an internal server error while processing your request. The security engine remains active in the background.</p>

    <div class="diagnostic-panel">
      <div class="diagnostic-header">Shield Diagnostics</div>
      <div class="diagnostic-body">STATUS: 500 INTERNAL_SERVER_ERROR
MODULE: SSR_ROUTING_HANDLER
MESSAGE: Safe render boundary intercepted a catastrophic execution error.</div>
    </div>

    <div class="actions">
      <button class="btn btn-primary" onclick="window.location.reload()">Reload System Dashboard</button>
      <a href="/" class="btn btn-secondary">Return to Guard Base</a>
    </div>
  </div>
</body>
</html>`;
}
