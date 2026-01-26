/**
 * Shared CSS styles for account.xaostech.io
 * Includes light/dark theme support controlled by bubble.js
 */
export const styles = `
/* =============================================================================
   DARK THEME (Default)
   ============================================================================= */
:root {
  --primary: #f6821f;
  --primary-dark: #e65100;
  --primary-light: #ff9d4d;
  --secondary: #00d4ff;
  --secondary-dark: #0099cc;
  --bg: #0a0a0a;
  --bg-surface: #121218;
  --bg-card: #1a1a2e;
  --bg-elevated: #252538;
  --bg-input: #2a2a3a;
  --border: #333344;
  --border-subtle: #222233;
  --text: #e0e0e0;
  --text-primary: #ffffff;
  --text-muted: #888;
  --success: #22c55e;
  --danger: #ef4444;
  --warning: #f59e0b;
  --info: #3b82f6;
  --shadow-glow: 0 0 20px rgba(0, 212, 255, 0.15);
  --transition-normal: 0.25s ease;
}

/* =============================================================================
   LIGHT THEME
   ============================================================================= */
[data-theme="light"],
body.light-theme {
  --primary: #e65100;
  --primary-dark: #bf4500;
  --primary-light: #f6821f;
  --secondary: #0099cc;
  --secondary-dark: #007399;
  --bg: #f5f5f7;
  --bg-surface: #ffffff;
  --bg-card: #ffffff;
  --bg-elevated: #ffffff;
  --bg-input: #f0f0f2;
  --border: #dddddd;
  --border-subtle: #eeeeee;
  --text: #333333;
  --text-primary: #1a1a1a;
  --text-muted: #666666;
  --shadow-glow: 0 0 20px rgba(0, 153, 204, 0.1);
}

/* Light theme specific overrides */
body.light-theme .card,
[data-theme="light"] .card {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
}

body.light-theme header,
[data-theme="light"] header {
  background: var(--bg-surface);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}

body.light-theme .badge-owner,
[data-theme="light"] .badge-owner {
  background: linear-gradient(135deg, #e65100, #bf4500);
}

body.light-theme .nav-link:hover,
[data-theme="light"] .nav-link:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

body.light-theme .welcome-banner,
[data-theme="light"] .welcome-banner {
  background: linear-gradient(135deg, rgba(230, 81, 0, 0.1), rgba(191, 69, 0, 0.05));
}

/* =============================================================================
   BASE STYLES
   ============================================================================= */
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.6;
  transition: background-color var(--transition-normal), color var(--transition-normal);
}

a {
  color: var(--primary);
  text-decoration: none;
  transition: color 0.2s;
}

a:hover {
  color: var(--primary-dark);
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 2rem;
  margin-bottom: 1.5rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--text);
}

input, textarea, select {
  width: 100%;
  padding: 0.75rem 1rem;
  background: var(--bg-input);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-size: 1rem;
  transition: border-color 0.2s, box-shadow 0.2s;
}

input:focus, textarea:focus, select:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.1);
}

button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  font-size: 1rem;
  font-weight: 600;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: var(--primary);
  color: #fff;
}

.btn-primary:hover {
  background: var(--primary-dark);
  transform: translateY(-1px);
}

.btn-secondary {
  background: var(--bg-input);
  color: var(--text);
  border: 1px solid var(--border);
}

.btn-secondary:hover {
  background: var(--border);
}

.btn-danger {
  background: var(--danger);
  color: #fff;
}

.btn-danger:hover {
  background: #dc2626;
}

.btn-success {
  background: var(--success);
  color: #fff;
}

.btn-success:hover {
  background: #16a34a;
}

/* User card styles */
.user-card {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 1.5rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 2rem;
}

.user-card .avatar {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  object-fit: cover;
  border: 3px solid var(--primary);
}

.user-card .user-info h2 {
  margin: 0 0 0.5rem 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.user-card .user-info p {
  color: var(--text-muted);
  margin: 0;
}

/* Role badges */
.badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: bold;
  text-transform: uppercase;
}

.badge-owner {
  background: linear-gradient(135deg, #f6821f, #e65100);
  color: #fff;
}

.badge-admin {
  background: #7c3aed;
  color: #fff;
}

.badge-user {
  background: var(--border);
  color: var(--text-muted);
}

/* Navigation grid */
.nav-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
  margin-top: 2rem;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1.25rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  transition: all 0.2s;
}

.nav-link:hover {
  border-color: var(--primary);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.nav-link .icon {
  font-size: 2rem;
}

.nav-link .nav-text h3 {
  margin: 0;
  color: var(--text);
}

.nav-link .nav-text p {
  margin: 0.25rem 0 0;
  color: var(--text-muted);
  font-size: 0.875rem;
}

/* Welcome banner */
.welcome-banner {
  background: linear-gradient(135deg, rgba(246, 130, 31, 0.2), rgba(230, 81, 0, 0.1));
  border: 1px solid var(--primary);
  border-radius: 12px;
  padding: 1rem 1.5rem;
  margin-bottom: 2rem;
}

/* Messages */
.message {
  padding: 1rem 1.5rem;
  border-radius: 8px;
  margin-bottom: 1rem;
}

.message-error {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--danger);
  color: var(--danger);
}

.message-success {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid var(--success);
  color: var(--success);
}

.message-info {
  background: rgba(59, 130, 246, 0.1);
  border: 1px solid var(--info);
  color: var(--info);
}

/* Header */
header {
  padding: 1rem 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border);
}

header .logo {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  color: var(--text);
  font-size: 1.25rem;
  font-weight: bold;
}

header .logo img {
  height: 32px;
}

header nav {
  display: flex;
  gap: 1.5rem;
}

/* Tables */
table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 1rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

th {
  background: var(--bg-input);
  font-weight: 600;
}

tr:hover td {
  background: rgba(255, 255, 255, 0.02);
}

/* Responsive */
@media (max-width: 768px) {
  .container {
    padding: 1rem;
  }

  .user-card {
    flex-direction: column;
    text-align: center;
  }

  .nav-grid {
    grid-template-columns: 1fr;
  }

  header {
    flex-direction: column;
    gap: 1rem;
  }
}
`;
