import React from 'react';

// I18N-1: hardcoded JSX text — should be flagged
export function WelcomeBanner() {
  return (
    <div>
      <h1>Welcome to our application</h1>
      <p>Please sign in to continue</p>
    </div>
  );
}

// I18N-1: hardcoded placeholder / alt — should be flagged
export function LoginForm() {
  return (
    <form>
      <input placeholder="Enter your email address" type="email" />
      <input placeholder="Enter your password" type="password" />
      <img alt="Company logo" src="/logo.png" />
      <button type="submit" aria-label="Sign in to your account">Sign in</button>
    </form>
  );
}

// I18N-2: non-locale date formatting — should be flagged
export function UserProfile({ user }) {
  const joined = new Date(user.joinedAt).toDateString();
  const lastSeen = new Date(user.lastSeen).toTimeString();
  return (
    <div>
      <span>Joined: {joined}</span>
      <span>Last seen: {lastSeen}</span>
    </div>
  );
}

// Should NOT be flagged — console.log, data attributes, short strings
export function NotFlagged() {
  console.log("Debug: component mounted");
  return <div data-testid="not-flagged" className="container" />;
}

// Should NOT be flagged — already using t()
export function AlreadyI18n({ t }) {
  return <button>{t('button.submit')}</button>;
}
