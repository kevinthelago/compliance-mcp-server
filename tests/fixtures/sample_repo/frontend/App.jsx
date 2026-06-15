// PLANTED VIOLATION: hardcoded user-facing strings (i18n domain)
// These strings should be externalized via i18next or react-intl.
export function App() {
  return (
    <div>
      <h1>Welcome to our application</h1>
      <button>Click here to continue</button>
      <p>Please enter your email address</p>
      <label>Your name</label>
    </div>
  );
}
