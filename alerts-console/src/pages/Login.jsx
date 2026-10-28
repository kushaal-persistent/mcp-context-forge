import { useState } from 'react';
import { useSession } from '../session.jsx';
import { Button, ErrorBanner, Notice } from '../components/ui.jsx';

export default function Login() {
  const { login, notice } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await login(email.trim(), password);
    } catch (err) {
      // Same message for a wrong email and a wrong password: the gateway does not say which.
      setError(err.status === 401 ? 'Invalid email or password.' : err.message);
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-full items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-xl border border-ink-700 bg-ink-900 p-8 shadow-xl">
        <div>
          <h1 className="text-xl font-semibold text-white">ContextForge Alerts</h1>
          <p className="mt-1 text-sm text-slate-400">Sign in with your gateway account.</p>
        </div>

        <Notice>{!error && notice}</Notice>
        <ErrorBanner>{error}</ErrorBanner>

        <label className="block text-sm text-slate-300">
          Email
          <input
            type="email"
            autoComplete="username"
            required
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-md border border-ink-700 bg-ink-950 px-3 py-2 text-slate-100"
          />
        </label>
        <label className="block text-sm text-slate-300">
          Password
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-md border border-ink-700 bg-ink-950 px-3 py-2 text-slate-100"
          />
        </label>

        <Button type="submit" variant="primary" disabled={busy || !email || !password} className="w-full py-2">
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </main>
  );
}
