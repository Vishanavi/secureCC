import { useMemo, useState } from "react";
import ThemeSwitcher from "./ThemeSwitcher";
import {
  getPasswordChecks,
  isPasswordValid,
  validatePassword,
  validateUsername,
} from "../utils/authValidation";

const SESSION_KEY = "securecc_session";

function apiBaseUrl() {
  const fromEnv = process.env.REACT_APP_API_URL;
  if (fromEnv) return fromEnv.replace(/\/$/, "");
  if (typeof window === "undefined") {
    return "http://localhost:8000";
  }
  const { hostname, port } = window.location;
  const local =
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1";
  if (local && port === "8000") {
    return "";
  }
  if (local) {
    return "http://localhost:8000";
  }
  return `http://${hostname}:8000`;
}

function parseApiError(payload, fallback) {
  if (!payload?.detail) return fallback;
  if (typeof payload.detail === "string") return payload.detail;
  if (Array.isArray(payload.detail)) {
    return payload.detail.map((d) => d.msg || String(d)).join(" ");
  }
  return fallback;
}

export default function AuthPage({ onAuthSuccess, theme, onThemeChange }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showPasswordHints, setShowPasswordHints] = useState(false);

  const isSignup = mode === "signup";
  const passwordChecks = useMemo(() => getPasswordChecks(password), [password]);
  const usernameError = username.trim() ? validateUsername(username) : null;

  const resetFeedback = () => {
    setMessage("");
    setError("");
  };

  const handleSignup = async () => {
    resetFeedback();
    const userErr = validateUsername(username);
    if (userErr) {
      setError(userErr);
      return;
    }
    const passErr = validatePassword(password);
    if (passErr) {
      setError(passErr);
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      const base = apiBaseUrl();
      const url = base ? `${base}/auth/signup` : "/auth/signup";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(parseApiError(payload, "Signup failed."));
      }
      setMessage("Account created. Please log in with your new credentials.");
      setMode("login");
      setPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(err?.message || "Signup failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogin = async () => {
    resetFeedback();
    const userErr = validateUsername(username);
    if (userErr) {
      setError(userErr);
      return;
    }
    if (!password) {
      setError("Password is required.");
      return;
    }

    setSubmitting(true);
    try {
      const base = apiBaseUrl();
      const url = base ? `${base}/auth/login` : "/auth/login";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(parseApiError(payload, "Invalid username or password."));
      }
      const data = await res.json();
      window.localStorage.setItem(SESSION_KEY, data.username || username.trim());
      onAuthSuccess(data.username || username.trim());
    } catch (err) {
      setError(err?.message || "Login failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmitSignup =
    !usernameError && isPasswordValid(password) && password === confirmPassword && !submitting;
  const canSubmitLogin = !usernameError && password.length > 0 && !submitting;

  return (
    <div className="auth-screen">
      <div className="auth-card neon-panel">
        <div className="auth-card-header">
          <div className="auth-card-heading">
            <h1>SecureCC</h1>
            <p className="auth-subtitle">
              {isSignup
                ? "Create a secure account to save your code in the cloud"
                : "Sign in to your secure coding workspace"}
            </p>
          </div>
          <ThemeSwitcher currentTheme={theme} onThemeChange={onThemeChange} compact />
        </div>

        <div className="auth-tabs">
          <button
            type="button"
            className={mode === "login" ? "auth-tab auth-tab-active" : "auth-tab"}
            onClick={() => {
              setMode("login");
              resetFeedback();
              setShowPasswordHints(false);
            }}
          >
            Login
          </button>
          <button
            type="button"
            className={mode === "signup" ? "auth-tab auth-tab-active" : "auth-tab"}
            onClick={() => {
              setMode("signup");
              resetFeedback();
            }}
          >
            Sign Up
          </button>
        </div>

        <div className="auth-form">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="e.g. anuj_dev"
            className={usernameError && username.trim() ? "auth-input-invalid" : ""}
          />
          {isSignup ? (
            <p className="auth-hint">
              Must start with a letter; 3–30 chars (letters, numbers, underscore).
            </p>
          ) : null}
          {usernameError && username.trim() ? (
            <p className="auth-field-error">{usernameError}</p>
          ) : null}

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete={isSignup ? "new-password" : "current-password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onFocus={() => isSignup && setShowPasswordHints(true)}
            placeholder={isSignup ? "Create a strong password" : "Enter password"}
            className={
              isSignup && password && !isPasswordValid(password) ? "auth-input-invalid" : ""
            }
          />

          {isSignup && (showPasswordHints || password) ? (
            <ul className="auth-password-rules" aria-label="Password requirements">
              {passwordChecks.map((rule) => (
                <li key={rule.id} className={rule.ok ? "rule-ok" : "rule-pending"}>
                  <span className="rule-icon" aria-hidden="true">
                    {rule.ok ? "✓" : "○"}
                  </span>
                  {rule.label}
                </li>
              ))}
            </ul>
          ) : null}

          {isSignup ? (
            <>
              <label htmlFor="confirm-password">Confirm Password</label>
              <input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter password"
                className={
                  confirmPassword && confirmPassword !== password ? "auth-input-invalid" : ""
                }
              />
              {confirmPassword && confirmPassword !== password ? (
                <p className="auth-field-error">Passwords do not match.</p>
              ) : null}
            </>
          ) : null}

          {error ? <div className="auth-error">{error}</div> : null}
          {message ? <div className="auth-message">{message}</div> : null}

          <button
            type="button"
            className="auth-submit"
            disabled={isSignup ? !canSubmitSignup : !canSubmitLogin}
            onClick={isSignup ? handleSignup : handleLogin}
          >
            {submitting
              ? "Please wait…"
              : isSignup
                ? "Create Account"
                : "Login"}
          </button>
        </div>
      </div>
    </div>
  );
}
