import "./App.css";
import { useState } from "react";
import AuthPage from "./components/AuthPage";
import CodeEditor from "./components/CodeEditor";
import GetStartedPage from "./components/GetStartedPage";

const VALID_THEMES = ["slate", "snow"];

function normalizeTheme(stored) {
  if (stored === "midnight" || !VALID_THEMES.includes(stored)) {
    return "slate";
  }
  return stored;
}

function App() {
  const [user, setUser] = useState(() => {
    try {
      return window.localStorage.getItem("securecc_session") || "";
    } catch {
      return "";
    }
  });
  const [showAuth, setShowAuth] = useState(Boolean(user));
  const [theme, setTheme] = useState(() => {
    try {
      return normalizeTheme(window.localStorage.getItem("securecc_theme") || "slate");
    } catch {
      return "slate";
    }
  });

  const handleThemeChange = (newTheme) => {
    const next = normalizeTheme(newTheme);
    setTheme(next);
    try {
      window.localStorage.setItem("securecc_theme", next);
    } catch {
    }
  };

  return (
    <div className={`App theme-${theme}`}>
      {user ? (
        <CodeEditor
          user={user}
          onLogout={() => {
            setUser("");
            setShowAuth(false);
          }}
          currentTheme={theme}
          onThemeChange={handleThemeChange}
        />
      ) : showAuth ? (
        <AuthPage onAuthSuccess={setUser} theme={theme} onThemeChange={handleThemeChange} />
      ) : (
        <GetStartedPage onContinue={() => setShowAuth(true)} theme={theme} onThemeChange={handleThemeChange} />
      )}
    </div>
  );
}

export default App;
