import Editor from "@monaco-editor/react";
import { useEffect, useMemo, useRef, useState } from "react";
import ThemeSwitcher from "./ThemeSwitcher";

const DEFAULT_MAIN_C = `#include <stdio.h>

int main() {
  return 0;
}
`;


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

export default function CodeEditor({ user, onLogout, currentTheme, onThemeChange }) {
  const [files, setFiles] = useState({
    "main.c": DEFAULT_MAIN_C,
  });
  const [currentFile, setCurrentFile] = useState("main.c");
  const [code, setCode] = useState(files["main.c"]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState([]);
  const [compileOutput, setCompileOutput] = useState("");
  const [outputHeight, setOutputHeight] = useState(240);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeTab, setActiveTab] = useState("output");
  const [editorReady, setEditorReady] = useState(false);
  const dragRef = useRef({
    dragging: false,
    startY: 0,
    startHeight: 240,
  });
  const rootRef = useRef(null);
  const editorRef = useRef(null);
  const monacoRef = useRef(null);
  const decorationRef = useRef([]);
  const userRef = useRef(user);

  const pretty = useMemo(
    () =>
      result.map((v) => ({
        type: v.type,
        severity: v.severity,
        pattern: v.pattern,
        fix: v.fix,
        line: v.line,
        confidence: v.confidence,
      })),
    [result]
  );
  const hasVulnerabilities = pretty.length > 0;
  const criticalCount = pretty.filter((v) =>
    ["critical", "high", "error"].includes(String(v.severity || "").toLowerCase())
  ).length;
  const warningCount = pretty.filter((v) =>
    ["medium", "warning", "warn"].includes(String(v.severity || "").toLowerCase())
  ).length;
  const threatLevel = criticalCount > 0 ? "HIGH" : warningCount > 0 ? "MEDIUM" : "LOW";
  const displayName =
    user && user.includes("@")
      ? user.split("@")[0].replace(/[._-]/g, " ")
      : user || "Prince Dobriyal";

  const newFile = () => {
    const name = window.prompt("Enter file name (e.g. newfile.c):");
    if (!name) return;

    setFiles((prev) => {
      if (prev[name]) {
        return prev;
      }
      return { ...prev, [name]: "" };
    });
    setCurrentFile(name);
    setCode("");
  };

  const saveFile = async () => {
    const filename = currentFile;
    const content = code;
    setFiles((prev) => ({ ...prev, [filename]: content }));
    try {
      const base = apiBaseUrl();
      const url = base ? `${base}/files` : "/files";
      const res = await fetch(url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: userRef.current,
          filename,
          content,
        }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(payload.detail || "Failed to save file.");
      }
      setCompileOutput("File saved.");
      setError("");
    } catch (err) {
      setError(err?.message || "Failed to save file.");
      setCompileOutput("");
    }
    setActiveTab("output");
  };

  const deleteFile = async () => {
    const filename = currentFile;
    const names = Object.keys(files);
    if (names.length <= 1) {
      setError("You must keep at least one file.");
      setActiveTab("output");
      return;
    }
    if (!window.confirm(`Delete "${filename}"? This cannot be undone.`)) {
      return;
    }

    setLoading(true);
    setError("");
    try {
      const base = apiBaseUrl();
      const url = base ? `${base}/files` : "/files";
      const res = await fetch(url, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: userRef.current,
          filename,
        }),
      });
      if (!res.ok) {
        const payload = await res.json().catch(() => ({}));
        if (res.status !== 404) {
          throw new Error(payload.detail || "Failed to delete file.");
        }
      }

      const remaining = names.filter((name) => name !== filename);
      const nextFile = remaining[0];
      setFiles((prev) => {
        const next = { ...prev };
        delete next[filename];
        return next;
      });
      setCurrentFile(nextFile);
      setCompileOutput(`Deleted "${filename}".`);
      setActiveTab("output");
    } catch (err) {
      setError(err?.message || "Failed to delete file.");
      setActiveTab("output");
    } finally {
      setLoading(false);
    }
  };

  const compileCode = async () => {
    setLoading(true);
    setError("");
    setCompileOutput("");
    try {
      const base = apiBaseUrl();
      const url = base ? `${base}/compile` : "/compile";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`API error ${res.status}: ${text}`);
      }

      const data = await res.json();

      if (data.status === "blocked") {
        setResult(Array.isArray(data.findings) ? data.findings : []);
        setCompileOutput("Compilation blocked due to security findings.");
        setActiveTab("security");
      } else {
        setResult(
          Array.isArray(data.findings)
            ? data.findings
            : Array.isArray(data.security)
              ? data.security
              : []
        );
        setCompileOutput(data.output || "");
        setActiveTab("output");
      }
    } catch (e) {
      setResult([]);
      const raw = e?.message || "Request failed";
      const hint =
        raw === "Failed to fetch"
          ? " Start FastAPI: run the .\\run_backend.bat script in your project root (needs GCC on PATH)."
          : "";
      setError(`${raw}.${hint}`);
      setActiveTab("output");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    userRef.current = user;
  }, [user]);

  useEffect(() => {
    let ignore = false;
    const loadFiles = async () => {
      if (!user) return;
      try {
        const base = apiBaseUrl();
        const query = encodeURIComponent(user);
        const url = base ? `${base}/files?username=${query}` : `/files?username=${query}`;
        const res = await fetch(url);
        if (!res.ok) {
          const payload = await res.json().catch(() => ({}));
          throw new Error(payload.detail || "Failed to load files.");
        }
        const data = await res.json();
        if (ignore) return;

        const fromServer = Array.isArray(data.files) ? data.files : [];
        if (fromServer.length === 0) {
          const fallback = { "main.c": DEFAULT_MAIN_C };
          setFiles(fallback);
          setCurrentFile("main.c");
          setCode(DEFAULT_MAIN_C);
          return;
        }

        const nextFiles = {};
        for (const item of fromServer) {
          if (item && item.filename) {
            nextFiles[item.filename] = item.content ?? "";
          }
        }
        const names = Object.keys(nextFiles);
        if (names.length === 0) {
          nextFiles["main.c"] = DEFAULT_MAIN_C;
        }
        const first = Object.keys(nextFiles)[0];
        setFiles(nextFiles);
        setCurrentFile(first);
        setCode(nextFiles[first] ?? "");
        setError("");
      } catch (err) {
        if (!ignore) {
          setError(err?.message || "Failed to load files.");
        }
      }
    };

    loadFiles();
    return () => {
      ignore = true;
    };
  }, [user]);

  useEffect(() => {
    if (!editorReady || !editorRef.current || !monacoRef.current) return;
    const monaco = monacoRef.current;
    const next = pretty
      .filter((v) => Number.isFinite(v.line) && v.line > 0)
      .map((v) => {
        const isCritical = ["critical", "high", "error"].includes(
          String(v.severity || "").toLowerCase()
        );
        return {
          range: new monaco.Range(v.line, 1, v.line, 1),
          options: {
            isWholeLine: true,
            linesDecorationsClassName: isCritical ? "risk-line-critical" : "risk-line-warning",
          },
        };
      });

    decorationRef.current = editorRef.current.deltaDecorations(decorationRef.current, next);
  }, [pretty, editorReady]);

  useEffect(() => {
    setCode(files[currentFile] ?? "");
  }, [currentFile, files]);

  useEffect(() => {
    const onFsChange = () => {
      setIsFullscreen(Boolean(document.fullscreenElement));
    };
    document.addEventListener("fullscreenchange", onFsChange);

    const onMove = (e) => {
      if (!dragRef.current.dragging) return;
      const dy = dragRef.current.startY - e.clientY;
      const max = Math.max(180, Math.floor(window.innerHeight * 0.55));
      const next = Math.max(120, Math.min(max, dragRef.current.startHeight + dy));
      setOutputHeight(next);
    };

    const onUp = () => {
      dragRef.current.dragging = false;
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      document.removeEventListener("fullscreenchange", onFsChange);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  const sessionClass = hasVulnerabilities ? "status-dot dot-red" : "status-dot dot-green";

  return (
    <div ref={rootRef} className="compiler-container ide-container">
      <div className="ide-topbar neon-panel">
        <div className="ide-topbar-row">
          <div className="brand">
            <div className="brand-title">SECURECC</div>
            <div className="brand-subtitle">
              <span className={sessionClass} />
              Secure Environment {hasVulnerabilities ? "At Risk" : "Active"}
            </div>
          </div>
          <ThemeSwitcher currentTheme={currentTheme} onThemeChange={onThemeChange} compact />
        </div>
        <div className="top-meta">
          <div className="pill">
            User: <strong>{displayName}</strong>
          </div>
          <div className="pill">Role: <strong>Developer</strong></div>
          <div className="pill">File: <strong>{currentFile}</strong></div>
          <div className="pill">Language: <strong>C</strong></div>
          <div className="pill">
            Session: <strong>{hasVulnerabilities ? "Protected With Alerts" : "Protected"}</strong>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={() => {
              try {
                window.localStorage.removeItem("securecc_session");
              } catch {
              }
              onLogout?.();
            }}
            title="Logout"
          >
            Logout
          </button>
          <button
            type="button"
            className="icon-button"
            onClick={async () => {
              try {
                if (!document.fullscreenElement) {
                  await (rootRef.current?.requestFullscreen?.() ??
                    document.documentElement.requestFullscreen());
                } else {
                  await document.exitFullscreen();
                }
              } catch {

              }
            }}
            title={isFullscreen ? "Exit fullscreen (Esc)" : "Enter fullscreen"}
          >
            {isFullscreen ? "Exit Fullscreen" : "Fullscreen"}
          </button>
        </div>
      </div>

      <div className="ide-main">
        <div className="sidebar neon-panel">
          <h3>Files</h3>
          {Object.keys(files).map((file) => (
            <div
              key={file}
              className={
                file === currentFile ? "file file-active" : "file"
              }
              onClick={() => {
                setCurrentFile(file);
                setCode(files[file] ?? "");
              }}
            >
              {file}
            </div>
          ))}

          <div className="sidebar-actions">
            <button type="button" onClick={newFile} className="sidebar-button" disabled={loading}>
              + New File
            </button>
            <button
              type="button"
              onClick={deleteFile}
              className="sidebar-button sidebar-button-danger"
              disabled={loading || Object.keys(files).length <= 1}
              title={
                Object.keys(files).length <= 1
                  ? "At least one file is required"
                  : `Delete ${currentFile}`
              }
            >
              Delete File
            </button>
          </div>
        </div>

        <div className="editor-area">
          <div className="editor-section neon-panel">
            <Editor
              height="100%"
              defaultLanguage="c"
              theme={currentTheme === "snow" ? "light" : "vs-dark"}
              value={code}
              onChange={(value) => setCode(value ?? "")}
              onMount={(editor, monaco) => {
                editorRef.current = editor;
                monacoRef.current = monaco;
                setEditorReady(true);
              }}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                scrollBeyondLastLine: false,
              }}
            />
          </div>

          <div className="controls neon-panel">
            <button onClick={saveFile} disabled={loading} className="btn-save">
              💾 Save Code
            </button>
            <button onClick={compileCode} disabled={loading} className="btn-compile">
              {loading ? "🛡 Checking..." : "🛡 Secure Compile"}
            </button>
            <button
              className="btn-clear"
              onClick={() => {
                setCode("");
                setResult([]);
                setError("");
                setCompileOutput("");
                setActiveTab("output");
              }}
            >
              🧹 Reset Workspace
            </button>
          </div>
        </div>
      </div>

      <div
        className="output-section neon-panel"
        style={{ height: outputHeight }}
      >
        <div
          className="output-resize-handle"
          role="separator"
          aria-label="Resize output panel"
          onMouseDown={(e) => {
            dragRef.current.dragging = true;
            dragRef.current.startY = e.clientY;
            dragRef.current.startHeight = outputHeight;
          }}
        />
        <div className="output-tabs">
          <button
            type="button"
            className={activeTab === "output" ? "tab-active" : ""}
            onClick={() => setActiveTab("output")}
          >
            Output
          </button>
          <button
            type="button"
            className={activeTab === "security" ? "tab-active" : ""}
            onClick={() => setActiveTab("security")}
          >
            Security Report
          </button>
        </div>

        {error ? (
          <div className="error-box">{error}</div>
        ) : null}

        {activeTab === "output" ? (
          <div>
            <h2>Compiler Output</h2>
            {compileOutput ? (
              <div className="compile-output">
                <h3>Compiler Messages</h3>
                <pre>{compileOutput}</pre>
              </div>
            ) : (
              <p>Run secure compile to see output.</p>
            )}
          </div>
        ) : null}

        {activeTab === "security" ? (
          <div>
            <h2>Security Report</h2>
            <div className="security-report-card">
              <p>Status: <strong>{hasVulnerabilities ? "RISK DETECTED" : "SECURE"} {hasVulnerabilities ? "⚠️" : "✅"}</strong></p>
              <p>Vulnerabilities Found: {pretty.length}</p>
              <p>Risk Level: {threatLevel}</p>
              {!hasVulnerabilities ? (
                <div>
                  <p><strong>No vulnerabilities detected.</strong></p>
                  <p>✔ No buffer overflow risks</p>
                  <p>✔ No unsafe memory usage</p>
                  <p>✔ Code passed all checks</p>
                </div>
              ) : (
                pretty.map((v, i) => (
                  <div key={`${v.type}-${v.pattern}-${v.line}-${i}`} className="finding">
                    <div className="finding-header">
                      <b>{v.type}</b>
                      <span className="severity">{v.severity || "UNKNOWN"}</span>
                    </div>
                    {Number.isFinite(v.line) ? <p>Line: {v.line}</p> : null}
                    {v.pattern ? <p>Pattern: {v.pattern}</p> : null}
                    {typeof v.confidence === "number" ? (
                      <p>Confidence: {(v.confidence * 100).toFixed(2)}%</p>
                    ) : null}
                    {v.fix ? <p>Recommendation: <span>{v.fix}</span></p> : null}
                  </div>
                ))
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

