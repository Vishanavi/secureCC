import { useEffect, useState } from "react";
import ThemeSwitcher from "./ThemeSwitcher";

const PARTICLES = Array.from({ length: 24 }, (_, i) => ({
  id: i,
  left: `${(i * 17) % 100}%`,
  delay: `${(i % 8) * 0.45}s`,
  duration: `${7 + (i % 6)}s`,
}));

export default function GetStartedPage({ onContinue, theme, onThemeChange }) {
  const [scanValue, setScanValue] = useState(1);
  const [scrollY, setScrollY] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setScanValue((prev) => (prev >= 50 ? 1 : prev + 1));
    }, 90);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY || 0);

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();

    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const heroFadeProgress = Math.min(scrollY / 500, 1);
  const heroStyle = {
    transform: `translateY(-${scrollY * 0.3}px)`,
    opacity: Math.max(1 - heroFadeProgress, 0),
  };

  return (
    <div className="dora-page">
      <header className="dora-nav-wrap">
        <div className="dora-brand">SecureCC</div>
        <ThemeSwitcher currentTheme={theme} onThemeChange={onThemeChange} />
        <button type="button" className="dora-cta-top" onClick={onContinue}>
          Get Started
        </button>
      </header>

      <section className="dora-hero" style={heroStyle}>
        <div className="dora-globe" aria-hidden="true" />
        <div className="dora-stars" aria-hidden="true">
          {PARTICLES.map((particle) => (
            <span
              key={particle.id}
              className="dora-star"
              style={{
                left: particle.left,
                animationDelay: particle.delay,
                animationDuration: particle.duration,
              }}
            />
          ))}
        </div>
        <p className="dora-kicker">Secure Compiler AI</p>
        <h1 className="dora-title">
          Scan code beyond vulnerabilities,
          <br />
          compile with confidence.
        </h1>
        <div className="dora-prompt">
          <span>Analyze C code for buffer overflow and risky calls...</span>
          <button type="button" onClick={onContinue}>
            Continue
          </button>
        </div>
      </section>

      <section className="dora-pipeline">
        <div className="dora-left">
          <p className="dora-kicker dora-kicker-orange">Security Pipeline</p>
          <h2>Build secure code, end-to-end.</h2>
          <div className="dora-steps">
            <div className={scanValue < 18 ? "active" : ""}>
              <strong>Analyzing input...</strong>
              <p>SecureCC inspects patterns and data flow risks.</p>
            </div>
            <div className={scanValue >= 18 && scanValue < 36 ? "active" : ""}>
              <strong>Detecting threats...</strong>
              <p>Dangerous functions and overflow paths are flagged.</p>
            </div>
            <div className={scanValue >= 36 ? "active" : ""}>
              <strong>Safe compile gate...</strong>
              <p>Compilation proceeds only after passing policy checks.</p>
            </div>
          </div>
        </div>

        <div className="dora-right">
          <div className="dora-mock-panel">
            <div className="dora-mock-top">
              <span />
              <span />
              <span />
            </div>
            <div className="dora-mock-content">
              <div className="dora-metric">
                <p>Threat Scan Progress</p>
                <h3>{scanValue}%</h3>
              </div>
              <div className="dora-progress">
                <div style={{ width: `${(scanValue / 50) * 100}%` }} />
              </div>
              <pre>{`int size = n * sizeof(int);\nmalloc(size);`}</pre>
            </div>
          </div>
        </div>
      </section>

      <div className="dora-bottom-cta">
        <button type="button" className="dora-cta-bottom" onClick={onContinue}>
          Continue to Login
        </button>
      </div>
    </div>
  );
}
