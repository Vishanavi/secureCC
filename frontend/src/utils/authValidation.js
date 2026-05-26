/** Username: letter first, then letters/digits/underscore, 3–30 chars. */
export const USERNAME_REGEX = /^[a-zA-Z][a-zA-Z0-9_]{2,29}$/;

export function validateUsername(username) {
  const value = (username || "").trim();
  if (!value) {
    return "Username is required.";
  }
  if (!/^[a-zA-Z]/.test(value)) {
    return "Username must start with a letter (not a number).";
  }
  if (!USERNAME_REGEX.test(value)) {
    return "Use 3–30 characters: letters, numbers, and underscore only.";
  }
  return null;
}

export function getPasswordChecks(password) {
  const value = password || "";
  return [
    { id: "length", label: "At least 6 characters", ok: value.length >= 6 },
    { id: "lower", label: "One lowercase letter (a–z)", ok: /[a-z]/.test(value) },
    { id: "upper", label: "One uppercase letter (A–Z)", ok: /[A-Z]/.test(value) },
    { id: "digit", label: "One number (0–9)", ok: /\d/.test(value) },
    {
      id: "special",
      label: "One special symbol (!@#$…)",
      ok: /[^a-zA-Z0-9]/.test(value),
    },
  ];
}

export function validatePassword(password) {
  const checks = getPasswordChecks(password);
  const failed = checks.find((c) => !c.ok);
  if (failed) {
    return `Password does not meet requirements: ${failed.label}.`;
  }
  return null;
}

export function isPasswordValid(password) {
  return getPasswordChecks(password).every((c) => c.ok);
}
