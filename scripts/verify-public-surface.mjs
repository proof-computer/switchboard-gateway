import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const forbiddenPathPatterns = [
  /(^|\/)\.env(\.|\/|$)/,
  /(^|\/)(\.acurast|\.operator-host|\.switchboard|node_modules|dist|tmp|coverage)(\/|$)/,
  /(^|\/).*\.(pem|key|p12|pfx)$/i,
  /(^|\/)(secrets?|credentials?|tokens?|private-keys?)(\/|$)/i
];

const forbiddenContentPatterns = [
  { label: "PEM private key", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { label: "GitHub token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/ },
  { label: "GitHub fine-grained token", pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ }
];

const { stdout } = await execFileAsync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], {
  maxBuffer: 1024 * 1024
});
const files = stdout.split(/\r?\n/).filter(Boolean);

const forbiddenFiles = files.filter((file) => forbiddenPathPatterns.some((pattern) => pattern.test(file)));
const contentFindings = [];

for (const file of files) {
  let contents;
  try {
    contents = await readFile(file, "utf8");
  } catch {
    continue;
  }
  for (const check of forbiddenContentPatterns) {
    if (check.pattern.test(contents)) {
      contentFindings.push({ file, label: check.label });
    }
  }
}

if (forbiddenFiles.length > 0 || contentFindings.length > 0) {
  const details = [];
  if (forbiddenFiles.length > 0) {
    details.push("Forbidden tracked paths:", ...forbiddenFiles.map((file) => `  - ${file}`));
  }
  if (contentFindings.length > 0) {
    if (details.length > 0) details.push("");
    details.push(
      "Forbidden secret-like content:",
      ...contentFindings.map((finding) => `  - ${finding.file}: ${finding.label}`)
    );
  }
  throw new Error(details.join("\n"));
}

console.log(`Verified ${files.length} public gateway files for surface safety.`);
