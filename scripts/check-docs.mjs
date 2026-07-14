import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const ignoredDirectories = new Set(['.git', 'coverage', 'dist', 'node_modules']);

function markdownFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    if (ignoredDirectories.has(entry)) continue;
    const path = join(directory, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) files.push(...markdownFiles(path));
    else if (extname(entry).toLowerCase() === '.md') files.push(path);
  }
  return files;
}

function anchors(markdown) {
  return new Set(
    markdown
      .split('\n')
      .filter((line) => /^#{1,6}\s+/.test(line))
      .map((line) =>
        line
          .replace(/^#{1,6}\s+/, '')
          .trim()
          .toLowerCase()
          .replace(/[`*_~]/g, '')
          .replace(/[^\p{L}\p{N}\s-]/gu, '')
          .replace(/\s+/g, '-')
      )
  );
}

const failures = [];
for (const file of markdownFiles(root)) {
  const content = readFileSync(file, 'utf8');
  const links = content.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g);
  for (const match of links) {
    const rawTarget = match[1]?.trim().replace(/^<|>$/g, '');
    if (!rawTarget || /^(?:https?:|mailto:)/i.test(rawTarget)) continue;

    const [rawPath, rawAnchor] = rawTarget.split('#', 2);
    const target = rawPath ? resolve(dirname(file), decodeURIComponent(rawPath)) : file;
    if (!existsSync(target)) {
      failures.push(`${file.slice(root.length + 1)} -> ${rawTarget}`);
      continue;
    }
    if (rawAnchor && statSync(target).isFile()) {
      const targetAnchors = anchors(readFileSync(target, 'utf8'));
      if (!targetAnchors.has(decodeURIComponent(rawAnchor).toLowerCase())) {
        failures.push(`${file.slice(root.length + 1)} -> missing anchor ${rawTarget}`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(
    `Documentation link check failed:\n${failures.map((item) => `- ${item}`).join('\n')}`
  );
  process.exitCode = 1;
} else {
  console.log('Documentation links are valid.');
}
