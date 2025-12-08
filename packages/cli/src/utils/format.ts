import pc from 'picocolors';

export const symbols = {
  success: pc.green('✓'),
  error: pc.red('✗'),
  warning: pc.yellow('⚠'),
  info: pc.blue('ℹ'),
  arrow: pc.cyan('→'),
  bullet: pc.dim('•'),
};

export function formatKey(key: string): string {
  return pc.dim(`${key}:`);
}

export function formatValue(value: string | number | boolean): string {
  if (typeof value === 'boolean') {
    return value ? pc.green('true') : pc.red('false');
  }
  return pc.white(String(value));
}

export function formatHeader(text: string): string {
  return pc.bold(pc.cyan(text));
}

export function formatSuccess(text: string): string {
  return `${symbols.success} ${pc.green(text)}`;
}

export function formatError(text: string): string {
  return `${symbols.error} ${pc.red(text)}`;
}

export function formatWarning(text: string): string {
  return `${symbols.warning} ${pc.yellow(text)}`;
}

export function formatDim(text: string): string {
  return pc.dim(text);
}

export function formatJson(obj: unknown): string {
  return JSON.stringify(obj, null, 2);
}

export function formatTable(rows: Array<[string, string]>): string {
  const maxKeyLength = Math.max(...rows.map(([k]) => k.length));
  return rows
    .map(([key, value]) => `  ${formatKey(key.padEnd(maxKeyLength))} ${formatValue(value)}`)
    .join('\n');
}

export function formatBox(title: string, content: string): string {
  const lines = content.split('\n');
  const maxLength = Math.max(title.length, ...lines.map((l) => l.length));
  const border = pc.dim('─'.repeat(maxLength + 4));

  return [
    `${pc.dim('┌')}${border}${pc.dim('┐')}`,
    `${pc.dim('│')}  ${formatHeader(title.padEnd(maxLength))}  ${pc.dim('│')}`,
    `${pc.dim('├')}${border}${pc.dim('┤')}`,
    ...lines.map((line) => `${pc.dim('│')}  ${line.padEnd(maxLength)}  ${pc.dim('│')}`),
    `${pc.dim('└')}${border}${pc.dim('┘')}`,
  ].join('\n');
}

export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return `${str.slice(0, maxLength - 3)}...`;
}
