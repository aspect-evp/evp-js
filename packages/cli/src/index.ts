// Public API for programmatic usage
export {
  dnsCommand,
  inspectCommand,
  issueCommand,
  keygenCommand,
  testCommand,
  verifyCommand,
} from './commands/index.js';

// Re-export utilities for custom CLI tools
export * from './utils/format.js';
