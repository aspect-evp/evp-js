#!/usr/bin/env node
import { defineCommand, runMain } from 'citty';
import packageJson from '../package.json' with { type: 'json' };
import {
  dnsCommand,
  inspectCommand,
  issueCommand,
  keygenCommand,
  testCommand,
  verifyCommand,
} from './commands/index.js';

const main = defineCommand({
  meta: {
    name: 'evp',
    version: packageJson.version,
    description: 'CLI tool for Email Verification Protocol (EVP) testing and development',
  },
  subCommands: {
    keygen: keygenCommand,
    issue: issueCommand,
    verify: verifyCommand,
    inspect: inspectCommand,
    test: testCommand,
    dns: dnsCommand,
  },
});

runMain(main);
