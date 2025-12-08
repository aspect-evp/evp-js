#!/usr/bin/env node
import { defineCommand, runMain } from 'citty';
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
    version: '0.1.0',
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
