import { EVPError, type VerificationResult } from '@aspect-evp/core';
import { createTestFlow, generateNonce } from '@aspect-evp/core/testing';
import { EmailVerificationVerifier } from '@aspect-evp/verifier';
import { defineCommand } from 'citty';
import consola from 'consola';
import pc from 'picocolors';
import {
  formatDim,
  formatError,
  formatHeader,
  formatJson,
  formatSuccess,
  formatTable,
  symbols,
  truncate,
} from '../utils/format.js';

interface Step {
  name: string;
  status: 'pending' | 'running' | 'success' | 'error';
  duration?: number;
  details?: string;
}

interface TestArgs {
  email: string;
  issuer: string;
  origin: string;
  verbose: boolean;
  json: boolean;
}

/** Create initial steps for the EVP flow */
function createSteps(): Step[] {
  return [
    { name: 'Generate test keys', status: 'pending' },
    { name: 'Configure mock DNS', status: 'pending' },
    { name: 'Generate session nonce', status: 'pending' },
    { name: 'Issue EVT', status: 'pending' },
    { name: 'Create Key Binding JWT', status: 'pending' },
    { name: 'Verify EVT+KB token', status: 'pending' },
  ];
}

/** Get icon and text styling for a step based on status */
function getStepDisplay(step: Step): { icon: string; text: string } {
  switch (step.status) {
    case 'pending':
      return { icon: pc.dim('○'), text: pc.dim(step.name) };
    case 'running':
      return { icon: pc.yellow('◐'), text: pc.yellow(step.name) };
    case 'success': {
      let text = pc.green(step.name);
      if (step.duration) {
        text += pc.dim(` (${step.duration}ms)`);
      }
      return { icon: pc.green('●'), text };
    }
    case 'error':
      return { icon: pc.red('●'), text: pc.red(step.name) };
  }
}

/** Render the steps progress display */
function renderSteps(steps: Step[], args: TestArgs) {
  if (args.json) return;

  console.clear();
  console.log();
  console.log(formatHeader('EVP Flow Simulation'));
  console.log(formatDim('─'.repeat(50)));
  console.log();
  console.log(
    formatTable([
      ['Email', args.email],
      ['Issuer', args.issuer],
      ['RP Origin', args.origin],
    ])
  );
  console.log();

  for (const step of steps) {
    const { icon, text } = getStepDisplay(step);
    console.log(`  ${icon} ${text}`);
    if (step.details && args.verbose) {
      console.log(`    ${pc.dim(step.details)}`);
    }
  }
  console.log();
}

/** Output success result */
function outputSuccess(result: VerificationResult, token: string, args: TestArgs) {
  if (args.json) {
    console.log(
      formatJson({
        success: true,
        config: {
          email: args.email,
          issuer: args.issuer,
          rpOrigin: args.origin,
        },
        result: {
          email: result.email,
          issuer: result.issuer,
          issuedAt: result.issuedAt.toISOString(),
        },
        token: args.verbose ? token : undefined,
      })
    );
    return;
  }

  console.log(formatSuccess('Full EVP flow completed successfully!'));
  console.log();

  console.log(formatHeader('Verification Result'));
  console.log(formatDim('─'.repeat(50)));
  console.log();
  console.log(
    formatTable([
      ['Email', result.email],
      ['Issuer', result.issuer],
      ['Issued At', result.issuedAt.toISOString()],
    ])
  );

  if (args.verbose) {
    console.log();
    console.log(formatHeader('Token'));
    console.log(formatDim('─'.repeat(50)));
    console.log();
    console.log(pc.dim(token));
  }

  console.log();
  console.log(`${symbols.info} ${pc.dim('This simulates the browser-mediated EVP flow.')}`);
  console.log(`${symbols.info} ${pc.dim('In production, the browser handles steps 3-4.')}`);
}

/** Output error result */
function outputError(error: unknown, asJson: boolean): never {
  if (asJson) {
    const errorInfo: { success: boolean; error: string; code?: string } = {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
    if (error instanceof EVPError) {
      errorInfo.code = error.code;
    }
    console.log(formatJson(errorInfo));
    process.exit(1);
  }

  console.log(formatError('EVP flow failed'));
  console.log();

  if (error instanceof EVPError) {
    console.log(
      formatTable([
        ['Error Code', error.code],
        ['Message', error.message],
      ])
    );
  } else {
    consola.error(error);
  }
  process.exit(1);
}

/** Create step runner with state management */
function createStepRunner(steps: Step[], args: TestArgs) {
  function updateStep(index: number, update: Partial<Step>) {
    const step = steps[index];
    if (step) Object.assign(step, update);
  }

  async function runStep<T>(index: number, fn: () => Promise<T>): Promise<T> {
    const step = steps[index];
    if (!step) throw new Error(`Invalid step index: ${index}`);

    step.status = 'running';
    renderSteps(steps, args);

    const start = Date.now();
    try {
      const result = await fn();
      step.status = 'success';
      step.duration = Date.now() - start;
      return result;
    } catch (error) {
      step.status = 'error';
      step.details = error instanceof Error ? error.message : String(error);
      renderSteps(steps, args);
      throw error;
    }
  }

  return { updateStep, runStep };
}

export const testCommand = defineCommand({
  meta: {
    name: 'test',
    description: 'Run a complete EVP flow simulation',
  },
  args: {
    email: {
      type: 'string',
      alias: 'e',
      description: 'Email address to test with',
      default: 'user@example.com',
    },
    issuer: {
      type: 'string',
      alias: 'i',
      description: 'Issuer domain',
      default: 'issuer.example.com',
    },
    origin: {
      type: 'string',
      alias: 'o',
      description: 'RP origin',
      default: 'https://app.example.com',
    },
    verbose: {
      type: 'boolean',
      alias: 'v',
      description: 'Show detailed output',
      default: false,
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    const steps = createSteps();
    const { updateStep, runStep } = createStepRunner(steps, args as TestArgs);

    try {
      // Step 0: Create test flow (generates keys)
      const testFlow = await runStep(0, async () => {
        const flow = await createTestFlow({
          issuer: args.issuer,
          rpOrigin: args.origin,
        });
        updateStep(0, { details: 'Algorithm: EdDSA' });
        return flow;
      });

      // Step 1: DNS configured as part of test flow
      updateStep(1, {
        status: 'success',
        details: `_email-verification.${args.email.split('@')[1]} → ${args.issuer}`,
      });

      // Step 2: Generate nonce
      const nonce = await runStep(2, async () => {
        const n = generateNonce(32);
        updateStep(2, { details: `Nonce: ${truncate(n, 20)}` });
        return n;
      });

      // Step 3: Issue token
      const token = await runStep(3, async () => {
        const t = await testFlow.createToken(args.email, nonce);
        updateStep(3, { details: `Token length: ${t.length} chars` });
        return t;
      });

      // Step 4: KB-JWT (part of createToken)
      updateStep(4, { status: 'success', details: 'Bound to session nonce and RP origin' });

      // Step 5: Verify token
      const result = await runStep(5, async () => {
        const verifier = new EmailVerificationVerifier({
          rpOrigin: args.origin,
          dnsResolver: testFlow.dnsResolver,
          fetch: testFlow.fetch,
        });
        const r = await verifier.verify(token, nonce);
        updateStep(5, { details: `Verified: ${r.email}` });
        return r;
      });

      renderSteps(steps, args as TestArgs);
      outputSuccess(result, token, args as TestArgs);
    } catch (error) {
      renderSteps(steps, args as TestArgs);
      outputError(error, args.json);
    }
  },
});
