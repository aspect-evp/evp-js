import { EVPError } from '@aspect-evp/core';
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
    const steps: Array<{
      name: string;
      status: 'pending' | 'running' | 'success' | 'error';
      duration?: number;
      details?: string;
    }> = [
      { name: 'Generate test keys', status: 'pending' },
      { name: 'Configure mock DNS', status: 'pending' },
      { name: 'Generate session nonce', status: 'pending' },
      { name: 'Issue SD-JWT token', status: 'pending' },
      { name: 'Create Key Binding JWT', status: 'pending' },
      { name: 'Verify SD-JWT+KB token', status: 'pending' },
    ];

    function renderSteps() {
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
        let icon: string;
        let text: string;

        switch (step.status) {
          case 'pending':
            icon = pc.dim('○');
            text = pc.dim(step.name);
            break;
          case 'running':
            icon = pc.yellow('◐');
            text = pc.yellow(step.name);
            break;
          case 'success':
            icon = pc.green('●');
            text = pc.green(step.name);
            if (step.duration) {
              text += pc.dim(` (${step.duration}ms)`);
            }
            break;
          case 'error':
            icon = pc.red('●');
            text = pc.red(step.name);
            break;
        }

        console.log(`  ${icon} ${text}`);
        if (step.details && args.verbose) {
          console.log(`    ${pc.dim(step.details)}`);
        }
      }
      console.log();
    }

    async function runStep<T>(index: number, fn: () => Promise<T>): Promise<T> {
      const step = steps[index];
      if (!step) throw new Error(`Invalid step index: ${index}`);

      step.status = 'running';
      renderSteps();

      const start = Date.now();
      try {
        const result = await fn();
        step.status = 'success';
        step.duration = Date.now() - start;
        return result;
      } catch (error) {
        step.status = 'error';
        step.details = error instanceof Error ? error.message : String(error);
        renderSteps();
        throw error;
      }
    }

    try {
      // Step 0-1: Create test flow (generates keys + configures DNS)
      const testFlow = await runStep(0, async () => {
        const flow = await createTestFlow({
          issuer: args.issuer,
          rpOrigin: args.origin,
        });
        steps[0]!.details = 'Algorithm: EdDSA';
        return flow;
      });

      // Step 1: DNS configured as part of test flow
      steps[1]!.status = 'success';
      steps[1]!.details = `_email-verification.${args.email.split('@')[1]} → ${args.issuer}`;

      // Step 2: Generate nonce
      const nonce = await runStep(2, async () => {
        const n = generateNonce(32);
        steps[2]!.details = `Nonce: ${truncate(n, 20)}`;
        return n;
      });

      // Step 3-4: Create token (simulates browser + issuer)
      const token = await runStep(3, async () => {
        const t = await testFlow.createToken(args.email, nonce);
        steps[3]!.details = `Token length: ${t.length} chars`;
        return t;
      });

      // Mark KB-JWT step as done (it's part of createToken)
      steps[4]!.status = 'success';
      steps[4]!.details = 'Bound to session nonce and RP origin';

      // Step 5: Verify token
      const result = await runStep(5, async () => {
        const verifier = new EmailVerificationVerifier({
          rpOrigin: args.origin,
          dnsResolver: testFlow.dnsResolver,
          fetch: testFlow.fetch,
        });

        const r = await verifier.verify(token, nonce);
        steps[5]!.details = `Verified: ${r.email}`;
        return r;
      });

      renderSteps();

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
    } catch (error) {
      renderSteps();

      if (args.json) {
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
  },
});
