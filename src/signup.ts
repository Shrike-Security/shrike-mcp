/**
 * Interactive signup flow for shrike-mcp.
 * Creates a free Community account and saves the API key to ~/.shrike/credentials.
 *
 * Usage: npx shrike-mcp --signup
 */

import { createInterface } from 'readline';
import { config } from './config.js';
import { saveCredentials } from './keyProvider.js';

interface RegisterResponse {
  api_key?: string;
  customer_id?: string;
  access_token?: string;
  message?: string;
  error?: string;
}

/**
 * Prompts for a single line of input from the terminal.
 */
function prompt(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim()));
  });
}

/**
 * Prompts for a password without echoing characters.
 * Falls back to visible input if raw mode isn't available (piped stdin).
 */
function promptPassword(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);

    const stdin = process.stdin;
    if (!stdin.isTTY) {
      // Not a TTY (piped input) — read normally
      const rl = createInterface({ input: stdin, output: process.stdout });
      rl.question('', (answer) => {
        rl.close();
        resolve(answer.trim());
      });
      return;
    }

    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let password = '';
    const onData = (ch: string) => {
      const c = ch.toString();
      if (c === '\n' || c === '\r' || c === '\u0004') {
        // Enter or Ctrl-D
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(password);
      } else if (c === '\u0003') {
        // Ctrl-C
        process.stdout.write('\n');
        process.exit(0);
      } else if (c === '\u007F' || c === '\b') {
        // Backspace
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        password += c;
        process.stdout.write('*');
      }
    };

    stdin.on('data', onData);
  });
}

/**
 * Runs the interactive signup flow.
 */
export async function runSignup(): Promise<void> {
  console.log('');
  console.log('  Shrike Security — Free Account Signup');
  console.log('  ─────────────────────────────────────');
  console.log('  Create a free Community account (1,000 scans/month).');
  console.log('  Your API key will be saved to ~/.shrike/credentials.');
  console.log('');

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    const email = await prompt(rl, '  Email: ');
    if (!email || !email.includes('@') || !email.includes('.')) {
      console.error('\n  Error: Valid email address is required.');
      process.exit(1);
    }

    // Close readline before password prompt (raw mode conflicts with readline)
    rl.close();

    const password = await promptPassword('  Password: ');
    if (!password || password.length < 8) {
      console.error('\n  Error: Password must be at least 8 characters.');
      process.exit(1);
    }

    const confirmPassword = await promptPassword('  Confirm password: ');
    if (password !== confirmPassword) {
      console.error('\n  Error: Passwords do not match.');
      process.exit(1);
    }

    console.log('');
    console.log('  Creating account...');

    const endpoint = config.backendUrl;
    const response = await fetch(`${endpoint}/api/v1/community/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as Record<string, unknown>;
      const errorMsg = (body.error as string) || (body.message as string) || `HTTP ${response.status}`;
      console.error(`  Error: ${errorMsg}`);
      process.exit(1);
    }

    const data = await response.json() as RegisterResponse;
    const apiKey = data.api_key;

    if (!apiKey) {
      console.error('  Error: No API key in response. Contact support@shrike.security');
      process.exit(1);
    }

    // Save to ~/.shrike/credentials
    await saveCredentials(apiKey);

    console.log('');
    console.log('  Account created successfully!');
    console.log('');
    console.log(`  API Key: ${apiKey.slice(0, 12)}...${apiKey.slice(-4)}`);
    console.log('  Saved to: ~/.shrike/credentials');
    console.log('');
    console.log('  Next steps:');
    console.log('    1. Run "npx shrike-mcp" to start the MCP server');
    console.log('    2. Or set SHRIKE_API_KEY in your environment');
    console.log('');
  } finally {
    // Ensure readline is closed even on error
    rl.close();
  }
}
