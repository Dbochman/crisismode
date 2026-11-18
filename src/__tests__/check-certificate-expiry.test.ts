// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CrisisMode Contributors

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const script = join(import.meta.dirname, '../../checks/check-certificate-expiry/check.sh');

describe('certificate check output contract', () => {
  let bin: string;

  beforeEach(() => {
    bin = mkdtempSync(join(tmpdir(), 'certificate-check-'));
    // Replace only openssl: no sockets, certificates, or remote services needed.
    writeFileSync(join(bin, 'openssl'), `#!/usr/bin/env bash
set -eu
if [ "$1" = s_client ]; then
  if [ "$CERT_MODE" = empty ]; then exit 1; fi
  printf '%s\\n' 'TLS handshake output'
  exit 1
fi
cat >/dev/null
if [ "$CERT_MODE" = invalid ]; then exit 1; fi
case "$*" in
  *-enddate*) printf 'notAfter=%s\\n' "$CERT_EXPIRY" ;;
  *-serial*)
    if [ "$CERT_MODE" = missing-serial ]; then exit 1; fi
    printf 'serial=1234\\n' ;;
  *)
    printf 'subject=CN=fixture.test\\nissuer=CN=fixture CA\\nnotAfter=%s\\n' "$CERT_EXPIRY"
    if [ "$CERT_MODE" != missing-sans ]; then
      printf 'X509v3 Subject Alternative Name:\\n    DNS:fixture.test\\n'
    fi ;;
esac
`, { mode: 0o755 });
  });

  afterEach(() => {
    rmSync(bin, { recursive: true, force: true });
  });

  function run(verb: string, mode: string, days = 90) {
    const expiry = new Date(Date.now() + days * 86_400_000);
    const result = spawnSync('bash', [script], {
      input: JSON.stringify({ verb, target: { host: 'fixture.test', port: 443 } }),
      encoding: 'utf8',
      timeout: 5000,
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        CERT_MODE: mode,
        // OpenSSL's format, accepted by both BSD and GNU date.
        CERT_EXPIRY: `${expiry.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' })} ${expiry.getUTCDate()} ${expiry.toISOString().slice(11, 19)} ${expiry.getUTCFullYear()} GMT`,
      },
    });
    expect(result.error).toBeUndefined();
    expect(result.stderr).toBe('');
    expect(result.stdout.trim(), `${verb}/${mode} must emit JSON`).not.toBe('');
    return { code: result.status, output: JSON.parse(result.stdout) };
  }

  it.each(['health', 'diagnose'])('%s reports a connection failure with empty OpenSSL output', (verb) => {
    const { code, output } = run(verb, 'empty');
    expect(code).toBe(2);
    expect(output.summary).toContain('Could not connect');
    if (verb === 'health') expect(output.status).toBe('critical');
    else expect(output).toMatchObject({ healthy: false, findings: [{ id: 'cert-conn-fail' }] });
  });

  it.each(['health', 'diagnose'])('%s reports malformed certificate output instead of exiting silently', (verb) => {
    const { code, output } = run(verb, 'invalid');
    expect(code).toBe(3);
    expect(output.summary).toContain('Could not parse certificate');
    if (verb === 'health') expect(output.status).toBe('unknown');
    else expect(output).toMatchObject({ healthy: false, findings: [{ id: 'cert-parse-fail' }] });
  });

  it.each([
    [90, 'healthy', 0],
    [20, 'warning', 1],
    [-2, 'critical', 2],
  ] as const)('health reports certificates expiring in %i days as %s', (days, status, code) => {
    const result = run('health', 'valid', days);
    expect(result.code).toBe(code);
    expect(result.output).toMatchObject({ status, confidence: expect.any(Number), signals: expect.any(Array) });
  });

  it.each([
    ['valid', 'DNS:fixture.test', '1234'],
    ['missing-sans', 'none found', '1234'],
    ['missing-serial', 'DNS:fixture.test', 'unknown'],
  ])('diagnose preserves JSON when optional certificate details are %s', (mode, sans, serial) => {
    const { code, output } = run('diagnose', mode);
    expect(code).toBe(0);
    expect(output.healthy).toBe(true);
    expect(output.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'cert-sans', detail: sans }),
      expect.objectContaining({ id: 'cert-serial', detail: serial }),
    ]));
  });
});
