#!/usr/bin/env node
'use strict';
// Standalone staging harness: node shadow-scan.js RECEIPT_ID ATTACHMENT_ID FILE
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const [receiptId, attachmentId, source] = process.argv.slice(2);
if (!receiptId || !attachmentId || !source) { console.error('Usage: shadow-scan.js RECEIPT_ID ATTACHMENT_ID FILE'); process.exit(2); }
const timeout = Number(process.env.SCAN_TIMEOUT_MS || 30000);
if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000) throw Error('Invalid SCAN_TIMEOUT_MS');
function run(exe, args) {
  return new Promise(resolve => {
    const start = performance.now(); let output = ''; let timedOut = false; let failure = null;
    const child = spawn(exe, args, { stdio: ['ignore', 'pipe', 'ignore'], shell: false });
    child.stdout.on('data', chunk => { if (output.length < 1048576) output += chunk.toString().slice(0, 1048576 - output.length); });
    child.on('error', () => { failure = 'spawn_failed'; });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    child.on('close', code => { clearTimeout(timer); resolve({ code, output, error: timedOut ? 'timeout' : failure, duration_ms: Math.round(performance.now() - start) }); });
  });
}
(async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'raxo-shadow-'));
  try {
    const snapshot = path.join(dir, 'attachment');
    await fs.copyFile(source, snapshot, fs.constants.COPYFILE_EXCL);
    await fs.chmod(snapshot, 0o400);
    const c = await run(process.env.CLAMSCAN || 'clamscan', ['--no-summary', '--', snapshot]);
    let clam = c.error ? 'ERROR' : c.code === 0 ? 'CLEAN' : c.code === 1 ? 'DETECTED' : 'ERROR';
    const r = await run(process.env.RAXOSENTINEL || 'raxosentinel', ['client', '--socket', process.env.RAXOSENTINEL_SOCKET || '/run/raxosentinel/scan.sock', '--json-envelope', snapshot]);
    let response; try { response = JSON.parse(r.output); } catch { response = null; }
    const verdict = !r.error && response && ['CLEAN','DETECTED','UNSCANNED','ERROR','BUSY'].includes(response.status) ? response.status : 'ERROR';
    const records = [
      { receipt_id: receiptId, attachment_id: attachmentId, scanner: 'clamav', verdict: clam, database_generation: null, duration_ms: c.duration_ms, error: c.error || (clam === 'ERROR' ? 'scan_failed' : null) },
      { receipt_id: receiptId, attachment_id: attachmentId, scanner: 'raxosentinel', verdict, database_generation: response?.database_generation || null, duration_ms: r.duration_ms, error: r.error || (['ERROR','BUSY','UNSCANNED'].includes(verdict) ? 'scan_failed' : null) }
    ];
    console.log(JSON.stringify(records));
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
})().catch(() => { console.error('Shadow harness failed to prepare attachment'); process.exitCode = 2; });
