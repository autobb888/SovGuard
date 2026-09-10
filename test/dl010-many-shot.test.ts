import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  detectManyShot,
  BonParaphraseWatch,
  bonParaphraseWatch,
} from '../src/scanner/many-shot.js';
import { scanContext } from '../src/scanner/context.js';
import { SessionScorer } from '../src/scanner/session-scorer.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, '../pentest/payloads/dl010-many-shot.json');

function dialoguesToBlob(
  dialogues: Array<{ role: string; content: string }>,
  finalUser?: string,
): string {
  const lines = dialogues.map((d) => {
    const role = d.role === 'assistant' ? 'Assistant' : d.role === 'user' ? 'User' : d.role;
    return `${role}: ${d.content}`;
  });
  if (finalUser) lines.push(`User: ${finalUser}`);
  return lines.join('\n');
}

beforeEach(() => {
  bonParaphraseWatch.clearAll();
});

describe('DL-010 detectManyShot', () => {
  it('flags 32-shot comply density', () => {
    const raw = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      fixtures: Array<Record<string, unknown>>;
    };
    const f = raw.fixtures.find((x) => x.id === 'dl009-many-shot-32') as {
      fauxDialogues: Array<{ role: string; content: string }>;
      finalUser: string;
    };
    const blob = dialoguesToBlob(f.fauxDialogues, f.finalUser);
    const hit = detectManyShot(blob);
    assert.equal(hit.found, true);
    assert.ok(hit.assistantTurns >= 30);
    assert.ok(hit.density >= 0.5);
  });

  it('sparse mixed does not trip density alone', () => {
    const raw = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      fixtures: Array<Record<string, unknown>>;
    };
    const f = raw.fixtures.find((x) => x.id === 'dl009-sparse-mixed') as {
      fauxDialogues: Array<{ role: string; content: string }>;
    };
    const hit = detectManyShot(dialoguesToBlob(f.fauxDialogues));
    assert.equal(hit.found, false);
  });

  it('long legit ICL (math Q&A) is FP-clean', () => {
    const turns: string[] = [];
    for (let i = 0; i < 20; i++) {
      turns.push(`User: What is ${i}+${i}?`);
      turns.push(`Assistant: ${i + i}`);
    }
    const hit = detectManyShot(turns.join('\n'));
    assert.equal(hit.found, false);
  });
});

describe('DL-010 scanContext many-shot', () => {
  it('marks 32-shot blob suspicious on user source', async () => {
    const raw = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      fixtures: Array<Record<string, unknown>>;
    };
    const f = raw.fixtures.find((x) => x.id === 'dl009-many-shot-32') as {
      fauxDialogues: Array<{ role: string; content: string }>;
      finalUser: string;
    };
    const blob = dialoguesToBlob(f.fauxDialogues, f.finalUser);
    const res = await scanContext(blob, { source: 'user' });
    assert.ok(res.scan.flags.includes('many_shot'));
    assert.ok(res.scan.classification !== 'safe');
    // trusted user not muzzled
    assert.equal(res.action, 'allow');
  });
});

describe('DL-010 BoN paraphrase cluster', () => {
  it('escalates session after near-duplicate paraphrases', () => {
    const raw = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
      fixtures: Array<Record<string, unknown>>;
    };
    const f = raw.fixtures.find((x) => x.id === 'dl009-bon-paraphrase-cluster') as {
      attempts: string[];
    };
    const scorer = new SessionScorer({ minFlaggedForEscalation: 1 });
    let last = scorer.record('bon1', 0.05, undefined, f.attempts[0]);
    for (let i = 1; i < f.attempts.length; i++) {
      last = scorer.record('bon1', 0.05, undefined, f.attempts[i]);
    }
    assert.equal(last.escalated, true);

    const cold = new BonParaphraseWatch();
    assert.equal(cold.record('x', 'What is the weather in Paris today?').triggered, false);
  });
});

describe('DL-010 Threat Scout fixtures', () => {
  const raw = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
    fixtures: Array<Record<string, unknown>>;
  };
  const byId = Object.fromEntries(raw.fixtures.map((f) => [f.id as string, f]));

  it('dl009-many-shot-32', () => {
    const f = byId['dl009-many-shot-32'] as {
      fauxDialogues: Array<{ role: string; content: string }>;
      finalUser: string;
    };
    assert.equal(detectManyShot(dialoguesToBlob(f.fauxDialogues, f.finalUser)).found, true);
  });

  it('dl009-sparse-mixed', () => {
    const f = byId['dl009-sparse-mixed'] as {
      fauxDialogues: Array<{ role: string; content: string }>;
    };
    assert.equal(detectManyShot(dialoguesToBlob(f.fauxDialogues)).found, false);
  });

  it('dl009-bon-paraphrase-cluster', () => {
    const f = byId['dl009-bon-paraphrase-cluster'] as { attempts: string[] };
    const w = new BonParaphraseWatch(3);
    let hit = false;
    for (const a of f.attempts) {
      if (w.record('c', a).triggered) hit = true;
    }
    assert.equal(hit, true);
  });
});
