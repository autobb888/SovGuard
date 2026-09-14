import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  shouldPromoteCorroboration,
  shouldPromoteH2j,
  shouldPromoteH2e,
  shouldPromoteH3c,
  H1_PROMOTE_FLAG,
  H2J_PROMOTE_FLAG,
  H2E_PROMOTE_FLAG,
  H3C_PROMOTE_FLAG,
} from '../src/scanner/corroboration-promote.js';

const T = { blockThreshold: 0.7 };

describe('H1 corroboration promote (pure rule)', () => {
  it('promotes untrusted when PA≥0.5 and PG≥0.3', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'untrusted_content',
        pa: 0.99,
        pg: 0.45,
        retrievalHit: false,
        combinedScore: 0.69,
        ...T,
      }),
      true,
    );
  });

  it('promotes untrusted when PA≥0.5 and retrievalHit (PG low)', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'untrusted_content',
        pa: 0.8,
        pg: 0.1,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      true,
    );
  });

  it('never promotes on PG alone (PA < 0.5)', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'untrusted_content',
        pa: 0.0,
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply on user_chat', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'user_chat',
        pa: 0.99,
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.69,
        ...T,
      }),
      false,
    );
  });

  it('does not apply on security_research', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'security_research',
        pa: 0.99,
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.69,
        ...T,
      }),
      false,
    );
  });

  it('does not apply when mode is omitted (default scan)', () => {
    assert.equal(
      shouldPromoteCorroboration({
        pa: 0.99,
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.69,
        ...T,
      }),
      false,
    );
  });

  it('does not re-promote when already ≥ blockThreshold', () => {
    assert.equal(
      shouldPromoteCorroboration({
        mode: 'untrusted_content',
        pa: 0.99,
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.7,
        ...T,
      }),
      false,
    );
  });

  it('flag constant is corroboration_promote', () => {
    assert.equal(H1_PROMOTE_FLAG, 'corroboration_promote');
  });
});

describe('H2j PG∧retrieval promote (pure rule)', () => {
  it('promotes untrusted when PG≥0.3 and retrievalHit (PA low)', () => {
    assert.equal(
      shouldPromoteH2j({
        mode: 'untrusted_content',
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      true,
    );
  });

  it('never promotes on PG alone (no retrievalHit)', () => {
    assert.equal(
      shouldPromoteH2j({
        mode: 'untrusted_content',
        pg: 0.45,
        retrievalHit: false,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('never promotes on retrievalHit alone (PG low)', () => {
    assert.equal(
      shouldPromoteH2j({
        mode: 'untrusted_content',
        pg: 0.1,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply on user_chat', () => {
    assert.equal(
      shouldPromoteH2j({
        mode: 'user_chat',
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply when mode is omitted', () => {
    assert.equal(
      shouldPromoteH2j({
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not re-promote when already ≥ blockThreshold', () => {
    assert.equal(
      shouldPromoteH2j({
        mode: 'untrusted_content',
        pg: 0.45,
        retrievalHit: true,
        combinedScore: 0.7,
        ...T,
      }),
      false,
    );
  });

  it('flag constant is h2j_pg_retrieval_promote', () => {
    assert.equal(H2J_PROMOTE_FLAG, 'h2j_pg_retrieval_promote');
  });
});

describe('H2e ret∧(PG∨sem) promote (pure rule)', () => {
  it('promotes untrusted when retrievalHit and PG≥0.3 (sem low)', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.1,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      true,
    );
  });

  it('promotes untrusted when retrievalHit and sem≥0.3 (PG low)', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.1,
        sem: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      true,
    );
  });

  it('never promotes on retrievalHit alone (PG and sem low)', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.1,
        sem: 0.1,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('never promotes on PG+sem without retrievalHit', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.45,
        retrievalHit: false,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('never promotes on PG alone (no retrieval)', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.0,
        retrievalHit: false,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply on user_chat', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'user_chat',
        pg: 0.45,
        sem: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply when mode is omitted', () => {
    assert.equal(
      shouldPromoteH2e({
        pg: 0.45,
        sem: 0.45,
        retrievalHit: true,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not re-promote when already ≥ blockThreshold', () => {
    assert.equal(
      shouldPromoteH2e({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.45,
        retrievalHit: true,
        combinedScore: 0.7,
        ...T,
      }),
      false,
    );
  });

  it('flag constant is h2e_ret_pg_sem_promote', () => {
    assert.equal(H2E_PROMOTE_FLAG, 'h2e_ret_pg_sem_promote');
  });
});

describe('H3c PG∧sem promote (pure rule)', () => {
  it('promotes untrusted when PG≥0.3 and sem≥0.22', () => {
    assert.equal(
      shouldPromoteH3c({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.22,
        combinedScore: 0.45,
        ...T,
      }),
      true,
    );
  });

  it('never promotes on PG alone (sem below 0.22)', () => {
    assert.equal(
      shouldPromoteH3c({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.21,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('never promotes on sem alone (PG low)', () => {
    assert.equal(
      shouldPromoteH3c({
        mode: 'untrusted_content',
        pg: 0.1,
        sem: 0.45,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply on user_chat', () => {
    assert.equal(
      shouldPromoteH3c({
        mode: 'user_chat',
        pg: 0.45,
        sem: 0.45,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not apply when mode is omitted', () => {
    assert.equal(
      shouldPromoteH3c({
        pg: 0.45,
        sem: 0.45,
        combinedScore: 0.45,
        ...T,
      }),
      false,
    );
  });

  it('does not re-promote when already ≥ blockThreshold', () => {
    assert.equal(
      shouldPromoteH3c({
        mode: 'untrusted_content',
        pg: 0.45,
        sem: 0.45,
        combinedScore: 0.7,
        ...T,
      }),
      false,
    );
  });

  it('flag constant is h3c_pg_sem_promote', () => {
    assert.equal(H3C_PROMOTE_FLAG, 'h3c_pg_sem_promote');
  });
});
