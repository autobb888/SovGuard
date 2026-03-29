import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanTopics, type TopicRailsConfig } from '../src/scanner/topic-rails.js';

const config: TopicRailsConfig = {
  deniedTopics: [
    {
      name: 'competitors',
      keywords: ['CompetitorX', 'RivalCo', 'OtherProduct'],
      action: 'flag',
    },
    {
      name: 'legal-advice',
      keywords: ['legal advice', 'attorney', 'lawsuit'],
      action: 'block',
    },
    {
      name: 'internal-tools',
      keywords: ['internal dashboard'],
      patterns: [/\bproject[-\s]?alpha\b/i],
      action: 'block',
    },
  ],
};

describe('Topic/Policy Rails', () => {
  it('should match a denied topic by keyword', () => {
    const matches = scanTopics('Have you tried CompetitorX for this?', config);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].topic, 'competitors');
    assert.equal(matches[0].action, 'flag');
  });

  it('should match multiple topics in one message', () => {
    const matches = scanTopics('Ask your attorney about CompetitorX', config);
    assert.equal(matches.length, 2);
    const topics = matches.map(m => m.topic).sort();
    assert.deepEqual(topics, ['competitors', 'legal-advice']);
  });

  it('should respect word boundaries', () => {
    // "compete" should not match "CompetitorX" keyword
    const matches = scanTopics('We need to compete harder in this market', config);
    assert.equal(matches.length, 0);
  });

  it('should return empty array when no topics match', () => {
    const matches = scanTopics('The weather is nice today', config);
    assert.equal(matches.length, 0);
  });

  it('should match regex patterns', () => {
    const matches = scanTopics('Check status on project-alpha', config);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].topic, 'internal-tools');
    assert.equal(matches[0].action, 'block');
  });

  it('should handle action: block vs flag', () => {
    const flagMatch = scanTopics('Try RivalCo instead', config);
    assert.equal(flagMatch[0].action, 'flag');

    const blockMatch = scanTopics('You should get legal advice', config);
    assert.equal(blockMatch[0].action, 'block');
  });

  it('should be case-insensitive', () => {
    const matches = scanTopics('have you heard of COMPETITORX?', config);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].topic, 'competitors');
  });

  it('should return empty when no config provided', () => {
    const matches = scanTopics('anything', { deniedTopics: [] });
    assert.equal(matches.length, 0);
  });

  it('should default action to flag', () => {
    const cfg: TopicRailsConfig = {
      deniedTopics: [{ name: 'test', keywords: ['banana'] }],
    };
    const matches = scanTopics('I like banana splits', cfg);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].action, 'flag');
  });

  it('should prefer keyword match over pattern match (no duplicates)', () => {
    const matches = scanTopics('Check the internal dashboard for project alpha', config);
    assert.equal(matches.length, 1);
    assert.equal(matches[0].topic, 'internal-tools');
    assert.equal(matches[0].keyword, 'internal dashboard');
  });
});
