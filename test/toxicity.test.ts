import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanToxicity } from '../src/outbound/toxicity.js';

describe('Toxicity Outbound Scanner', () => {
  describe('Hate speech / slurs', () => {
    it('should detect racial slurs', () => {
      const flags = scanToxicity('You are just a dirty wetback');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].type, 'toxicity');
      assert.equal(flags[0].detail, 'hate_speech');
      assert.equal(flags[0].severity, 'high');
      assert.equal(flags[0].action, 'block');
    });

    it('should detect homophobic slurs', () => {
      const flags = scanToxicity('Shut up you stupid faggot');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'hate_speech');
    });

    it('should detect gendered slurs', () => {
      const flags = scanToxicity('She is such a slut');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'hate_speech');
    });
  });

  describe('Threats / violence', () => {
    it('should detect death threats', () => {
      const flags = scanToxicity("I'll kill you and your family");
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'threats_violence');
      assert.equal(flags[0].action, 'block');
    });

    it('should detect stalking threats', () => {
      const flags = scanToxicity("You're dead meat, watch your back");
      assert.ok(flags.length > 0);
    });
  });

  describe('Self-harm', () => {
    it('should detect self-harm encouragement', () => {
      const flags = scanToxicity('You should just kill yourself');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'self_harm');
      assert.equal(flags[0].action, 'block');
    });

    it('should detect kys abbreviation', () => {
      const flags = scanToxicity('just kys nobody cares');
      assert.ok(flags.length > 0);
    });

    it('should NOT flag suicide prevention context', () => {
      const flags = scanToxicity('If you are in crisis, call the suicide prevention hotline at 988. Help is available 24/7.');
      // Should not flag clinical/prevention context
      const selfHarmFlags = flags.filter(f => f.detail === 'self_harm');
      assert.equal(selfHarmFlags.length, 0);
    });
  });

  describe('Sexual content', () => {
    it('should detect explicit sexual content', () => {
      const flags = scanToxicity('Send me your nudes right now');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'sexual_content');
      assert.equal(flags[0].severity, 'medium');
      assert.equal(flags[0].action, 'flag');
    });

    it('should detect sexual solicitation', () => {
      const flags = scanToxicity('Looking for sex in exchange for money');
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'sexual_content');
    });
  });

  describe('Harassment / bullying', () => {
    it('should detect doxxing language', () => {
      const flags = scanToxicity("I've posted your home address online");
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'harassment_bullying');
    });

    it('should detect stalking language', () => {
      const flags = scanToxicity("I'm watching you, I know where you live");
      assert.ok(flags.length > 0);
    });

    it('should detect targeted extreme insults', () => {
      const flags = scanToxicity("You're a worthless waste of oxygen");
      assert.ok(flags.length > 0);
      assert.equal(flags[0].detail, 'harassment_bullying');
    });
  });

  describe('Clean text (no false positives)', () => {
    it('should NOT flag professional business text', () => {
      const flags = scanToxicity('Please review the quarterly report and provide feedback by end of day. The metrics show a 15% improvement in customer satisfaction.');
      assert.equal(flags.length, 0);
    });

    it('should NOT flag medical/clinical discussion', () => {
      const flags = scanToxicity('The patient presents with self-reported depression. Recommend screening for suicidal ideation using PHQ-9. Refer to psychiatry if needed.');
      assert.equal(flags.length, 0);
    });

    it('should NOT flag news reporting about violence', () => {
      const flags = scanToxicity('The police reported that the suspect was apprehended after a shooting in the downtown area. No casualties were reported.');
      assert.equal(flags.length, 0);
    });

    it('should NOT flag normal conversation', () => {
      const flags = scanToxicity("That's a great idea! Let me know if you need help with anything else.");
      assert.equal(flags.length, 0);
    });
  });
});
