import { describe, it, expect } from 'vitest';
import { redactPII, rehydratePII, getRedactionSummary } from './piiRedactor.js';

describe('redactPII', () => {
  it('should return unchanged text when no PII is found', () => {
    const result = redactPII('Hello, this is a normal message.');
    expect(result.piiDetected).toBe(false);
    expect(result.redactedText).toBe('Hello, this is a normal message.');
    expect(result.redactionCount).toBe(0);
    expect(result.redactions).toHaveLength(0);
  });

  it('should redact a single email address', () => {
    const result = redactPII('Contact john@acme.com for details.');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Contact [EMAIL_1] for details.');
    expect(result.redactionCount).toBe(1);
    expect(result.redactions[0].token).toBe('[EMAIL_1]');
    expect(result.redactions[0].original).toBe('john@acme.com');
    expect(result.redactions[0].type).toBe('email');
  });

  it('should redact multiple emails with unique tokens', () => {
    const result = redactPII('Email john@acme.com and jane@acme.com about the meeting.');
    expect(result.redactedText).toBe('Email [EMAIL_1] and [EMAIL_2] about the meeting.');
    expect(result.redactionCount).toBe(2);
    expect(result.redactions[0].token).toBe('[EMAIL_1]');
    expect(result.redactions[1].token).toBe('[EMAIL_2]');
  });

  it('should redact phone numbers', () => {
    const result = redactPII('Call me at 555-123-4567.');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Call me at [PHONE_1].');
    expect(result.redactions[0].type).toBe('phone');
  });

  it('should redact SSN', () => {
    const result = redactPII('My SSN is 123-45-6789.');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('My SSN is [SSN_1].');
    expect(result.redactions[0].type).toBe('ssn');
  });

  it('should redact credit card numbers', () => {
    const result = redactPII('Card number: 4111111111111111');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Card number: [CARD_1]');
    expect(result.redactions[0].type).toBe('credit_card');
  });

  it('should redact AWS keys', () => {
    const result = redactPII('Key: AKIAIOSFODNN7EXAMPLE');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Key: [AWSKEY_1]');
    expect(result.redactions[0].type).toBe('aws_key');
  });

  it('should redact IP addresses', () => {
    const result = redactPII('Server at 192.168.1.100');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Server at [IP_1]');
    expect(result.redactions[0].type).toBe('ip_address');
  });

  it('should redact multiple PII types in one text', () => {
    const result = redactPII(
      'Send to john@acme.com at 555-123-4567. SSN: 123-45-6789'
    );
    expect(result.piiDetected).toBe(true);
    expect(result.redactionCount).toBe(3);
    // Should contain EMAIL, PHONE, SSN tokens
    const types = result.redactions.map(r => r.type);
    expect(types).toContain('email');
    expect(types).toContain('phone');
    expect(types).toContain('ssn');
  });

  it('should handle private key markers', () => {
    const result = redactPII('-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK...');
    expect(result.piiDetected).toBe(true);
    expect(result.redactions[0].type).toBe('private_key');
  });

  it('should redact DOB patterns', () => {
    const result = redactPII('DOB: 01/15/1990');
    expect(result.piiDetected).toBe(true);
    expect(result.redactions[0].type).toBe('dob');
  });

  it('should redact street addresses', () => {
    const result = redactPII('Lives at 123 Main Street');
    expect(result.piiDetected).toBe(true);
    expect(result.redactions[0].type).toBe('address');
  });
});

describe('rehydratePII', () => {
  it('should replace tokens with original values', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 8 },
    ];
    const result = rehydratePII('Contact [EMAIL_1] for details.', redactions);
    expect(result).toBe('Contact john@acme.com for details.');
  });

  it('should handle multiple tokens', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 0 },
      { token: '[EMAIL_2]', original: 'jane@acme.com', type: 'email', position: 20 },
    ];
    const result = rehydratePII(
      'Email [EMAIL_1] and [EMAIL_2] about the meeting.',
      redactions
    );
    expect(result).toBe('Email john@acme.com and jane@acme.com about the meeting.');
  });

  it('should handle repeated tokens from LLM output', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 0 },
    ];
    const result = rehydratePII(
      'I sent to [EMAIL_1]. Confirming [EMAIL_1] received it.',
      redactions
    );
    expect(result).toBe('I sent to john@acme.com. Confirming john@acme.com received it.');
  });

  it('should return text unchanged if no redactions', () => {
    const result = rehydratePII('No PII here.', []);
    expect(result).toBe('No PII here.');
  });

  it('should roundtrip: redact then rehydrate', () => {
    const original = 'Email john@acme.com and call 555-123-4567.';
    const redacted = redactPII(original);
    const restored = rehydratePII(redacted.redactedText, redacted.redactions);
    expect(restored).toBe(original);
  });
});

describe('getRedactionSummary', () => {
  it('should count PII types', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'a@b.com', type: 'email', position: 0 },
      { token: '[EMAIL_2]', original: 'c@d.com', type: 'email', position: 10 },
      { token: '[PHONE_1]', original: '555-1234', type: 'phone', position: 20 },
    ];
    const summary = getRedactionSummary(redactions);
    expect(summary).toEqual({ email: 2, phone: 1 });
  });

  it('should return empty object for no redactions', () => {
    expect(getRedactionSummary([])).toEqual({});
  });
});
