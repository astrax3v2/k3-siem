'use strict';
const { extractCondition } = require('../../src/services/correlationEngine');

describe('correlationEngine.extractCondition', () => {
  test('extracts event_id from EventID==XXXX logic text', () => {
    expect(extractCondition({ logic: 'EventID==4625 count>=10 within window' })).toEqual({ field: 'event_id', value: '4625' });
  });

  test('extracts event_id for Kerberoasting EncryptionType pattern', () => {
    expect(extractCondition({ logic: 'EventID==4769 EncryptionType==0x17 count>5 same_user' })).toEqual({ field: 'event_id', value: '4769' });
  });

  test('extracts action from CmdLine has pattern', () => {
    expect(extractCondition({ logic: 'CmdLine has bypass -> ProcessInjection' })).toEqual({ field: 'action', like: 'bypass' });
  });

  test('prefers structured conditions field when present', () => {
    expect(extractCondition({ logic: 'irrelevant text', conditions: JSON.stringify({ field: 'event_id', value: '9999' }) }))
      .toEqual({ field: 'event_id', value: '9999' });
  });

  test('returns null when nothing recognizable', () => {
    expect(extractCondition({ logic: 'some totally custom rule with no pattern' })).toBeNull();
  });
});
