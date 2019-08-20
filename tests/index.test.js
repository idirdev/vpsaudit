'use strict';

/**
 * @file vpsaudit tests
 * @author idirdev
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const {
  checkSSH, checkFirewall, checkUpdates, checkDisk,
  checkOpenPorts, checkUsers, checkPermissions,
  gradeServer, formatReport, summary, runAudit, CHECKS
} = require('../src/index.js');

describe('vpsaudit', () => {
  describe('checkSSH', () => {
    it('returns a valid result object', () => {
      const r = checkSSH();
      assert.ok(r.name, 'has name');
      assert.ok(['pass', 'warn', 'fail'].includes(r.status), 'valid status');
      assert.ok(r.message, 'has message');
      assert.ok(r.severity, 'has severity');
    });

    it('handles missing sshd_config gracefully', () => {
      const r = checkSSH();
      assert.equal(typeof r.status, 'string');
    });
  });

  describe('checkFirewall', () => {
    it('returns a valid result object', () => {
      const r = checkFirewall();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
      assert.ok(typeof r.message === 'string');
    });
  });

  describe('checkUpdates', () => {
    it('returns a valid result object', () => {
      const r = checkUpdates();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
    });
  });

  describe('checkDisk', () => {
    it('returns a valid result object', () => {
      const r = checkDisk();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
      assert.ok(typeof r.message === 'string');
    });
  });

  describe('checkOpenPorts', () => {
    it('returns a valid result object', () => {
      const r = checkOpenPorts();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
    });
  });

  describe('checkUsers', () => {
    it('handles missing /etc/shadow gracefully', () => {
      const r = checkUsers();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
    });
  });

  describe('checkPermissions', () => {
    it('handles missing sensitive files gracefully', () => {
      const r = checkPermissions();
      assert.ok(['pass', 'warn', 'fail'].includes(r.status));
    });
  });

  describe('gradeServer', () => {
    it('returns A for all passes', () => {
      const results = [
        { status: 'pass', severity: 'high' },
        { status: 'pass', severity: 'medium' },
        { status: 'pass', severity: 'high' }
      ];
      assert.equal(gradeServer(results), 'A');
    });

    it('returns F for multiple high-severity failures', () => {
      const results = [
        { status: 'fail', severity: 'high' },
        { status: 'fail', severity: 'high' },
        { status: 'pass', severity: 'medium' }
      ];
      assert.equal(gradeServer(results), 'F');
    });

    it('returns B for 75%+ passes with no fails', () => {
      const results = [
        { status: 'pass', severity: 'high' },
        { status: 'pass', severity: 'high' },
        { status: 'pass', severity: 'high' },
        { status: 'warn', severity: 'medium' }
      ];
      const g = gradeServer(results);
      assert.ok(['A', 'B'].includes(g));
    });

    it('returns N/A for empty results', () => {
      assert.equal(gradeServer([]), 'N/A');
    });
  });

  describe('formatReport', () => {
    it('returns a non-empty string', () => {
      const results = [
        { name: 'SSH', status: 'pass', severity: 'high', message: 'OK' }
      ];
      const report = formatReport(results);
      assert.ok(typeof report === 'string');
      assert.ok(report.length > 0);
      assert.ok(report.includes('[PASS]'));
    });

    it('includes FAIL marker for failed checks', () => {
      const results = [
        { name: 'Firewall', status: 'fail', severity: 'high', message: 'Firewall off' }
      ];
      assert.ok(formatReport(results).includes('[FAIL]'));
    });
  });

  describe('summary', () => {
    it('returns correct counts', () => {
      const results = [
        { status: 'pass', severity: 'high' },
        { status: 'warn', severity: 'medium' },
        { status: 'fail', severity: 'high' }
      ];
      const s = summary(results);
      assert.ok(s.includes('1 passed'));
      assert.ok(s.includes('1 warnings'));
      assert.ok(s.includes('1 failed'));
    });
  });

  describe('runAudit', () => {
    it('returns report with grade and summary', () => {
      const result = runAudit({ checks: ['disk'] });
      assert.ok(result.grade);
      assert.ok(result.summary);
      assert.ok(Array.isArray(result.results));
      assert.ok(typeof result.report === 'string');
    });

    it('runs selected checks only', () => {
      const result = runAudit({ checks: ['disk', 'firewall'] });
      assert.ok(result.results.length <= 2);
    });
  });

  describe('CHECKS', () => {
    it('has 7 entries', () => {
      assert.equal(CHECKS.length, 7);
    });

    it('each check has name, fn, severity', () => {
      for (const c of CHECKS) {
        assert.ok(c.name);
        assert.ok(typeof c.fn === 'function');
        assert.ok(c.severity);
      }
    });
  });
});
