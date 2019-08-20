'use strict';

/**
 * @module vpsaudit
 * @description Audit VPS/server security configuration.
 * @author idirdev
 */

const fs = require('fs');
const { execSync } = require('child_process');

/**
 * Execute a shell command and return stdout, or null on failure.
 * @param {string} cmd
 * @returns {string|null}
 */
function exec(cmd) {
  try {
    return execSync(cmd, { stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 }).toString().trim();
  } catch {
    return null;
  }
}

/**
 * Check SSH daemon configuration for security settings.
 * @returns {object} Check result
 */
function checkSSH() {
  const name = 'SSH Configuration';
  const severity = 'high';
  const sshdConfig = '/etc/ssh/sshd_config';

  if (!fs.existsSync(sshdConfig)) {
    return {
      name, severity, status: 'warn',
      message: 'sshd_config not found (non-Linux or SSH not installed)',
      details: {}
    };
  }

  let content;
  try {
    content = fs.readFileSync(sshdConfig, 'utf8');
  } catch {
    return { name, severity, status: 'warn', message: 'Cannot read sshd_config (permission denied)', details: {} };
  }

  const get = (key) => {
    const m = content.match(new RegExp(`^\\s*${key}\\s+(\\S+)`, 'mi'));
    return m ? m[1] : null;
  };

  const details = {
    PermitRootLogin: get('PermitRootLogin') || 'not set (default: yes)',
    PasswordAuthentication: get('PasswordAuthentication') || 'not set (default: yes)',
    Port: get('Port') || '22 (default)',
    Protocol: get('Protocol') || 'not set'
  };

  const issues = [];
  const rootLogin = (get('PermitRootLogin') || '').toLowerCase();
  if (!rootLogin || rootLogin === 'yes') issues.push('PermitRootLogin is enabled');

  const passAuth = (get('PasswordAuthentication') || '').toLowerCase();
  if (!passAuth || passAuth === 'yes') issues.push('PasswordAuthentication is enabled');

  const port = get('Port');
  if (!port || port === '22') issues.push('SSH running on default port 22');

  const status = issues.length === 0 ? 'pass' : issues.length <= 1 ? 'warn' : 'fail';
  const message = issues.length === 0
    ? 'SSH configuration looks secure'
    : 'SSH issues: ' + issues.join('; ');

  return { name, severity, status, message, details };
}

/**
 * Check firewall status via ufw or iptables.
 * @returns {object} Check result
 */
function checkFirewall() {
  const name = 'Firewall Status';
  const severity = 'high';

  const ufw = exec('ufw status 2>/dev/null');
  if (ufw !== null) {
    const active = ufw.toLowerCase().includes('active');
    return {
      name, severity,
      status: active ? 'pass' : 'fail',
      message: active ? 'UFW firewall is active' : 'UFW firewall is inactive',
      details: { tool: 'ufw', output: ufw.split('\n').slice(0, 3).join(' | ') }
    };
  }

  const ipt = exec('iptables -L INPUT --line-numbers 2>/dev/null | head -20');
  if (ipt !== null) {
    const hasRules = ipt.split('\n').filter(l => /^[0-9]/.test(l)).length > 0;
    return {
      name, severity,
      status: hasRules ? 'pass' : 'warn',
      message: hasRules ? 'iptables has INPUT rules configured' : 'iptables has no INPUT rules',
      details: { tool: 'iptables', rules: ipt.split('\n').length }
    };
  }

  return {
    name, severity, status: 'warn',
    message: 'No firewall tool found (ufw/iptables unavailable)',
    details: {}
  };
}

/**
 * Check for pending system updates.
 * @returns {object} Check result
 */
function checkUpdates() {
  const name = 'Pending Updates';
  const severity = 'medium';

  const apt = exec('apt list --upgradable 2>/dev/null | grep -c upgradable');
  if (apt !== null) {
    const count = parseInt(apt, 10) || 0;
    return {
      name, severity,
      status: count === 0 ? 'pass' : count < 10 ? 'warn' : 'fail',
      message: count === 0 ? 'System is up to date' : `${count} package(s) have pending updates`,
      details: { pendingCount: count, packageManager: 'apt' }
    };
  }

  const yum = exec('yum check-update 2>/dev/null; echo $?');
  if (yum !== null) {
    const exitCode = yum.split('\n').pop().trim();
    return {
      name, severity,
      status: exitCode === '0' ? 'pass' : 'warn',
      message: exitCode === '0' ? 'System is up to date' : 'Pending yum updates found',
      details: { packageManager: 'yum' }
    };
  }

  return {
    name, severity, status: 'warn',
    message: 'Cannot determine update status (apt/yum not found)',
    details: {}
  };
}

/**
 * Check disk usage with df.
 * @returns {object} Check result
 */
function checkDisk() {
  const name = 'Disk Usage';
  const severity = 'medium';

  const df = exec('df -h --output=target,pcent 2>/dev/null || df -h 2>/dev/null');
  if (df === null) {
    return { name, severity, status: 'warn', message: 'df command unavailable', details: {} };
  }

  const lines = df.split('\n').slice(1).filter(Boolean);
  const mounts = [];
  let maxUsage = 0;

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2) {
      const pctStr = parts.find(p => p.endsWith('%'));
      if (pctStr) {
        const pct = parseInt(pctStr, 10);
        const mount = parts[0];
        mounts.push({ mount, usage: pct });
        if (!isNaN(pct) && pct > maxUsage) maxUsage = pct;
      }
    }
  }

  const status = maxUsage >= 90 ? 'fail' : maxUsage >= 75 ? 'warn' : 'pass';
  const message = maxUsage >= 90
    ? `Critical: disk usage at ${maxUsage}%`
    : maxUsage >= 75
      ? `Warning: disk usage at ${maxUsage}%`
      : `Disk usage is healthy (max ${maxUsage}%)`;

  return { name, severity, status, message, details: { mounts, maxUsage } };
}

/**
 * Check open ports via ss or netstat.
 * @returns {object} Check result
 */
function checkOpenPorts() {
  const name = 'Open Ports';
  const severity = 'medium';

  const ss = exec('ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null');
  if (ss === null) {
    return { name, severity, status: 'warn', message: 'ss/netstat not available', details: {} };
  }

  const lines = ss.split('\n').slice(1).filter(Boolean);
  const ports = [];
  for (const line of lines) {
    const m = line.match(/[:\s](\d{1,5})\s/g);
    if (m) {
      const p = parseInt(m[m.length - 1].trim().replace(':', ''), 10);
      if (p > 0 && p <= 65535 && !ports.includes(p)) ports.push(p);
    }
  }

  const riskyPorts = [21, 23, 25, 110, 143, 3306, 5432, 6379, 27017];
  const exposed = ports.filter(p => riskyPorts.includes(p));

  return {
    name, severity,
    status: exposed.length === 0 ? 'pass' : 'warn',
    message: exposed.length === 0
      ? `${ports.length} port(s) open, no high-risk ports detected`
      : `High-risk port(s) open: ${exposed.join(', ')}`,
    details: { openPorts: ports.sort((a, b) => a - b), riskyExposed: exposed }
  };
}

/**
 * Check for passwordless accounts in /etc/shadow.
 * @returns {object} Check result
 */
function checkUsers() {
  const name = 'Passwordless Accounts';
  const severity = 'high';
  const shadow = '/etc/shadow';

  if (!fs.existsSync(shadow)) {
    return { name, severity, status: 'warn', message: '/etc/shadow not found (non-Linux)', details: {} };
  }

  let content;
  try {
    content = fs.readFileSync(shadow, 'utf8');
  } catch {
    return { name, severity, status: 'warn', message: 'Cannot read /etc/shadow (permission denied)', details: {} };
  }

  const passwordless = [];
  for (const line of content.split('\n').filter(Boolean)) {
    const [user, hash] = line.split(':');
    if (hash === '' || hash === '::') passwordless.push(user);
  }

  return {
    name, severity,
    status: passwordless.length === 0 ? 'pass' : 'fail',
    message: passwordless.length === 0
      ? 'No passwordless accounts found'
      : `Passwordless accounts: ${passwordless.join(', ')}`,
    details: { passwordlessAccounts: passwordless }
  };
}

/**
 * Check permissions on sensitive files.
 * @returns {object} Check result
 */
function checkPermissions() {
  const name = 'Sensitive File Permissions';
  const severity = 'high';

  const targets = [
    { file: '/etc/passwd', maxMode: 0o644 },
    { file: '/etc/shadow', maxMode: 0o640 },
    { file: '/etc/sudoers', maxMode: 0o440 },
    { file: '/etc/ssh/sshd_config', maxMode: 0o644 }
  ];

  const issues = [];
  const checked = [];

  for (const { file, maxMode } of targets) {
    if (!fs.existsSync(file)) continue;
    try {
      const stat = fs.statSync(file);
      const mode = stat.mode & 0o777;
      const worldWritable = (mode & 0o002) !== 0;
      checked.push({ file, mode: mode.toString(8).padStart(4, '0') });
      if (worldWritable || mode > maxMode) {
        issues.push(`${file} has loose permissions (${mode.toString(8)})`);
      }
    } catch {
      // skip unreadable
    }
  }

  if (checked.length === 0) {
    return { name, severity, status: 'warn', message: 'No sensitive files found to check', details: {} };
  }

  return {
    name, severity,
    status: issues.length === 0 ? 'pass' : 'fail',
    message: issues.length === 0 ? 'Sensitive file permissions are correct' : issues.join('; '),
    details: { checked, issues }
  };
}

/** @type {Array<{name: string, fn: Function, severity: string}>} */
const CHECKS = [
  { name: 'ssh', fn: checkSSH, severity: 'high' },
  { name: 'firewall', fn: checkFirewall, severity: 'high' },
  { name: 'updates', fn: checkUpdates, severity: 'medium' },
  { name: 'disk', fn: checkDisk, severity: 'medium' },
  { name: 'ports', fn: checkOpenPorts, severity: 'medium' },
  { name: 'users', fn: checkUsers, severity: 'high' },
  { name: 'permissions', fn: checkPermissions, severity: 'high' }
];

/**
 * Grade the server based on check results.
 * @param {object[]} results
 * @returns {string} Grade A-F
 */
function gradeServer(results) {
  const total = results.length;
  if (total === 0) return 'N/A';
  const passes = results.filter(r => r.status === 'pass').length;
  const fails = results.filter(r => r.status === 'fail').length;
  const highFails = results.filter(r => r.status === 'fail' && r.severity === 'high').length;
  if (highFails >= 2) return 'F';
  const score = passes / total;
  if (score >= 0.9 && fails === 0) return 'A';
  if (score >= 0.75) return 'B';
  if (score >= 0.6) return 'C';
  if (score >= 0.4) return 'D';
  return 'F';
}

/**
 * Format a human-readable report from results.
 * @param {object[]} results
 * @returns {string}
 */
function formatReport(results) {
  const grade = gradeServer(results);
  const lines = [
    '='.repeat(50),
    '  VPS Security Audit Report',
    '='.repeat(50),
    `  Grade: ${grade}`,
    ''
  ];
  for (const r of results) {
    const icon = r.status === 'pass' ? '[PASS]' : r.status === 'warn' ? '[WARN]' : '[FAIL]';
    lines.push(`${icon} [${r.severity.toUpperCase()}] ${r.name}`);
    lines.push(`       ${r.message}`);
  }
  lines.push('');
  lines.push(summary(results));
  return lines.join('\n');
}

/**
 * Return a one-line summary of audit results.
 * @param {object[]} results
 * @returns {string}
 */
function summary(results) {
  const pass = results.filter(r => r.status === 'pass').length;
  const warn = results.filter(r => r.status === 'warn').length;
  const fail = results.filter(r => r.status === 'fail').length;
  return `Summary: ${pass} passed, ${warn} warnings, ${fail} failed — Grade: ${gradeServer(results)}`;
}

/**
 * Run all (or selected) security checks and return a combined report.
 * @param {object} [opts]
 * @param {string[]} [opts.checks] - Check names to run (default: all)
 * @param {boolean} [opts.verbose] - Include full details
 * @returns {object} Audit report
 */
function runAudit(opts = {}) {
  const { checks: selected, verbose = false } = opts;
  const toRun = selected && selected.length
    ? CHECKS.filter(c => selected.includes(c.name))
    : CHECKS;

  const results = toRun.map(({ fn }) => fn());

  if (!verbose) {
    results.forEach(r => delete r.details);
  }

  return {
    grade: gradeServer(results),
    summary: summary(results),
    results,
    report: formatReport(results)
  };
}

module.exports = { runAudit, checkSSH, checkFirewall, checkUpdates, checkDisk, checkOpenPorts, checkUsers, checkPermissions, gradeServer, formatReport, summary, CHECKS };
