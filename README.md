# vpsaudit

> **[EN]** A CLI security audit tool for Linux VPS servers — checks SSH configuration, firewall status, pending system updates, and disk usage in one command.
> **[FR]** Un outil d'audit de sécurité CLI pour les serveurs VPS Linux — vérifie la configuration SSH, l'état du pare-feu, les mises à jour système en attente et l'utilisation disque en une seule commande.

---

## Features / Fonctionnalités

**[EN]**
- SSH security checks: root login, password authentication, default port 22
- Firewall detection: UFW active status or iptables rules
- System update check: counts upgradable packages via apt
- Disk usage check with warning at 75% and failure at 90%
- System info display: hostname, platform, CPU count, RAM, uptime
- JSON output mode for integration with monitoring systems
- Exit code 1 when critical failures are detected

**[FR]**
- Vérifications SSH : connexion root, authentification par mot de passe, port par défaut 22
- Détection du pare-feu : statut UFW actif ou règles iptables
- Vérification des mises à jour système : compte les paquets à mettre à jour via apt
- Vérification de l'utilisation disque avec avertissement à 75% et échec à 90%
- Affichage des informations système : hostname, plateforme, CPU, RAM, uptime
- Mode de sortie JSON pour l'intégration avec les systèmes de surveillance
- Code de sortie 1 en cas d'échec critique

---

## Installation

```bash
npm install -g @idirdev/vpsaudit
```

---

## CLI Usage / Utilisation CLI

```bash
# Run full audit with human-readable output
# Lancer l'audit complet avec sortie lisible
vpsaudit

# Output results as JSON
# Sortir les résultats en JSON
vpsaudit --json

# Show help / Afficher l'aide
vpsaudit --help
```

### Example Output / Exemple de sortie

```
$ vpsaudit
System: vps-prod-01 (linux x64)
Memory: 1.24GB/3.84GB free
Uptime: 312h

[OK] SSH configuration OK
[!!] Password auth enabled
[!!] SSH on default port 22
[OK] UFW active
[OK] System up to date (2 pending)
[OK] Disk usage: 61%

$ vpsaudit --json
{
  "system": {
    "hostname": "vps-prod-01",
    "platform": "linux",
    "arch": "x64",
    "uptime": "312h",
    "cpus": 2,
    "totalMem": "3.84GB",
    "freeMem": "1.24GB"
  },
  "audit": [
    { "check": "ssh", "status": "pass", "msg": "SSH configuration OK" },
    { "check": "firewall", "status": "pass", "msg": "UFW active" },
    { "check": "updates", "status": "pass", "msg": "System up to date (2 pending)" },
    { "check": "disk", "status": "pass", "msg": "Disk usage: 61%" }
  ]
}
```

---

## API (Programmatic) / API (Programmation)

**[EN]** Use vpsaudit as a library to integrate server health checks into your automation scripts.
**[FR]** Utilisez vpsaudit comme bibliothèque pour intégrer les vérifications de santé serveur dans vos scripts d'automatisation.

```javascript
const {
  getSystemInfo,
  checkSSH,
  checkFirewall,
  checkUpdates,
  checkDisk,
  runAudit,
} = require('@idirdev/vpsaudit');

// Get system information
// Obtenir les informations système
const info = getSystemInfo();
console.log(info);
// { hostname: 'vps-prod-01', platform: 'linux', arch: 'x64',
//   release: '6.8.0', uptime: '312h', cpus: 2,
//   totalMem: '3.84GB', freeMem: '1.24GB' }

// Individual checks — each returns an array of result objects
// Vérifications individuelles — chacune retourne un tableau d'objets résultat
const sshResults  = checkSSH();
const fwResults   = checkFirewall();
const updResults  = checkUpdates();
const diskResults = checkDisk();

// Run all checks at once
// Lancer toutes les vérifications en même temps
const results = runAudit();
results.forEach(r => {
  const icon = r.status === 'pass' ? '[OK]' : r.status === 'warn' ? '[!!]' : '[XX]';
  console.log(`${icon} ${r.msg}`);
});
// Each result: { check: string, status: 'pass'|'warn'|'fail'|'skip', msg: string }

const hasFail = results.some(r => r.status === 'fail');
if (hasFail) process.exit(1);
```

### API Reference

| Function | Parameters | Returns |
|----------|-----------|---------|
| `getSystemInfo()` | — | `{hostname, platform, arch, release, uptime, cpus, totalMem, freeMem}` |
| `checkSSH()` | — | `Array<{check, status, msg}>` |
| `checkFirewall()` | — | `Array<{check, status, msg}>` |
| `checkUpdates()` | — | `Array<{check, status, msg}>` |
| `checkDisk()` | — | `Array<{check, status, msg}>` |
| `runAudit()` | — | `Array<{check, status, msg}>` |

---

## License

MIT - idirdev
