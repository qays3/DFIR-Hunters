# Linux SysAdmin Toolkit

A comprehensive collection of bash scripts for Linux system administrators to monitor, maintain, and optimize server infrastructure.

## Features

- **System Health Monitoring** - Real-time system resource tracking
- **Automated Backup Solutions** - Scheduled backup automation
- **Log Management** - Log rotation and cleanup utilities
- **Performance Optimization** - System tuning scripts
- **Security Auditing** - Basic security check tools
- **Network Diagnostics** - Connection and bandwidth monitoring

## Quick Start

```bash
git clone https://github.com/qays3/linux-sysadmin-toolkit.git
cd linux-sysadmin-toolkit
chmod +x *.sh
./install.sh
```

## Scripts Included

### Core Scripts
- `install.sh` - Installation and setup script
- `health-check.sh` - System health monitoring
- `backup-manager.sh` - Automated backup management
- `log-cleaner.sh` - Log rotation and cleanup
- `network-monitor.sh` - Network diagnostics
- `security-audit.sh` - Basic security checks

### Usage Examples

**Run health check:**
```bash
./health-check.sh
```

**Setup automated backups:**
```bash
./backup-manager.sh --schedule daily
```

**Monitor network performance:**
```bash
./network-monitor.sh --interval 60
```

## Requirements

- Linux (Ubuntu/Debian/CentOS/RHEL)
- Bash 4.0+
- Root or sudo access for some features

## Installation

The `install.sh` script will:
1. Check system compatibility
2. Install required dependencies
3. Setup monitoring services
4. Configure automated tasks

## Configuration

Edit `/etc/sysadmin-toolkit/config.conf` after installation to customize:
- Backup paths
- Monitoring intervals
- Alert thresholds
- Log retention periods

## Contributing

Pull requests welcome! Please ensure all scripts are tested on multiple distributions.

## License

MIT License - See LICENSE file for details

## Author

Maintained by sysadmins, for sysadmins.

## Changelog

### v2.1.0 (2024-10-15)
- Added network monitoring enhancements
- Improved backup compression
- Fixed log rotation issues
- Performance optimizations

### v2.0.0 (2024-08-01)
- Complete rewrite for better compatibility
- Added security audit features
- Improved error handling

### v1.5.0 (2024-05-20)
- Initial public release