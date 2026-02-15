# Social Media Leak Monitor

A CLI tool that monitors social media platforms for leaked credentials from your domains.

## Installation

```bash
cd social-media-leak-monitor
npm install
```

## Usage

```bash
# Single scan
node src/index.js -d example.com -o

# Continuous monitoring
node src/index.js -d example.com,yourcompany.com
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--domains` | `-d` | Comma-separated list of domains |
| `--once` | `-o` | Run once and exit |
| `--interval` | `-i` | Check interval in minutes |
| `--verbose` | `-v` | Verbose output |

## Features

- Monitors Reddit for mentions
- Monitors Twitter/X via Nitter
- Detects multiple credential types

## License

MIT
