# V3RM1N

<img src="media/logo.png" width=300/>

Firmware security scanner

## Usage

```
v3rm1n [--database <path>] <firmware>
```

The default database directory is `database`. `cves.json` contains version and
component rules, while `unsafe-apis.txt` contains one case-sensitive C symbol per
line. Use `--database` to load a different directory.
