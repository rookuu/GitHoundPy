# GitHoundPy

A Python implementation of the GitHound collector for BloodHound OpenGraph. 

Credit to the SpecterOps team for the original implementation: [https://github.com/SpecterOps/GitHound/tree/main](https://github.com/SpecterOps/GitHound/tree/main)

## Usage

```
usage: githound.py [-h] --org ORG [--api-url API_URL] [--app-id APP_ID]
                   [--app-installation-id APP_INSTALLATION_ID]
                   [--app-cert-path APP_CERT_PATH] [--output OUTPUT]
                   [--max-workers MAX_WORKERS] [--verbose]

GitHoundPy - GitHub OpenGraph Collector

options:
  -h, --help            show this help message and exit
  --org ORG             GitHub organization name
  --api-url API_URL     GitHub API base URL (default: https://api.github.com)
  --app-id APP_ID       GitHub App ID
  --app-installation-id APP_INSTALLATION_ID
                        GitHub App Installation ID
  --app-cert-path APP_CERT_PATH
                        Path to GitHub App private key (PEM) or PEM string
  --output OUTPUT       Output file for the graph data (default: githound.json)
  --max-workers MAX_WORKERS
                        Maximum number of worker threads for parallel processing
                        (default: 10)
  --verbose             Enable verbose logging

Environment Variables for Credentials:
  GITHOUND_TOKEN              GitHub personal access token
  GITHOUND_APP_CERTIFICATE    GitHub App private key (PEM format)
```

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set up authentication (choose one):
   - **Personal Access Token**: Set the `GITHOUND_TOKEN` environment variable
   - **GitHub App**: Use `--app-id`, `--app-installation-id`, and either `--app-cert-path` or set `GITHOUND_APP_CERTIFICATE`

3. Run the ingestor:
   ```bash
   # Using personal access token
   export GITHOUND_TOKEN=your_token_here
   python githound.py --org <org_name> [--output <file>] [--verbose]
   
   # Using GitHub App
   python githound.py --org <org_name> --app-id <app_id> --app-installation-id <install_id> --app-cert-path <cert_path>
   ```

## Output

The tool outputs a JSON file compatible with BloodHound's OpenGraph format, ready for import and analysis.

## License

MIT License. See LICENSE file for details.