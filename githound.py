import argparse
import logging
import os
import jwt

from datetime import datetime

from githound.ingestor import GitHoundIngestor
from githound.session import GitHubSession

def main():
    parser = argparse.ArgumentParser(
        description="GitHoundPy - GitHub OpenGraph Collector",
        epilog="""
Environment Variables for Credentials:
  GITHOUND_TOKEN              GitHub personal access token
  GITHOUND_APP_CERTIFICATE    GitHub App private key (PEM format)
        """
    )
    parser.add_argument('--org', required=True, help='GitHub organization name')
    parser.add_argument('--api-url', default='https://api.github.com', help='GitHub API base URL')
    parser.add_argument('--app-id', help='GitHub App ID')
    parser.add_argument('--app-installation-id', help='GitHub App Installation ID')
    parser.add_argument('--app-cert-path', help='Path to GitHub App private key (PEM) or PEM string')
    parser.add_argument(
        '--output',
        default=f"githound_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        help='Output file for the graph data'
    )
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of worker threads for parallel processing (default: 10)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    token = os.environ.get('GITHOUND_TOKEN')
    certificate_data = os.environ.get('GITHOUND_APP_CERTIFICATE')

    # Must have a valid credential method
    if token:
        session = GitHubSession(token=token, api_uri=args.api_url)
    elif args.app_id and args.app_installation_id and (certificate_data or args.app_cert_path):
        if args.app_cert_path:
            try:
                with open(args.app_cert_path, 'r') as cert_file:
                    certificate_data = cert_file.read()
            except Exception as e:
                parser.error(f"Failed to read GitHub App certificate from {args.app_cert_path}: {e}")

        if not certificate_data:
            parser.error("You must provide a valid GitHub App certificate via --app-cert-path or GITHOUND_APP_CERTIFICATE environment variable")

        try:
            app_jwk = jwt.jwk_from_pem(certificate_data.encode('utf-8'))
        except Exception as e:
            parser.error(f"Invalid GitHub App certificate: {e}")

        session = GitHubSession(app_id=args.app_id, installation_id=args.app_installation_id, jwk=app_jwk, api_uri=args.api_url)
    else:
        parser.error("You must provide either a GITHOUND_TOKEN or --app-id, --app-installation-id, and a GitHub App certificate via --app-cert-path or GITHOUND_APP_CERTIFICATE environment variable")

    githound = GitHoundIngestor(
        organization_name=args.org,
        session=session,
        max_workers=args.max_workers
    )

    githound.run()
    githound.save_graph(args.output)

if __name__ == "__main__":
    main()

