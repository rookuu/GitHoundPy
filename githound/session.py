"""
GitHub API session handling for GitHound.
"""

import requests
import time
import logging
import jwt
import threading

from typing import Dict, List

logger = logging.getLogger(__name__)

class GitHubSession:
    """Handles GitHub API authentication and requests"""

    default_headers: Dict[str, str] = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'GitHoundPy/1.0'
    }
    
    def __init__(self, token: str = None, app_id: str = None, installation_id: str = None, jwk: str = None, api_uri: str = "https://api.github.com"):
        self.api_uri = api_uri.rstrip('/')
        self.headers = self.default_headers.copy()

        self.session = requests.Session()
        self.session.headers.update(self.headers)

        # Thread lock for token refresh
        self._token_refresh_lock = threading.Lock()
        self._last_token_refresh = 0

        if token:
            # Token-based authentication
            self.update_token(token)
        elif app_id and installation_id and jwk:
            # App-based authentication
            self.app_id = app_id
            self.installation_id = installation_id
            self.jwk = jwk
            self.refresh_app_token()
        else:
            raise ValueError("Must provide either token or app credentials (app_id, installation_id, jwk)")
    
    def refresh_app_token(self):
        """Refresh the GitHub App token if needed"""
        if hasattr(self, 'app_id'):
             # Use lock to ensure only one thread refreshes at a time
            with self._token_refresh_lock:
                # Check if another thread already refreshed recently (within last 10 seconds)
                current_time = time.time()
                if current_time - self._last_token_refresh < 10:
                    return
                
                logger.info("Refreshing GitHub App token")
                new_token = self.get_token_from_app_credentials(self.app_id, self.installation_id, self.jwk)
                self.update_token(new_token)
                self._last_token_refresh = current_time

    def update_token(self, token: str):
        """Update the authentication token"""
        self.headers['Authorization'] = f'Bearer {token}'
        self.session.headers.update(self.headers)

    def get_token_from_app_credentials(self, app_id: str, installation_id: str, jwk: str):
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 600,  # Token valid for 10 minutes
            'iss': app_id
        }

        jwt_instance = jwt.JWT()
        encoded_jwt = jwt_instance.encode(payload, jwk, alg='RS256')

        headers = self.default_headers.copy()
        headers['Authorization'] = f'Bearer {encoded_jwt}'
        
        response = self.session.post(f"{self.api_uri}/app/installations/{installation_id}/access_tokens", headers=headers)
        
        if response.status_code != 201:
            raise Exception(f"Failed to get access token: {response.status_code} {response.text}")
        
        token_data = response.json()
        return token_data['token']

    def make_request(self, path: str, params: Dict = None) -> List[Dict]:
        """Make paginated GitHub API request"""
        url = f"{self.api_uri}/{path.lstrip('/')}"
        all_data = []
        
        while url:
            try:
                response = self.session.get(url, params=params if not all_data else None)
                
                # Handle token expiration for GitHub Apps
                if response.status_code == 401 and hasattr(self, 'app_id'):
                    logger.warning("Token expired, refreshing GitHub App token")
                    self.refresh_app_token()
                    # Retry the request with new token
                    response = self.session.get(url, params=params if not all_data else None)
                
                response.raise_for_status()
                
                data = response.json()
                if isinstance(data, list):
                    all_data.extend(data)
                else:
                    all_data.append(data)
                
                # Handle pagination
                url = None
                if 'Link' in response.headers:
                    links = response.headers['Link'].split(',')
                    for link in links:
                        if 'rel="next"' in link:
                            url = link.split(';')[0].strip('<> ')
                            break
                
                # Rate limiting
                if 'X-RateLimit-Remaining' in response.headers:
                    remaining = int(response.headers['X-RateLimit-Remaining'])
                    if remaining < 100:
                        reset_time = int(response.headers['X-RateLimit-Reset'])
                        sleep_time = max(0, reset_time - int(time.time()) + 10)
                        logger.warning(f"Rate limit low ({remaining}), sleeping {sleep_time}s")
                        time.sleep(sleep_time)
                        
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed for {url}: {e}")
                raise e
                
        return all_data
    
    def graphql_request(self, query: str, variables: Dict = None) -> Dict:
        """Make GraphQL request"""
        url = f"{self.api_uri}/graphql"
        payload = {
            'query': query,
            'variables': variables or {}
        }
        
        response = self.session.post(url, json=payload)
        
        # Handle token expiration for GitHub Apps
        if response.status_code == 401 and hasattr(self, 'app_id'):
            logger.warning("Token expired, refreshing GitHub App token")
            self.refresh_app_token()
            # Retry the request with new token
            response = self.session.post(url, json=payload)
        
        response.raise_for_status()
        return response.json()

