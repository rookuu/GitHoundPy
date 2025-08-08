import base64
import requests
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging
import argparse
import sys
import time
import json
import getpass

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class GitHoundNode:
    """Represents a node in the BloodHound graph"""
    id: str
    kinds: List[str]
    properties: Dict[str, Any]

@dataclass
class GitHoundEdge:
    """Represents an edge in the BloodHound graph"""
    kind: str
    start: Dict[str, str]
    end: Dict[str, str]
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GitHoundGraph:
    """Container for nodes and edges"""
    nodes: List[GitHoundNode] = field(default_factory=list)
    edges: List[GitHoundEdge] = field(default_factory=list)

class GitHubSession:
    """Handles GitHub API authentication and requests"""
    
    def __init__(self, organization_name: str, token: str, api_uri: str = "https://api.github.com"):
        self.organization_name = organization_name
        self.api_uri = api_uri.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'GitHound-Python/1.0'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def make_request(self, path: str, params: Dict = None) -> List[Dict]:
        """Make paginated GitHub API request"""
        url = f"{self.api_uri}/{path.lstrip('/')}"
        all_data = []
        
        while url:
            logger.debug(f"Making request to: {url}")
            
            try:
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
                break
                
        return all_data
    
    def graphql_request(self, query: str, variables: Dict = None) -> Dict:
        """Make GraphQL request"""
        url = f"{self.api_uri}/graphql"
        payload = {
            'query': query,
            'variables': variables or {}
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

class GitHoundIngestor:
    """Main ingestor class for GitHub data"""
    
    def __init__(self, session: GitHubSession):
        self.session = session
        self.graph = GitHoundGraph()
        self.repo_lookup = {}  # Cache for repo node_id -> repo_node mapping
        
    def normalize_null(self, value: Any) -> str:
        """Convert None values to empty strings"""
        return "" if value is None else str(value)
    
    def create_node(self, id: str, kind: str, properties: Dict[str, Any]) -> GitHoundNode:
        """Create a new GitHound node"""
        return GitHoundNode(
            id=id,
            kinds=[kind, 'GHBase'],
            properties={k: self.normalize_null(v) for k, v in properties.items()}
        )
    
    def create_edge(self, kind: str, start_id: str, end_id: str, properties: Dict = None) -> GitHoundEdge:
        """Create a new GitHound edge"""
        return GitHoundEdge(
            kind=kind,
            start={'value': start_id},
            end={'value': end_id},
            properties=properties or {}
        )
    
    def get_organization(self) -> GitHoundNode:
        """Collect organization information"""
        logger.info(f"Collecting organization: {self.session.organization_name}")
        
        org_data = self.session.make_request(f"orgs/{self.session.organization_name}")[0]
        
        properties = {
            'login': org_data.get('login'),
            'id': org_data.get('id'),
            'node_id': org_data.get('node_id'),
            'name': org_data.get('name'),
            'blog': org_data.get('blog'),
            'is_verified': org_data.get('is_verified'),
            'public_repos': org_data.get('public_repos'),
            'followers': org_data.get('followers'),
            'html_url': org_data.get('html_url'),
            'created_at': org_data.get('created_at'),
            'updated_at': org_data.get('updated_at'),
            'total_private_repos': org_data.get('total_private_repos'),
            'owned_private_repos': org_data.get('owned_private_repos'),
            'collaborators': org_data.get('collaborators'),
            'default_repository_permission': org_data.get('default_repository_permission'),
            'two_factor_requirement_enabled': org_data.get('two_factor_requirement_enabled'),
            'advanced_security_enabled_for_new_repositories': org_data.get('advanced_security_enabled_for_new_repositories')
        }
        
        node = self.create_node(org_data['node_id'], 'GHOrganization', properties)
        self.graph.nodes.append(node)
        return node
    
    def get_users(self, organization: GitHoundNode) -> List[GitHoundNode]:
        """Collect organization users"""
        logger.info("Collecting users")
        
        users_data = self.session.make_request(f"orgs/{organization.properties['login']}/members")
        users = []
        
        for user_data in users_data:
            # Get detailed user info
            user_details = self.session.make_request(f"user/{user_data['id']}")[0]
            
            properties = {
                'id': user_data.get('id'),
                'node_id': user_data.get('node_id'),
                'organization_name': organization.properties['login'],
                'organization_id': organization.properties['node_id'],
                'login': user_data.get('login'),
                'name': user_data.get('login'),
                'full_name': user_details.get('name'),
                'company': user_details.get('company'),
                'email': user_details.get('email'),
                'twitter_username': user_details.get('twitter_username'),
                'type': user_data.get('type'),
                'site_admin': user_data.get('site_admin')
            }
            
            user_node = self.create_node(user_data['node_id'], 'GHUser', properties)
            users.append(user_node)
            self.graph.nodes.append(user_node)
            
            # Create GHContains edge from organization to user
            contains_edge = self.create_edge('GHContains', organization.id, user_data['node_id'])
            self.graph.edges.append(contains_edge)
        
        return users
    
    def get_teams(self, organization: GitHoundNode) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect organization teams"""
        logger.info("Collecting teams")
        
        teams_data = self.session.make_request(f"orgs/{organization.properties['login']}/teams")
        teams = []
        edges = []
        
        for team_data in teams_data:
            properties = {
                'id': team_data.get('id'),
                'node_id': team_data.get('node_id'),
                'organization_name': organization.properties['login'],
                'organization_id': organization.properties['node_id'],
                'name': team_data.get('name'),
                'slug': team_data.get('slug'),
                'description': team_data.get('description'),
                'privacy': team_data.get('privacy'),
                'permission': team_data.get('permission')
            }
            
            team_node = self.create_node(team_data['node_id'], 'GHTeam', properties)
            teams.append(team_node)
            self.graph.nodes.append(team_node)
            
            # Create GHContains edge from organization to team
            contains_edge = self.create_edge('GHContains', organization.id, team_data['node_id'])
            edges.append(contains_edge)
            
            # Handle parent team relationships
            if team_data.get('parent'):
                parent_edge = self.create_edge('GHMemberOf', team_data['node_id'], team_data['parent']['node_id'])
                edges.append(parent_edge)
        
        return teams, edges
    
    def get_repositories(self, organization: GitHoundNode) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect organization repositories"""
        logger.info("Collecting repositories")
        
        repos_data = self.session.make_request(f"orgs/{organization.properties['login']}/repos")
        repos = []
        edges = []
        
        for repo_data in repos_data:
            properties = {
                'id': repo_data.get('id'),
                'node_id': repo_data.get('node_id'),
                'organization_name': organization.properties['login'],
                'organization_id': organization.properties['node_id'],
                'name': repo_data.get('name'),
                'full_name': repo_data.get('full_name'),
                'private': repo_data.get('private'),
                'owner_id': repo_data.get('owner', {}).get('id'),
                'owner_node_id': repo_data.get('owner', {}).get('node_id'),
                'owner_name': repo_data.get('owner', {}).get('login'),
                'html_url': repo_data.get('html_url'),
                'description': repo_data.get('description'),
                'created_at': repo_data.get('created_at'),
                'updated_at': repo_data.get('updated_at'),
                'pushed_at': repo_data.get('pushed_at'),
                'archived': repo_data.get('archived'),
                'disabled': repo_data.get('disabled'),
                'open_issues_count': repo_data.get('open_issues_count'),
                'allow_forking': repo_data.get('allow_forking'),
                'web_commit_signoff_required': repo_data.get('web_commit_signoff_required'),
                'visibility': repo_data.get('visibility'),
                'forks': repo_data.get('forks'),
                'open_issues': repo_data.get('open_issues'),
                'watchers': repo_data.get('watchers'),
                'default_branch': repo_data.get('default_branch'),
                'secret_scanning': repo_data.get('security_and_analysis', {}).get('secret_scanning', {}).get('status')
            }
            
            repo_node = self.create_node(repo_data['node_id'], 'GHRepository', properties)
            repos.append(repo_node)
            self.graph.nodes.append(repo_node)
            
            # Cache repo for later lookup by full_name and node_id
            self.repo_lookup[repo_data['full_name']] = repo_node
            self.repo_lookup[repo_data['node_id']] = repo_node
            
            # Create GHContains edge from organization to repository
            contains_edge = self.create_edge('GHContains', organization.id, repo_data['node_id'])
            edges.append(contains_edge)
            
            # Create ownership edge (if owner is different from organization)
            if repo_data['owner']['node_id'] != organization.id:
                owner_edge = self.create_edge('GHOwns', repo_data['owner']['node_id'], repo_data['node_id'])
                edges.append(owner_edge)
        
        return repos, edges
    
    def get_org_secret_scanning_alerts(self) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect organization-wide secret scanning alerts"""
        logger.info("Collecting organization secret scanning alerts")
        
        findings = []
        edges = []
        
        try:
            # Use organization-level secret scanning API
            secret_alerts = self.session.make_request(
                f"orgs/{self.session.organization_name}/secret-scanning/alerts"
            )
            
            for alert in secret_alerts:
                repo_name = alert.get('repository', {}).get('full_name')
                repo_node = self.repo_lookup.get(repo_name)
                
                if not repo_node:
                    logger.debug(f"Repository {repo_name} not found in cache for secret alert {alert.get('number')}")
                    continue
                
                properties = {
                    'id': alert.get('number'),
                    'repository_name': repo_name,
                    'repository_id': repo_node.id,
                    'secret_type': alert.get('secret_type'),
                    'secret_type_display_name': alert.get('secret_type_display_name'),
                    'state': alert.get('state'),
                    'created_at': alert.get('created_at'),
                    'updated_at': alert.get('updated_at'),
                    'url': alert.get('html_url'),
                    'finding_type': 'secret_scanning'
                }
                
                finding_id = f"secret_scan_{repo_node.id}_{alert.get('number')}"
                finding_node = self.create_node(finding_id, 'GHSecretScanningAlert', properties)
                findings.append(finding_node)
                
                # Link finding to repository using GHHasSecretScanningAlert
                finding_edge = self.create_edge('GHHasSecretScanningAlert', repo_node.id, finding_id)
                edges.append(finding_edge)
                
        except Exception as e:
            logger.error(f"Failed to collect organization secret scanning alerts: {e}")
        
        return findings, edges
    
    def get_security_findings(self, repos: List[GitHoundNode]) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect GitHub Advanced Security findings using organization-level APIs"""
        logger.info("Collecting security findings using organization-level APIs")
        
        all_findings = []
        all_edges = []
        
        # Collect secret scanning alerts
        secret_findings, secret_edges = self.get_org_secret_scanning_alerts()
        all_findings.extend(secret_findings)
        all_edges.extend(secret_edges)
        
        logger.info(f"Collected {len(all_findings)} security findings total")
        return all_findings, all_edges
    
    def get_branches(self, repos: List[GitHoundNode]) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect repository branches and protection rules"""
        logger.info("Collecting branches")
        
        branches = []
        edges = []
        
        for repo in repos:
            repo_name = repo.properties['full_name']
            try:
                branches_data = self.session.make_request(f"repos/{repo_name}/branches")
                
                for branch_data in branches_data:
                    properties = {
                        'organization': repo.properties['organization_name'],
                        'organization_id': repo.properties['organization_id'],
                        'short_name': branch_data.get('name'),
                        'name': f"{repo.properties['name']}\\{branch_data.get('name')}",
                        'commit_hash': branch_data.get('commit', {}).get('sha'),
                        'commit_url': branch_data.get('commit', {}).get('url'),
                        'protected': branch_data.get('protected', False)
                    }
                    
                    # Get branch protection details if protected
                    if branch_data.get('protected') and branch_data.get('protection_url'):
                        try:
                            protection_data = self.session.make_request(
                                f"repos/{repo_name}/branches/{branch_data['name']}/protection"
                            )[0]
                            
                            properties.update({
                                'protection_enforce_admins': protection_data.get('enforce_admins', {}).get('enabled', False),
                                'protection_lock_branch': protection_data.get('lock_branch', {}).get('enabled', False),
                                'protection_required_pull_request_reviews': bool(protection_data.get('required_pull_request_reviews')),
                                'protection_required_approving_review_count': protection_data.get('required_pull_request_reviews', {}).get('required_approving_review_count', 0),
                                'protection_require_code_owner_reviews': protection_data.get('required_pull_request_reviews', {}).get('require_code_owner_reviews', False),
                                'protection_require_last_push_approval': protection_data.get('required_pull_request_reviews', {}).get('require_last_push_approval', False)
                            })
                            
                            # Handle bypass allowances
                            bypass_allowances = protection_data.get('required_pull_request_reviews', {}).get('bypass_pull_request_allowances', {})
                            if bypass_allowances:
                                for user in bypass_allowances.get('users', []):
                                    bypass_edge = self.create_edge('GHBypassPullRequestAllowances', user['node_id'], branch_data['commit']['sha'])
                                    edges.append(bypass_edge)
                                
                                for team in bypass_allowances.get('teams', []):
                                    bypass_edge = self.create_edge('GHBypassPullRequestAllowances', team['node_id'], branch_data['commit']['sha'])
                                    edges.append(bypass_edge)
                            
                            # Handle push restrictions
                            restrictions = protection_data.get('restrictions')
                            if restrictions:
                                for user in restrictions.get('users', []):
                                    restriction_edge = self.create_edge('GHRestrictionsCanPush', user['node_id'], branch_data['commit']['sha'])
                                    edges.append(restriction_edge)
                                
                                for team in restrictions.get('teams', []):
                                    restriction_edge = self.create_edge('GHRestrictionsCanPush', team['node_id'], branch_data['commit']['sha'])
                                    edges.append(restriction_edge)
                                    
                        except Exception as e:
                            logger.debug(f"Could not get protection details for {repo_name}/{branch_data['name']}: {e}")
                    
                    branch_node = self.create_node(branch_data['commit']['sha'], 'GHBranch', properties)
                    branches.append(branch_node)
                    
                    # Use GHContains edge from repository to branch (based on CSV)
                    branch_edge = self.create_edge('GHContains', repo.id, branch_data['commit']['sha'])
                    edges.append(branch_edge)
                    
            except Exception as e:
                logger.debug(f"Could not get branches for {repo_name}: {e}")
        
        return branches, edges
    
    def get_roles_and_permissions(self, organization: GitHoundNode, repos: List[GitHoundNode], teams: List[GitHoundNode]) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect roles and permission mappings"""
        logger.info("Collecting roles and permissions")
        
        roles = []
        edges = []
        
        # Create base organization roles
        org_id = organization.id
        org_login = organization.properties['login']
        
        # Base repository roles for organization
        base_roles = ['read', 'triage', 'write', 'maintain', 'admin']
        for role in base_roles:
            role_id = base64.b64encode(f"{org_id}_all_repo_{role}".encode()).decode()
            properties = {
                'id': role_id,
                'organization_name': org_login,
                'organization_id': org_id,
                'name': f"{org_login}/all_repo_{role}",
                'short_name': f'all_repo_{role}',
                'type': 'organization'
            }
            role_node = self.create_node(role_id, 'GHOrgRole', properties)
            roles.append(role_node)
        
        # Organization owners and members
        owners_id = base64.b64encode(f"{org_id}_owners".encode()).decode()
        owners_props = {
            'id': owners_id,
            'organization_name': org_login,
            'organization_id': org_id,
            'name': f"{org_login}/owners",
            'short_name': 'owners',
            'type': 'organization'
        }
        owners_role = self.create_node(owners_id, 'GHOrgRole', owners_props)
        roles.append(owners_role)
        
        members_id = base64.b64encode(f"{org_id}_members".encode()).decode()
        members_props = {
            'id': members_id,
            'organization_name': org_login,
            'organization_id': org_id,
            'name': f"{org_login}/members",
            'short_name': 'members',
            'type': 'organization'
        }
        members_role = self.create_node(members_id, 'GHOrgRole', members_props)
        roles.append(members_role)
        
        # Add organization permissions for owners
        owner_perms = ['GHCreateRepository', 'GHInviteMember', 'GHAddCollaborator', 'GHCreateTeam', 'GHTransferRepository']
        for perm in owner_perms:
            edge = self.create_edge(perm, owners_id, org_id)
            edges.append(edge)
        
        # Repository-specific roles
        for repo in repos:
            repo_roles = ['read', 'write', 'admin', 'triage', 'maintain']
            for role in repo_roles:
                role_id = base64.b64encode(f"{repo.id}_{role}".encode()).decode()
                properties = {
                    'id': role_id,
                    'organization_name': org_login,
                    'organization_id': org_id,
                    'name': f"{repo.properties['full_name']}/{role}",
                    'short_name': role,
                    'type': 'repository'
                }
                repo_role = self.create_node(role_id, 'GHRepoRole', properties)
                roles.append(repo_role)
                
                # Add appropriate permissions
                if role == 'read':
                    perms = ['GHCanPull', 'GHReadRepoContents']
                elif role == 'write':
                    perms = ['GHCanPush', 'GHCanPull', 'GHReadRepoContents', 'GHWriteRepoContents', 'GHWriteRepoPullRequests']
                elif role == 'admin':
                    perms = ['GHAdminTo', 'GHCanPush', 'GHCanPull', 'GHReadRepoContents', 'GHWriteRepoContents', 
                            'GHWriteRepoPullRequests', 'GHManageWebhooks', 'GHManageDeployKeys', 'GHPushProtectedBranch',
                            'GHDeleteAlertsCodeScanning', 'GHViewSecretScanningAlerts', 'GHBypassProtections', 'GHEditProtections']
                elif role == 'maintain':
                    perms = ['GHPushProtectedBranch']
                else:
                    perms = []
                
                for perm in perms:
                    edge = self.create_edge(perm, role_id, repo.id)
                    edges.append(edge)
        
        return roles, edges
    
    def get_saml_identities(self) -> List[GitHoundEdge]:
        """Collect SAML identity mappings using GraphQL"""
        logger.info("Collecting SAML identities")
        
        query = """
        query SAML($login: String!, $count: Int = 100, $after: String = null) {
            organization(login: $login) {
                id
                name
                samlIdentityProvider {
                    externalIdentities(first: $count, after: $after) {
                        nodes {
                            guid
                            id
                            samlIdentity {
                                attributes {
                                    metadata
                                    name
                                    value
                                }
                                nameId
                                username
                            }
                            user {
                                id
                                login
                            }
                        }
                        pageInfo {
                            endCursor
                            hasNextPage
                        }
                    }
                }
            }
        }
        """
        
        edges = []
        has_next_page = True
        after = None
        
        while has_next_page:
            variables = {
                'login': self.session.organization_name,
                'count': 100,
                'after': after
            }
            
            try:
                result = self.session.graphql_request(query, variables)
                
                if result.get('data', {}).get('organization', {}).get('samlIdentityProvider'):
                    identities = result['data']['organization']['samlIdentityProvider']['externalIdentities']
                    
                    for identity in identities['nodes']:
                        for attribute in identity.get('samlIdentity', {}).get('attributes', []):
                            if attribute['name'] == "http://schemas.microsoft.com/identity/claims/objectidentifier":
                                edge = self.create_edge('SyncedToGHUser', attribute['value'], identity['user']['id'])
                                edges.append(edge)
                    
                    page_info = identities['pageInfo']
                    has_next_page = page_info['hasNextPage']
                    after = page_info['endCursor']
                else:
                    break
                    
            except Exception as e:
                logger.debug(f"Could not collect SAML identities: {e}")
                break
        
        return edges
    
    def get_roles_and_permissions(self, organization: GitHoundNode, repos: List[GitHoundNode], teams: List[GitHoundNode]) -> Tuple[List[GitHoundNode], List[GitHoundEdge]]:
        """Collect roles and permission mappings"""
        logger.info("Collecting roles and permissions")
        
        roles = []
        edges = []
        
        # Create base organization roles
        org_id = organization.id
        org_login = organization.properties['login']
        
        # Base repository roles for organization
        base_roles = ['read', 'triage', 'write', 'maintain', 'admin']
        for role in base_roles:
            role_id = base64.b64encode(f"{org_id}_all_repo_{role}".encode()).decode()
            properties = {
                'id': role_id,
                'organization_name': org_login,
                'organization_id': org_id,
                'name': f"{org_login}/all_repo_{role}",
                'short_name': f'all_repo_{role}',
                'type': 'organization'
            }
            role_node = self.create_node(role_id, 'GHOrgRole', properties)
            roles.append(role_node)
            
            # Create GHContains edge from organization to org role
            contains_edge = self.create_edge('GHContains', org_id, role_id)
            edges.append(contains_edge)
        
        # Organization owners and members
        owners_id = base64.b64encode(f"{org_id}_owners".encode()).decode()
        owners_props = {
            'id': owners_id,
            'organization_name': org_login,
            'organization_id': org_id,
            'name': f"{org_login}/owners",
            'short_name': 'owners',
            'type': 'organization'
        }
        owners_role = self.create_node(owners_id, 'GHOrgRole', owners_props)
        roles.append(owners_role)
        
        # Create GHContains edge from organization to owners role
        contains_edge = self.create_edge('GHContains', org_id, owners_id)
        edges.append(contains_edge)
        
        members_id = base64.b64encode(f"{org_id}_members".encode()).decode()
        members_props = {
            'id': members_id,
            'organization_name': org_login,
            'organization_id': org_id,
            'name': f"{org_login}/members",
            'short_name': 'members',
            'type': 'organization'
        }
        members_role = self.create_node(members_id, 'GHOrgRole', members_props)
        roles.append(members_role)
        
        # Create GHContains edge from organization to members role
        contains_edge = self.create_edge('GHContains', org_id, members_id)
        edges.append(contains_edge)
        
        # Add organization permissions for owners
        owner_perms = ['GHCreateRepository', 'GHInviteMember', 'GHAddCollaborator', 'GHCreateTeam', 'GHTransferRepository']
        for perm in owner_perms:
            edge = self.create_edge(perm, owners_id, org_id)
            edges.append(edge)
        
        # Repository-specific roles
        for repo in repos:
            repo_roles = ['read', 'write', 'admin', 'triage', 'maintain']
            for role in repo_roles:
                role_id = base64.b64encode(f"{repo.id}_{role}".encode()).decode()
                properties = {
                    'id': role_id,
                    'organization_name': org_login,
                    'organization_id': org_id,
                    'name': f"{repo.properties['full_name']}/{role}",
                    'short_name': role,
                    'type': 'repository'
                }
                repo_role = self.create_node(role_id, 'GHRepoRole', properties)
                roles.append(repo_role)
                
                # Create GHContains edge from organization to repo role
                contains_edge = self.create_edge('GHContains', org_id, role_id)
                edges.append(contains_edge)
                
                # Add appropriate permissions
                if role == 'read':
                    perms = ['GHCanPull', 'GHReadRepoContents']
                elif role == 'write':
                    perms = ['GHCanPush', 'GHCanPull', 'GHReadRepoContents', 'GHWriteRepoContents', 'GHWriteRepoPullRequests']
                elif role == 'admin':
                    perms = ['GHAdminTo', 'GHCanPush', 'GHCanPull', 'GHReadRepoContents', 'GHWriteRepoContents', 
                            'GHWriteRepoPullRequests', 'GHManageWebhooks', 'GHManageDeployKeys', 'GHPushProtectedBranch',
                            'GHDeleteAlertsCodeScanning', 'GHViewSecretScanningAlerts', 'GHBypassProtections', 'GHEditProtections',
                            'GHRunOrgMigration', 'GHManageSecurityProducts', 'GHManageRepoSecurityProducts', 
                            'GHJumpMergeQueue', 'GHCreateSoloMergeQueue', 'GHEditRepoCustomPropertiesValue']
                elif role == 'maintain':
                    perms = ['GHPushProtectedBranch', 'GHCanPush', 'GHCanPull', 'GHReadRepoContents', 'GHWriteRepoContents', 
                            'GHWriteRepoPullRequests', 'GHManageWebhooks', 'GHManageDeployKeys']
                elif role == 'triage':
                    perms = ['GHCanPull', 'GHReadRepoContents', 'GHWriteRepoPullRequests']
                else:
                    perms = []
                
                for perm in perms:
                    edge = self.create_edge(perm, role_id, repo.id)
                    edges.append(edge)
        
        # Create team roles for each team
        for team in teams:
            team_role_id = base64.b64encode(f"{team.id}_team_role".encode()).decode()
            team_role_props = {
                'id': team_role_id,
                'organization_name': org_login,
                'organization_id': org_id,
                'name': f"{team.properties['name']}_role",
                'short_name': f"{team.properties['name']}_role",
                'type': 'team'
            }
            team_role = self.create_node(team_role_id, 'GHTeamRole', team_role_props)
            roles.append(team_role)
            
            # Create GHContains edge from organization to team role
            contains_edge = self.create_edge('GHContains', org_id, team_role_id)
            edges.append(contains_edge)
            
            # Create GHMemberOf edge from team role to team
            member_edge = self.create_edge('GHMemberOf', team_role_id, team.id)
            edges.append(member_edge)
        
        return roles, edges
    
    def get_user_role_assignments(self, organization: GitHoundNode, users: List[GitHoundNode], teams: List[GitHoundNode], repos: List[GitHoundNode]) -> List[GitHoundEdge]:
        """Collect user role assignments and team memberships"""
        logger.info("Collecting user role assignments and team memberships")
        
        edges = []
        
        # Get organization membership roles
        try:
            for user in users:
                # Get user's organization membership details
                membership_data = self.session.make_request(
                    f"orgs/{organization.properties['login']}/memberships/{user.properties['login']}"
                )[0]
                
                role = membership_data.get('role', 'member')  # 'admin' or 'member'
                
                # Create role assignment edges
                if role == 'admin':
                    owners_id = base64.b64encode(f"{organization.id}_owners".encode()).decode()
                    role_edge = self.create_edge('GHHasRole', user.id, owners_id)
                    edges.append(role_edge)
                else:
                    members_id = base64.b64encode(f"{organization.id}_members".encode()).decode()
                    role_edge = self.create_edge('GHHasRole', user.id, members_id)
                    edges.append(role_edge)
                    
        except Exception as e:
            logger.debug(f"Could not get organization membership details: {e}")
        
        # Get team memberships
        for team in teams:
            try:
                team_members = self.session.make_request(
                    f"orgs/{organization.properties['login']}/teams/{team.properties['slug']}/members"
                )
                
                team_role_id = base64.b64encode(f"{team.id}_team_role".encode()).decode()
                
                for member in team_members:
                    # Find the user node
                    user_node = None
                    for user in users:
                        if user.properties['login'] == member['login']:
                            user_node = user
                            break
                    
                    if user_node:
                        # Create GHHasRole edge from user to team role
                        role_edge = self.create_edge('GHHasRole', user_node.id, team_role_id)
                        edges.append(role_edge)
                        
            except Exception as e:
                logger.debug(f"Could not get team members for {team.properties['name']}: {e}")
        
        return edges
    
    def run_collection(self) -> Dict:
        """Run the complete data collection process"""
        logger.info(f"Starting GitHub collection for organization: {self.session.organization_name}")
        
        # Collect organization
        organization = self.get_organization()
        
        # Collect users
        users = self.get_users(organization)
        
        # Collect teams
        teams, team_edges = self.get_teams(organization)
        self.graph.edges.extend(team_edges)
        
        # Collect repositories (this populates the repo_lookup cache)
        repos, repo_edges = self.get_repositories(organization)
        self.graph.edges.extend(repo_edges)
        
        # Collect security findings using organization-level APIs
        findings, finding_edges = self.get_security_findings(repos)
        self.graph.nodes.extend(findings)
        self.graph.edges.extend(finding_edges)
        
        # Collect branches
        branches, branch_edges = self.get_branches(repos)
        self.graph.nodes.extend(branches)
        self.graph.edges.extend(branch_edges)
        
        # Collect roles and permissions
        roles, role_edges = self.get_roles_and_permissions(organization, repos, teams)
        self.graph.nodes.extend(roles)
        self.graph.edges.extend(role_edges)
        
        # Collect user role assignments and team memberships
        user_role_edges = self.get_user_role_assignments(organization, users, teams, repos)
        self.graph.edges.extend(user_role_edges)
        
        # Collect SAML identities
        saml_edges = self.get_saml_identities()
        self.graph.edges.extend(saml_edges)
        
        # Create final payload
        payload = {
            'metadata': {
                'source_kind': 'GHBase'
            },
            'graph': {
                'nodes': [
                    {
                        'id': node.id,
                        'kinds': node.kinds,
                        'properties': node.properties
                    }
                    for node in self.graph.nodes
                ],
                'edges': [
                    {
                        'kind': edge.kind,
                        'start': edge.start,
                        'end': edge.end,
                        'properties': edge.properties
                    }
                    for edge in self.graph.edges
                ]
            }
        }
        
        logger.info(f"Collection complete: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")
        return payload
    

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='GitHub BloodHound Ingestor')
    parser.add_argument('--organization', '-o', required=True, help='GitHub organization name')
    parser.add_argument('--output', '-f', help='Output file path (default: githound_<org>.json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--include-security', '-s', action='store_true', default=True, 
                       help='Include security findings (default: True)')
    
    args = parser.parse_args()
    token = getpass.getpass("Enter your GitHub PAT: ").strip()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create session and ingestor
    session = GitHubSession(args.organization, token)
    ingestor = GitHoundIngestor(session)
    
    try:
        # Run collection
        payload = ingestor.run_collection()
        
        # Write output
        output_file = args.output or f"githound_{args.organization}.json"
        with open(output_file, 'w') as f:
            json.dump(payload, f, indent=2)
        
        logger.info(f"Output written to: {output_file}")
        
        # Print summary
        print(f"[+] Collection Summary for {args.organization}")
        print(f"[+] Output: {output_file}")
        
        # Node type breakdown
        node_types = {}
        for node in payload['graph']['nodes']:
            node_type = node['kinds'][0] if node['kinds'] else 'Unknown'
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        print(f"\n[+] Node Breakdown:")
        for node_type, count in sorted(node_types.items()):
            print(f"   {node_type}: {count}")
        
        # Security findings breakdown if collected
        security_findings = [node for node in payload['graph']['nodes'] 
                           if 'GHSecretScanningAlert' in node['kinds']]
        if security_findings:
            finding_types = {}
            for finding in security_findings:
                finding_type = finding['properties'].get('finding_type', 'unknown')
                finding_types[finding_type] = finding_types.get(finding_type, 0) + 1
            
            print(f"\n[+] Secrets Findings Breakdown:")
            for finding_type, count in sorted(finding_types.items()):
                print(f"   {finding_type}: {count}")
            
    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()