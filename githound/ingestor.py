"""
Main ingestion logic for GitHound.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from .session import GitHubSession
from opengraph import OpenGraphBuilder

logger = logging.getLogger(__name__)

class GitHoundIngestor:
    def __init__(self, organization_name: str, session: GitHubSession, max_workers: int = 10):
        self.session = session
        self.organization_name = organization_name
        self.graph = OpenGraphBuilder(source_kind="GHBase")
        self.max_workers = max_workers

        self.repo_lookup = {}
        self.user_lookup = {}

    def run(self):
        self.organization = self.get_organization(self.organization_name)
        self.users = self.get_users()
        self.teams = self.get_teams()
        self.repos = self.get_repositories()   
        
        self.get_org_secret_scanning_alerts()

        self.get_team_roles()
        self.get_organization_roles()
        self.get_repo_roles()

        logger.info("Ingestion complete")

    def save_graph(self, filename: str):
        """Save the graph to a file"""
        logger.info(f"Saving graph to {filename}")
        self.graph.save_to_file(filename)

    def get_organization(self, organization_name) -> Dict[str, Any]:
        """Collect organization information"""
        logger.info(f"Collecting organization: {organization_name}")
        
        org_data = self.session.make_request(f"orgs/{organization_name}")[0]
        
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
        
        self.graph.create_node(
            org_data['node_id'], 
            ['GHOrganization'], 
            properties
        )

        return org_data

    def get_users(self) -> List[Dict[str, Any]]:
        """Collect organization users using parallel processing"""
        logger.info("Collecting users")
        
        users_data = self.session.make_request(f"orgs/{self.organization['login']}/members")
        logger.info(f"Found {len(users_data)} users in organization")

        def process_user(user_data: Dict[str, Any]) -> Dict[str, Any]:
            """Process a single user with detailed API call"""
            logger.debug(f"Processing user: {user_data['login']}")

            # Get detailed user info
            try:
                user_details = self.session.make_request(f"user/{user_data['id']}")[0]
            except Exception as e:
                logger.error(f"Failed to fetch details for user {user_data['login']}: {e}")
                return None
            
            properties = {
                'id': user_data.get('id'),
                'node_id': user_data.get('node_id'),
                'login': user_data.get('login'),
                'name': user_data.get('login'),
                'full_name': user_details.get('name'),
                'company': user_details.get('company'),
                'email': user_details.get('email'),
                'twitter_username': user_details.get('twitter_username'),
                'type': user_data.get('type'),
                'site_admin': user_data.get('site_admin')
            }
            
            user_node = self.graph.create_node(user_data['node_id'], ['GHUser'], properties)
            self.graph.create_edge(self.organization['node_id'], user_node.id, 'GHContains')
            self.user_lookup[user_data['login']] = user_node
            
            return user_node

        users = []
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all user processing tasks
            future_to_user = {
                executor.submit(process_user, user_data): user_data
                for user_data in users_data
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_user):
                user_data = future_to_user[future]
                try:
                    user_node = future.result()
                    if user_node:
                        users.append(user_node)
                except Exception as e:
                    logger.error(f"Failed to process user {user_data.get('login', 'unknown')}: {e}")
        
        logger.info(f"Successfully processed {len(users)} users")
        return users


    def get_teams(self) -> List[Dict[str, Any]]:
        """Collect organization teams"""
        logger.info("Collecting teams")
        
        teams_data = self.session.make_request(f"orgs/{self.organization['login']}/teams")

        teams = []
        
        for team in teams_data:
            properties = {
                'id': team.get('id'),
                'node_id': team.get('node_id'),
                'name': team.get('name'),
                'slug': team.get('slug'),
                'description': team.get('description'),
                'privacy': team.get('privacy'),
                'permission': team.get('permission')
            }
            
            team_node = self.graph.create_node(team['node_id'], ['GHTeam'], properties)
            teams.append(team_node)

            self.graph.create_edge(self.organization['node_id'], team_node.id, 'GHContains')
            
            # Handle parent team relationships
            if team.get('parent'):
                self.graph.create_edge(team_node.id, team['parent']['node_id'], 'GHMemberOf')
        
        return teams
    
    def get_repositories(self) -> List[Dict[str, Any]]:
        """Collect organization repositories"""
        logger.info("Collecting repositories")
        
        repos_data = self.session.make_request(f"orgs/{self.organization['login']}/repos")
        repos = []
        
        for repo_data in repos_data:
            properties = {
                'id': repo_data.get('id'),
                'node_id': repo_data.get('node_id'),
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
            
            repo_node = self.graph.create_node(repo_data['node_id'], ['GHRepository'], properties)
            repos.append(repo_node)
            
            self.repo_lookup[repo_data['full_name']] = repo_node
            
            # Create GHContains edge from organization to repository
            self.graph.create_edge(self.organization['node_id'], repo_node.id, 'GHContains')
            
            # Create ownership edge (if owner is different from organization)
            if repo_data['owner']['node_id'] != self.organization['id']:
                self.graph.create_edge(repo_node.id, repo_data['owner']['node_id'], 'GHOwnedBy')
        
        return repos

    def get_org_secret_scanning_alerts(self) -> List[Dict[str, Any]]:
        """Collect organization-wide secret scanning alerts"""

        logger.info("Collecting organization secret scanning alerts")
        
        findings = []
        
        try:
            # Use organization-level secret scanning API
            secret_alerts = self.session.make_request(
                f"orgs/{self.organization['login']}/secret-scanning/alerts"
            )
            
            for alert in secret_alerts:
                repo_name = alert.get('repository', {}).get('full_name')
                repo_node = self.repo_lookup.get(repo_name)
                
                if not repo_node:
                    logger.warning(f"Repository {repo_name} not found in cache for secret alert {alert.get('number')}")
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
                finding_node = self.graph.create_node(finding_id, ['GHSecretScanningAlert'], properties)
                findings.append(finding_node)

                self.graph.create_edge(repo_node.id, finding_id, 'GHHasSecretScanningAlert')
                
        except Exception as e:
            logger.error(f"Failed to collect organization secret scanning alerts: {e}")
        
        return findings
        
    def get_team_roles(self) -> None:
        """Collect team roles and memberships"""
        logger.info("Collecting team roles and memberships")

        def process_team(team_node):
            members_id = f"{team_node.id}_members"
            properties = {
                'id': members_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{self.organization['login']}/{team_node.properties['slug']}/members",
                'short_name': f"members",
                'type': 'team'
            }
            self.graph.create_node(members_id, ['GHTeamRole'], properties)
            self.graph.create_edge(members_id, team_node.id, 'GHMemberOf')

            maintainers_id = f"{team_node.id}_maintainers"
            properties = {
                'id': maintainers_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{self.organization['login']}/{team_node.properties['slug']}/maintainers",
                'short_name': f"maintainers",
                'type': 'team'
            }
            self.graph.create_node(maintainers_id, ['GHTeamRole'], properties)
            self.graph.create_edge(maintainers_id, team_node.id, 'GHMemberOf')
            self.graph.create_edge(maintainers_id, team_node.id, 'GHAddMember')

            team_members_member = self.session.make_request(
                f"orgs/{self.organization['login']}/teams/{team_node.properties['slug']}/members?role=member"
            )
            for member in team_members_member:
                self.graph.create_edge(member['node_id'], members_id, 'GHHasRole')

            team_members_maintainer = self.session.make_request(
                f"orgs/{self.organization['login']}/teams/{team_node.properties['slug']}/members?role=maintainer"
            )
            for member in team_members_maintainer:
                self.graph.create_edge(member['node_id'], maintainers_id, 'GHHasRole')

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(process_team, team_node): team_node for team_node in self.teams}
            for future in as_completed(futures):
                team_node = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Failed to process team {team_node.properties.get('name', 'unknown')}: {e}")

    def get_organization_roles(self) -> None:
        """Collect organization roles and permissions"""
        logger.info("Collecting organization roles and permissions")

        org_all_repo_read_id = f"{self.organization['node_id']}_all_repo_read"
        org_all_repo_triage_id = f"{self.organization['node_id']}_all_repo_triage"
        org_all_repo_write_id = f"{self.organization['node_id']}_all_repo_write"
        org_all_repo_maintain_id = f"{self.organization['node_id']}_all_repo_maintain"
        org_all_repo_admin_id = f"{self.organization['node_id']}_all_repo_admin"

        custom_roles = self.session.make_request(
            f"orgs/{self.organization['login']}/organization-roles"
        )[0].get("roles", [])

        for custom_role in custom_roles:
            custom_role_id = f"{self.organization['node_id']}_{custom_role['name']}"

            properties = {
                'id': custom_role_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{self.organization['login']}/{custom_role['name']}",
                'short_name': custom_role['name'],
                'type': 'organization'
            }

            self.graph.create_node(custom_role_id, ['GHOrgRole'], properties)
            
            custom_role_member_teams = self.session.make_request(
                f"orgs/{self.organization['login']}/organization-roles/{custom_role['id']}/teams"
            )

            for member_team in custom_role_member_teams:
                self.graph.create_edge(member_team['node_id'], custom_role_id, 'GHHasRole')

            custom_role_member_users = self.session.make_request(
                f"orgs/{self.organization['login']}/organization-roles/{custom_role['id']}/users"
            )

            for member_user in custom_role_member_users:
                self.graph.create_edge(member_user['node_id'], custom_role_id, 'GHHasRole')

            base_role = custom_role.get('base_role')

            if base_role == 'read':
                self.graph.create_edge(custom_role_id, org_all_repo_read_id, 'GHHasBaseRole')
            elif base_role == 'triage':
                self.graph.create_edge(custom_role_id, org_all_repo_triage_id, 'GHHasBaseRole')
            elif base_role == 'write':
                self.graph.create_edge(custom_role_id, org_all_repo_write_id, 'GHHasBaseRole')
            elif base_role == 'maintain':
                self.graph.create_edge(custom_role_id, org_all_repo_maintain_id, 'GHHasBaseRole')
            elif base_role == 'admin':
                self.graph.create_edge(custom_role_id, org_all_repo_admin_id, 'GHHasBaseRole')

            for permission in custom_role.get('permissions', []):
                if permission == 'manage_organization_webhooks':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHManageOrganizationWebhooks')
                elif permission == 'org_bypass_code_scanning_dismissal_requests':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHOrgBypassCodeScanningDismissalRequests')
                elif permission == 'org_bypass_secret_scanning_closure_requests':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHOrgBypassSecretScanningClosureRequests')
                elif permission == 'org_review_and_manage_secret_scanning_bypass_requests':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHOrgReviewAndManageSecretScanningBypassRequests')
                elif permission == 'org_review_and_manage_secret_scanning_closure_requests':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHOrgReviewAndManageSecretScanningClosureRequests')
                elif permission == 'read_organization_actions_usage_metrics':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHReadOrganizationActionsUsageMetrics')
                elif permission == 'read_organization_custom_org_role':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHReadOrganizationCustomOrgRole')
                elif permission == 'read_organization_custom_repo_role':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHReadOrganizationCustomRepoRole')
                elif permission == 'resolve_secret_scanning_alerts':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHResolveSecretScanningAlerts')
                elif permission == 'view_secret_scanning_alerts':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHViewSecretScanningAlerts')
                elif permission == 'write_organization_actions_secrets':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHWriteOrganizationActionsSecrets')
                elif permission == 'write_organization_actions_settings':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHWriteOrganizationActionsSettings')
                elif permission == 'write_organization_custom_org_role':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHWriteOrganizationCustomOrgRole')
                elif permission == 'write_organization_custom_repo_role':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHWriteOrganizationCustomRepoRole')
                elif permission == 'write_organization_network_configurations':
                    self.graph.create_edge(custom_role_id, self.organization['node_id'], 'GHWriteOrganizationNetworkConfigurations')
                else:
                    logger.warning(f"Unhandled permission {permission} for custom role {custom_role['name']}")


        org_owners_id = f"{self.organization['node_id']}_owners"

        properties = {
            'id': org_owners_id,
            'organization_name': self.organization['login'],
            'organization_id': self.organization['node_id'],
            'name': f"{self.organization['login']}/owners",
            'short_name': 'owners',
            'type': 'organization'
        }

        self.graph.create_node(org_owners_id, ['GHOrgRole'], properties)

        self.graph.create_edge(org_owners_id, self.organization['node_id'], 'GHCreateRepository')
        self.graph.create_edge(org_owners_id, self.organization['node_id'], 'GHInviteMember')
        self.graph.create_edge(org_owners_id, self.organization['node_id'], 'GHAddCollaborator')
        self.graph.create_edge(org_owners_id, self.organization['node_id'], 'GHCreateTeam')
        self.graph.create_edge(org_owners_id, self.organization['node_id'], 'GHTransferRepository')
        self.graph.create_edge(org_owners_id, org_all_repo_admin_id, 'GHHasBaseRole')

        org_members_id = f"{self.organization['node_id']}_members"

        properties = {
            'id': org_members_id,
            'organization_name': self.organization['login'],
            'organization_id': self.organization['node_id'],
            'name': f"{self.organization['login']}/members",
            'short_name': 'members',
            'type': 'organization'
        }

        self.graph.create_node(org_members_id, ['GHOrgRole'], properties)

        self.graph.create_edge(org_members_id, self.organization['node_id'], 'GHCreateRepository')
        self.graph.create_edge(org_members_id, self.organization['node_id'], 'GHCreateTeam')
                
        if self.organization.get('default_repository_permission') != None:
            self.graph.create_edge(org_members_id, f"{self.organization['node_id']}_all_repo_{self.organization['default_repository_permission']}", 'GHHasBaseRole')

        org_members_admin = self.session.make_request(
            f"orgs/{self.organization['login']}/members?role=admin"
        )

        for member in org_members_admin:
            self.graph.create_edge(member['node_id'], org_owners_id, 'GHHasRole')

        org_members_members = self.session.make_request(
            f"orgs/{self.organization['login']}/members?role=member"
        )

        for member in org_members_members:
            self.graph.create_edge(member['node_id'], org_members_id, 'GHHasRole')


    def get_repo_roles(self) -> None:
        """Collect repository roles and permissions"""
        logger.info("Collecting repository roles and permissions")

        org_all_repo_read_id = f"{self.organization['node_id']}_all_repo_read"
        org_all_repo_triage_id = f"{self.organization['node_id']}_all_repo_triage"
        org_all_repo_write_id = f"{self.organization['node_id']}_all_repo_write"
        org_all_repo_maintain_id = f"{self.organization['node_id']}_all_repo_maintain"
        org_all_repo_admin_id = f"{self.organization['node_id']}_all_repo_admin"

        custom_repo_roles = self.session.make_request(
            f"orgs/{self.organization['login']}/custom-repository-roles"
        )[0].get('custom_roles', [])

        def process_repo(repo_node):
            repo_read_id = f"{repo_node.id}_read"

            properties = {
                'id': repo_read_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{repo_node.properties['full_name']}/read",
                'short_name': 'read',
                'type': 'repository'
            }

            self.graph.create_node(repo_read_id, ['GHRepoRole'], properties)

            self.graph.create_edge(repo_read_id, repo_node.id, 'GHCanPull')
            self.graph.create_edge(repo_read_id, repo_node.id, 'GHReadRepoContents')
            self.graph.create_edge(org_all_repo_read_id, repo_read_id, 'GHHasBaseRole')

            repo_write_id = f"{repo_node.id}_write"

            properties = {
                'id': repo_write_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{repo_node.properties['full_name']}/write",
                'short_name': 'write',
                'type': 'repository'
            }

            self.graph.create_node(repo_write_id, ['GHRepoRole'], properties)

            self.graph.create_edge(repo_write_id, repo_node.id, 'GHCanPush')
            self.graph.create_edge(repo_write_id, repo_node.id, 'GHCanPull')
            self.graph.create_edge(repo_write_id, repo_node.id, 'GHReadRepoContents')
            self.graph.create_edge(repo_write_id, repo_node.id, 'GHWriteRepoContents')
            self.graph.create_edge(repo_write_id, repo_node.id, 'GHWriteRepoPullRequests')
            self.graph.create_edge(org_all_repo_write_id, repo_write_id, 'GHHasBaseRole')

            repo_admin_id = f"{repo_node.id}_admin"

            properties = {
                'id': repo_admin_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{repo_node.properties['full_name']}/admin",
                'short_name': 'admin',
                'type': 'repository'
            }

            self.graph.create_node(repo_admin_id, ['GHRepoRole'], properties)

            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHAdminTo')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHCanPush')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHCanPull')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHReadRepoContents')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHWriteRepoContents')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHWriteRepoPullRequests')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHManageWebhooks')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHManageDeployKeys')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHPushProtectedBranch')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHDeleteAlertsCodeScanning')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHViewSecretScanningAlerts')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHRunOrgMigration')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHBypassProtections')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHJumpMergeQueue')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHCreateSoloMergeQueueEntry')
            self.graph.create_edge(repo_admin_id, repo_node.id, 'GHEditRepoCustomPropertiesValues')
            self.graph.create_edge(org_all_repo_admin_id, repo_admin_id, 'GHHasBaseRole')

            repo_triage_id = f"{repo_node.id}_triage"

            properties = {
                'id': repo_triage_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{repo_node.properties['full_name']}/triage",
                'short_name': 'triage',
                'type': 'repository'
            }

            self.graph.create_node(repo_triage_id, ['GHRepoRole'], properties)

            self.graph.create_edge(repo_triage_id, repo_node.id, 'GHCanPull')
            self.graph.create_edge(repo_triage_id, repo_read_id, 'GHHasBaseRole')
            self.graph.create_edge(org_all_repo_triage_id, repo_triage_id, 'GHHasBaseRole')

            repo_maintain_id = f"{repo_node.id}_maintain"

            properties = {
                'id': repo_maintain_id,
                'organization_name': self.organization['login'],
                'organization_id': self.organization['node_id'],
                'name': f"{repo_node.properties['full_name']}/maintain",
                'short_name': 'maintain',
                'type': 'repository'
            }

            self.graph.create_node(repo_maintain_id, ['GHRepoRole'], properties)

            self.graph.create_edge(repo_maintain_id, repo_node.id, 'GHPushProtectedBranch')
            self.graph.create_edge(repo_maintain_id, repo_write_id, 'GHHasBaseRole')
            self.graph.create_edge(org_all_repo_maintain_id, repo_maintain_id, 'GHHasBaseRole')

            for custom_role in custom_repo_roles:
                custom_role_id = f"{repo_node.id}_{custom_role['name']}"

                properties = {
                    'id': custom_role_id,
                    'organization_name': self.organization['login'],
                    'organization_id': self.organization['node_id'],
                    'name': f"{repo_node.properties['full_name']}/{custom_role['name']}",
                    'short_name': custom_role['name'],
                    'type': 'repository'
                }

                self.graph.create_node(custom_role_id, ['GHRepoRole'], properties)

                if custom_role.get('base_role') != None:
                    self.graph.create_edge(custom_role_id, f"{repo_node.id}_{custom_role['base_role']}", 'GHHasBaseRole')

                ignored_permissions = [
                    'close_issue', 'close_pull_request',
                    'mark_as_duplicate', 'reopen_issue', 'request_pr_review'
                ]

                for permission in custom_role.get('permissions', []):
                    if permission == 'manage_webhooks':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHManageWebhooks')
                    elif permission == 'manage_deploy_keys':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHManageDeployKeys')
                    elif permission == 'push_protected_branch':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHPushProtectedBranch')
                    elif permission == 'delete_alerts_code_scanning':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHDeleteAlertsCodeScanning')
                    elif permission == 'view_secret_scanning_alerts':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHViewSecretScanningAlerts')
                    elif permission == 'bypass_branch_protection':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHBypassProtections')
                    elif permission == 'edit_repo_protections':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHEditProtections')
                    elif permission == 'jump_merge_queue':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHJumpMergeQueue')
                    elif permission == 'create_solo_merge_queue_entry':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHCreateSoloMergeQueueEntry')
                    elif permission == 'edit_repo_custom_properties_values':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHEditRepoCustomPropertiesValues')
                    elif permission == 'add_assignee':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHAddAssignee')
                    elif permission == 'add_label':
                        self.graph.create_edge(custom_role_id, repo_node.id, 'GHAddLabel')
                    elif permission in ignored_permissions:
                        pass
                    else:
                        logger.warning(f"Unhandled permission {permission} for custom role {custom_role['name']} in repository {repo_node.properties['full_name']}")

            collaborators = self.session.make_request(
                f"repos/{repo_node.properties['full_name']}/collaborators?affiliation=direct"
            )

            for collaborator in collaborators:
                collaborator_role = collaborator.get('role_name')

                if collaborator_role == 'admin':
                    self.graph.create_edge(collaborator['node_id'], repo_admin_id, 'GHHasRole')
                elif collaborator_role == 'maintainer':
                    self.graph.create_edge(collaborator['node_id'], repo_maintain_id, 'GHHasRole')
                elif collaborator_role == 'write':
                    self.graph.create_edge(collaborator['node_id'], repo_write_id, 'GHHasRole')
                elif collaborator_role == 'triage':
                    self.graph.create_edge(collaborator['node_id'], repo_triage_id, 'GHHasRole')
                elif collaborator_role == 'read':
                    self.graph.create_edge(collaborator['node_id'], repo_read_id, 'GHHasRole')
                else:
                    self.graph.create_edge(collaborator['node_id'], f'{repo_node.id}_{collaborator_role}', 'GHHasRole')

            team_collaborators = self.session.make_request(
                f"repos/{repo_node.properties['full_name']}/teams"
            )

            for team in team_collaborators:
                team_role = team.get('permission')

                if team_role == 'admin':
                    self.graph.create_edge(team['node_id'], repo_admin_id, 'GHHasRole')
                elif team_role == 'maintain':
                    self.graph.create_edge(team['node_id'], repo_maintain_id, 'GHHasRole')
                elif team_role == 'write':
                    self.graph.create_edge(team['node_id'], repo_write_id, 'GHHasRole')
                elif team_role == 'triage':
                    self.graph.create_edge(team['node_id'], repo_triage_id, 'GHHasRole')
                elif team_role == 'read':
                    self.graph.create_edge(team['node_id'], repo_read_id, 'GHHasRole')
                else:
                    self.graph.create_edge(team['node_id'], f'{repo_node.id}_{team_role}', 'GHHasRole')

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(process_repo, repo_node): repo_node for repo_node in self.repos}
            for future in as_completed(futures):
                repo_node = futures[future]
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Failed to process repository {repo_node.properties.get('full_name', 'unknown')}: {e}")
