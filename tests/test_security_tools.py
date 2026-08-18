"""Tests for security and audit tools."""

import pytest
from unittest.mock import Mock, patch
import json
import base64
from datetime import datetime, timedelta

from aditor.tools.security import SecurityTools
from mcp.types import TextContent


@pytest.fixture
def mock_ldap_manager():
    """Mock LDAP manager for testing."""
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.domain = "test.local"
    return manager


@pytest.fixture
def security_tools(mock_ldap_manager):
    """Security tools instance for testing."""
    return SecurityTools(mock_ldap_manager)


class TestSecurityTools:
    """Test security and audit functionality."""
    
    def test_get_domain_info_success(self, security_tools, mock_ldap_manager):
        """Test successful domain information retrieval."""
        # Mock domain object search
        mock_domain_result = [
            {
                'dn': 'DC=test,DC=local',
                'attributes': {
                    'name': ['test'],
                    'dc': ['test'],
                    'objectSid': [b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'lockoutThreshold': [5],
                    'lockoutDuration': [-18000000000],  # 30 minutes in 100ns intervals
                    'maxPwdAge': [-36288000000000],  # 42 days
                    'minPwdAge': [-864000000000],  # 1 day
                    'minPwdLength': [8],
                    'pwdHistoryLength': [24],
                    'functionalLevel': [7]  # Windows Server 2008 R2
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_domain_result
        
        # Test get_domain_info
        result = security_tools.get_domain_info()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['name'] == 'test'
        assert response_data['domain_component'] == 'test'
        assert 'password_policy' in response_data
        
        password_policy = response_data['password_policy']
        assert password_policy['min_password_length'] == 8
        assert password_policy['password_history_length'] == 24
        assert password_policy['lockout_threshold'] == 5
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_privileged_groups_success(self, security_tools, mock_ldap_manager):
        """Test successful privileged group retrieval."""
        # Mock privileged groups search results
        mock_results = [
            {
                'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'displayName': ['Domain Admins'],
                    'description': ['Designated administrators of the domain'],
                    'member': [
                        'CN=Administrator,CN=Users,DC=test,DC=local',
                        'CN=Admin User,OU=Users,DC=test,DC=local'
                    ],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'adminCount': [1]
                }
            },
            {
                'dn': 'CN=Enterprise Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Enterprise Admins'],
                    'displayName': ['Enterprise Admins'],
                    'description': ['Designated administrators of the enterprise'],
                    'member': ['CN=Administrator,CN=Users,DC=test,DC=local'],
                    'adminCount': [1]
                }
            },
            {
                'dn': 'CN=Backup Operators,CN=Builtin,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Backup Operators'],
                    'displayName': ['Backup Operators'],
                    'description': ['Backup Operators can override security restrictions'],
                    'member': ['CN=Backup Service,OU=Service Accounts,DC=test,DC=local']
                }
            }
        ]
        
        # get_privileged_groups searches for each well-known group by name; return
        # the matching mock entry per query and empty for the rest.
        def search_side_effect(*args, **kwargs):
            search_filter = kwargs.get('search_filter', '')
            for entry in mock_results:
                name = entry['attributes']['sAMAccountName'][0]
                if f'sAMAccountName={name}' in search_filter:
                    return [entry]
            return []
        mock_ldap_manager.search.side_effect = search_side_effect

        # Test get_privileged_groups
        result = security_tools.get_privileged_groups()

        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['total_groups'] == 3
        assert len(response_data['privileged_groups']) == 3

        # Check specific groups (real output keys on sam_account_name / member_count)
        groups = {group['sam_account_name']: group for group in response_data['privileged_groups']}
        assert 'Domain Admins' in groups
        assert 'Enterprise Admins' in groups
        assert 'Backup Operators' in groups

        # Check member counts
        assert groups['Domain Admins']['member_count'] == 2
        assert groups['Enterprise Admins']['member_count'] == 1
    
    def test_audit_admin_accounts_success(self, security_tools, mock_ldap_manager):
        """Test successful admin account audit."""
        # audit_admin_accounts first searches each privileged group for its members,
        # then does a BASE-scoped lookup for each member DN.
        admin_dn = 'CN=Administrator,CN=Users,DC=test,DC=local'
        adminuser_dn = 'CN=Admin User,OU=Users,DC=test,DC=local'
        svc_dn = 'CN=Service Admin,OU=Service Accounts,DC=test,DC=local'

        users_by_dn = {
            admin_dn: [{
                'dn': admin_dn,
                'attributes': {
                    'sAMAccountName': ['Administrator'],
                    'displayName': ['Built-in Administrator'],
                    'userAccountControl': [512],  # Enabled, no flags
                    'lastLogon': [datetime.now() - timedelta(days=1)],
                    'pwdLastSet': [datetime.now() - timedelta(days=30)],
                }
            }],
            adminuser_dn: [{
                'dn': adminuser_dn,
                'attributes': {
                    'sAMAccountName': ['admin.user'],
                    'displayName': ['Admin User'],
                    'userAccountControl': [512],  # Enabled
                    'lastLogon': [datetime.now() - timedelta(days=120)],  # Stale (>90 days)
                    'pwdLastSet': [datetime.now() - timedelta(days=180)],
                }
            }],
            svc_dn: [{
                'dn': svc_dn,
                'attributes': {
                    'sAMAccountName': ['svc.admin'],
                    'displayName': ['Service Admin Account'],
                    'userAccountControl': [66048],  # Enabled, password never expires
                    'lastLogon': [datetime.now()],
                    'pwdLastSet': [datetime.now() - timedelta(days=365)],
                }
            }],
        }

        def search_side_effect(*args, **kwargs):
            search_filter = kwargs.get('search_filter', '')
            search_base = kwargs.get('search_base', '')
            if 'objectClass=group' in search_filter:
                # Only Domain Admins carries members in this fixture
                if 'sAMAccountName=Domain Admins' in search_filter:
                    return [{
                        'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                        'attributes': {'member': [admin_dn, adminuser_dn, svc_dn]}
                    }]
                return []
            # Per-member user lookup (scope BASE)
            return users_by_dn.get(search_base, [])

        mock_ldap_manager.search.side_effect = search_side_effect

        # Test audit_admin_accounts
        result = security_tools.audit_admin_accounts()

        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['total_admin_accounts'] == 3
        assert response_data['high_risk_count'] == 1
        assert response_data['medium_risk_count'] == 1
        assert response_data['low_risk_count'] == 1

        # Verify specific accounts (real output keys)
        accounts = {acc['sam_account_name']: acc for acc in response_data['admin_accounts']}

        # Built-in administrator should be enabled and low risk (no security issues)
        admin = accounts['Administrator']
        assert admin['enabled'] == True
        assert admin['risk_level'] == 'LOW'

        # Stale admin account flagged for inactivity
        assert accounts['admin.user']['risk_level'] == 'MEDIUM'

        # Service account with 'password never expires' flag is high risk
        svc_admin = accounts['svc.admin']
        assert svc_admin['risk_level'] == 'HIGH'
        assert 'Password never expires' in svc_admin['security_issues']
    
    def test_security_risk_assessment(self, security_tools):
        """Test security risk assessment logic."""
        # Test different risk scenarios
        
        # High risk: Multiple privileged groups + old password
        high_risk_account = {
            'memberOf': [
                'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'CN=Enterprise Admins,CN=Users,DC=test,DC=local'
            ],
            'pwdLastSet': [datetime.now() - timedelta(days=200)],
            'lastLogon': [datetime.now() - timedelta(days=90)]
        }
        risk = security_tools._assess_account_risk(high_risk_account)
        assert risk == 'high'  # _assess_account_risk returns lowercase (see WP5 casing note)
        
        # Medium risk: One privileged group + recent activity
        medium_risk_account = {
            'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=30)],
            'lastLogon': [datetime.now() - timedelta(days=1)]
        }
        risk = security_tools._assess_account_risk(medium_risk_account)
        assert risk == 'medium'
        
        # Low risk: Regular user
        low_risk_account = {
            'memberOf': ['CN=Domain Users,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=15)],
            'lastLogon': [datetime.now()]
        }
        risk = security_tools._assess_account_risk(low_risk_account)
        assert risk == 'low'
    
    def test_password_age_calculation(self, security_tools):
        """Test password age calculation."""
        # Test recent password
        recent_date = datetime.now() - timedelta(days=10)
        age = security_tools._calculate_password_age({'pwdLastSet': [recent_date]})
        assert age == 10
        
        # Test old password
        old_date = datetime.now() - timedelta(days=365)
        age = security_tools._calculate_password_age({'pwdLastSet': [old_date]})
        assert age == 365
        
        # Test never set password
        age = security_tools._calculate_password_age({'pwdLastSet': [None]})
        assert age == -1
        
        # Test missing attribute
        age = security_tools._calculate_password_age({})
        assert age == -1
    
    def test_is_privileged_group(self, security_tools):
        """Test privileged group detection."""
        # Test high-privilege groups
        assert security_tools._is_privileged_group('Domain Admins') == True
        assert security_tools._is_privileged_group('Enterprise Admins') == True
        assert security_tools._is_privileged_group('Schema Admins') == True
        assert security_tools._is_privileged_group('Backup Operators') == True
        
        # Test regular groups
        assert security_tools._is_privileged_group('Domain Users') == False
        assert security_tools._is_privileged_group('Sales Team') == False
        assert security_tools._is_privileged_group('Regular Group') == False
    
    def test_ldap_error_handling(self, security_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test get_domain_info with error
        result = security_tools.get_domain_info()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, security_tools):
        """Test schema information retrieval."""
        schema = security_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'security_attributes' in schema
        assert 'risk_levels' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations (real registered/available method names)
        operations = schema['operations']
        assert 'get_domain_info' in operations
        assert 'get_privileged_groups' in operations
        assert 'get_user_permissions' in operations
        assert 'get_inactive_users' in operations
        assert 'get_password_policy_violations' in operations
        assert 'audit_admin_accounts' in operations

        # Check risk levels (schema reports them lowercase)
        assert 'low' in schema['risk_levels']
        assert 'medium' in schema['risk_levels']
        assert 'high' in schema['risk_levels']
        assert 'critical' in schema['risk_levels']


# Methods deleted in WP2 because they returned hardcoded sample findings with no
# LDAP query behind them. Real equivalents (ACL analysis via nTSecurityDescriptor,
# a service-account audit via SPN/encryption types/password age) are Phase-2
# directory-state controls and must be built deliberately, not resurrected here.
DELETED_FABRICATED_METHODS = [
    'find_weak_passwords',
    'analyze_permissions',
    'detect_privilege_escalation',
    'check_service_accounts',
]


@pytest.mark.parametrize('method_name', DELETED_FABRICATED_METHODS)
def test_fabricating_methods_stay_deleted(method_name):
    """The fabricating stubs must not come back, and must not be in the schema."""
    assert not hasattr(SecurityTools, method_name), (
        f"{method_name} was deleted in WP2 as a fabrication; do not reintroduce it"
    )


def test_schema_operations_list_has_no_deleted_methods(security_tools):
    """get_schema_info must advertise only methods that actually exist."""
    operations = security_tools.get_schema_info()['operations']
    for method_name in DELETED_FABRICATED_METHODS:
        assert method_name not in operations
    for operation in operations:
        assert hasattr(security_tools, operation), (
            f"schema advertises {operation}, which SecurityTools does not implement"
        )

