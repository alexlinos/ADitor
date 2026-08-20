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

        # P2-WP6 re-rated this fixture. Nothing in it is reachable by an
        # attacker today - no PASSWD_NOTREQD, no SPN, no decade-old password -
        # so nothing here is HIGH. See TestAdminRiskLevel for the full ladder.
        assert response_data['high_risk_count'] == 0
        assert response_data['medium_risk_count'] == 1
        assert response_data['low_risk_count'] == 2

        # Verify specific accounts (real output keys)
        accounts = {acc['sam_account_name']: acc for acc in response_data['admin_accounts']}

        # Built-in administrator should be enabled and low risk (no security issues)
        admin = accounts['Administrator']
        assert admin['enabled'] == True
        assert admin['risk_level'] == 'LOW'

        # 120 days idle: reported, but a 90-179 day gap does not escalate.
        stale = accounts['admin.user']
        assert stale['risk_level'] == 'LOW'
        assert 'No logon for 120 days' in stale['security_issues']

        # A non-expiring password on an enabled account is MEDIUM: it defeats
        # the domain maximum password age, but it is not a way in.
        svc_admin = accounts['svc.admin']
        assert svc_admin['risk_level'] == 'MEDIUM'
        assert 'Password never expires' in svc_admin['security_issues']
        assert svc_admin['risk_drivers'], 'a rating must say what drove it'

        # Highest risk first, so the list is a priority order.
        levels = [acc['risk_level'] for acc in response_data['admin_accounts']]
        assert levels == sorted(levels, key=lambda l: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[l])
    
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


def _domain_entry(min_pwd_length, pwd_history_length):
    """One mock domain object with the given password-policy attributes.

    Everything flows through the real get_domain_info(), so these tests exercise
    the produce/consume contract between the two methods rather than a
    hand-written policy dict.
    """
    return [
        {
            'dn': 'DC=test,DC=local',
            'attributes': {
                'name': ['test'],
                'dc': ['test'],
                'objectSid': [b'\x01\x05\x00\x00\x00\x00\x00\x05'],
                'whenCreated': [datetime.now() - timedelta(days=365)],
                'whenChanged': [datetime.now() - timedelta(days=1)],
                'lockoutThreshold': [5],
                'lockoutDuration': [-18000000000],
                'maxPwdAge': [-36288000000000],
                'minPwdAge': [-864000000000],
                'minPwdLength': [min_pwd_length],
                'pwdHistoryLength': [pwd_history_length],
            }
        }
    ]


class TestCheckPasswordPolicy:
    """check_password_policy must evaluate the keys get_domain_info emits.

    The historical bug: it read 'min_length' / 'history_length' (never emitted)
    and 'lockout_policy' at the top level (never emitted), so every policy came
    back non-compliant, and it passed a bool as the response payload.
    """

    def test_produced_and_consumed_key_names_match(self, security_tools, mock_ldap_manager):
        """get_domain_info's password_policy keys are the ones checked."""
        mock_ldap_manager.search.return_value = _domain_entry(14, 24)

        policy = json.loads(security_tools.get_domain_info()[0].text)['password_policy']
        assert 'min_password_length' in policy
        assert 'password_history_length' in policy
        # The keys the old implementation read do not exist.
        assert 'min_length' not in policy
        assert 'history_length' not in policy

        report = json.loads(security_tools.check_password_policy()[0].text)
        checked = {check['attribute'] for check in report['checks']}
        assert checked == {'min_password_length', 'password_history_length'}

    def test_compliant_policy(self, security_tools, mock_ldap_manager):
        """A policy meeting both thresholds reports compliant with no advice."""
        mock_ldap_manager.search.return_value = _domain_entry(14, 24)

        result = security_tools.check_password_policy()

        # Consistent with every other tool: List[Content], JSON payload.
        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        report = json.loads(result[0].text)
        assert report['policy_compliant'] is True
        assert report['recommendations'] == []
        assert all(check['passed'] for check in report['checks'])
        assert report['password_policy']['min_password_length'] == 14
        assert report['password_policy']['password_history_length'] == 24
        # Lockout settings are reported for context, sourced from the real keys.
        assert report['lockout_policy']['lockout_threshold'] == 5

    def test_non_compliant_policy(self, security_tools, mock_ldap_manager):
        """A policy failing both thresholds reports both failures."""
        mock_ldap_manager.search.return_value = _domain_entry(6, 2)

        report = json.loads(security_tools.check_password_policy()[0].text)

        assert report['policy_compliant'] is False
        checks = {check['check']: check for check in report['checks']}
        assert checks['minimum_password_length']['passed'] is False
        assert checks['minimum_password_length']['actual'] == 6
        assert checks['password_history_length']['passed'] is False
        assert checks['password_history_length']['actual'] == 2
        assert len(report['recommendations']) == 2

    def test_mixed_policy_length_passes_history_fails(self, security_tools, mock_ldap_manager):
        """Each threshold is judged independently, not as one blanket verdict."""
        mock_ldap_manager.search.return_value = _domain_entry(12, 3)

        report = json.loads(security_tools.check_password_policy()[0].text)

        checks = {check['check']: check for check in report['checks']}
        assert checks['minimum_password_length']['passed'] is True
        assert checks['password_history_length']['passed'] is False
        assert report['policy_compliant'] is False
        assert len(report['recommendations']) == 1
        assert 'history' in report['recommendations'][0].lower()

    def test_boundary_values_are_compliant(self, security_tools, mock_ldap_manager):
        """The thresholds are inclusive minimums (>= 8 characters, >= 5 remembered)."""
        mock_ldap_manager.search.return_value = _domain_entry(
            SecurityTools.MIN_PASSWORD_LENGTH, SecurityTools.MIN_PASSWORD_HISTORY
        )

        report = json.loads(security_tools.check_password_policy()[0].text)

        assert report['policy_compliant'] is True

    def test_payload_is_the_report_not_a_bool(self, security_tools, mock_ldap_manager):
        """Regression: the payload used to be the literal string 'True'."""
        mock_ldap_manager.search.return_value = _domain_entry(14, 24)

        text = security_tools.check_password_policy()[0].text

        assert text.strip() not in ('True', 'False')
        assert isinstance(json.loads(text), dict)

    def test_error_from_domain_info_is_propagated(self, security_tools, mock_ldap_manager):
        """An LDAP failure surfaces as an error payload, not a fake verdict."""
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")

        result = security_tools.check_password_policy()

        assert len(result) == 1
        report = json.loads(result[0].text)
        assert report['success'] is False
        assert 'policy_compliant' not in report


class TestGenerateSecurityReport:
    """Prototype aggregator: kept, unregistered, and score-free."""

    def _content(self, payload):
        return [TextContent(type="text", text=json.dumps(payload))]

    def test_report_aggregates_without_a_score(self, security_tools):
        """Reports are pass/fail evidence: no invented aggregate score."""
        with patch.object(security_tools, 'get_domain_info',
                          return_value=self._content({'name': 'test'})), \
             patch.object(security_tools, 'audit_admin_accounts',
                          return_value=self._content({'total_admin_accounts': 3,
                                                      'high_risk_count': 1})), \
             patch.object(security_tools, 'get_privileged_groups',
                          return_value=self._content({'total_groups': 6})), \
             patch.object(security_tools, 'check_password_policy',
                          return_value=self._content({'policy_compliant': False})):
            result = security_tools.generate_security_report()

        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        report = json.loads(result[0].text)
        summary = report['executive_summary']
        assert 'overall_security_score' not in summary
        assert summary['total_admin_accounts'] == 3
        assert summary['high_risk_admin_accounts'] == 1
        assert summary['total_privileged_groups'] == 6
        assert summary['password_policy_compliant'] is False
        assert 'password_policy_assessment' in report['detailed_findings']
        assert report['recommendations']


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



# ---------------------------------------------------------------------------
# get_password_policy_violations (P2-WP6 Fix 1)
# ---------------------------------------------------------------------------

# userAccountControl bits, spelled out so the fixtures read as intent.
UAC_NORMAL_ACCOUNT = 0x0200        # 512
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_WORKSTATION_TRUST = 0x1000     # what a computer account carries

# 42 days expressed as AD's negative 100-nanosecond interval.
MAX_PWD_AGE_42_DAYS = -36288000000000


def _violation_user(sam, *, uac=UAC_NORMAL_ACCOUNT, pwd_age_days=10,
                    object_classes=('top', 'person', 'organizationalPerson', 'user'),
                    dn=None):
    """One synthetic directory entry for get_password_policy_violations.

    Names are invented (DC=test,DC=local); nothing here comes from a real domain.
    """
    attributes = {
        'sAMAccountName': [sam],
        'displayName': [sam],
        'objectClass': list(object_classes),
        'userAccountControl': [uac],
        'accountExpires': [0],
    }
    if pwd_age_days is None:
        attributes['pwdLastSet'] = [0]
    else:
        attributes['pwdLastSet'] = [datetime.now() - timedelta(days=pwd_age_days)]
    return {'dn': dn or f'CN={sam},OU=Accounts,DC=test,DC=local', 'attributes': attributes}


def _violations_search(users, max_pwd_age=MAX_PWD_AGE_42_DAYS):
    """search() side effect: the domain policy first, then the given user set.

    The mock deliberately returns `users` whatever the user search filter is, so
    the tests prove the tool excludes the wrong objects itself rather than
    relying on the directory to have honoured the filter.
    """
    def side_effect(*args, **kwargs):
        if 'objectClass=domain' in kwargs.get('search_filter', ''):
            return [{
                'dn': 'DC=test,DC=local',
                'attributes': {'maxPwdAge': [max_pwd_age], 'minPwdAge': [-864000000000]},
            }]
        return users
    return side_effect


def _violations_payload(security_tools, mock_ldap_manager, users, **kwargs):
    mock_ldap_manager.search.side_effect = _violations_search(users)
    result = security_tools.get_password_policy_violations(**kwargs)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


class TestPasswordExpiryIsNotClaimedForExemptAccounts:
    """Fix 1a: DONT_EXPIRE_PASSWORD exempts an account from maxPwdAge."""

    def test_never_expire_account_with_old_password_is_not_also_expired(
            self, security_tools, mock_ldap_manager):
        """The exact contradictory pair seen live: both findings on one account."""
        user = _violation_user('svc.exempt',
                               uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                               pwd_age_days=500)  # far past the 42-day maximum
        payload = _violations_payload(security_tools, mock_ldap_manager, [user])

        assert payload['count'] == 1
        violations = payload['password_violations'][0]['violations']
        assert 'Password set to never expire' in violations
        assert 'Password expired' not in violations
        assert payload['excluded_counts']['exempt_from_expiry'] == 1

    def test_expired_password_is_still_reported_without_the_exemption(
            self, security_tools, mock_ldap_manager):
        """Control case: the same old password without DONT_EXPIRE_PASSWORD."""
        user = _violation_user('user.expired', pwd_age_days=500)
        payload = _violations_payload(security_tools, mock_ldap_manager, [user])

        violations = payload['password_violations'][0]['violations']
        assert 'Password expired' in violations
        assert 'Password set to never expire' not in violations
        assert payload['excluded_counts']['exempt_from_expiry'] == 0

    def test_no_account_carries_both_findings(self, security_tools, mock_ldap_manager):
        """Asserted directly over a mixed set: the pair must be unreachable."""
        users = [
            _violation_user('user.fresh', pwd_age_days=3),
            _violation_user('user.expired', pwd_age_days=500),
            _violation_user('svc.exempt.old',
                            uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                            pwd_age_days=4000),
            _violation_user('svc.exempt.fresh',
                            uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                            pwd_age_days=3),
            _violation_user('user.notreqd',
                            uac=UAC_NORMAL_ACCOUNT | UAC_PASSWD_NOTREQD,
                            pwd_age_days=500),
            _violation_user('user.nopassword', pwd_age_days=None),
        ]
        payload = _violations_payload(security_tools, mock_ldap_manager, users)

        assert payload['password_violations'], 'fixture should produce findings'
        for account in payload['password_violations']:
            violations = account['violations']
            assert not ('Password expired' in violations
                        and 'Password set to never expire' in violations), (
                f"{account['sam_account_name']} reports a contradictory pair: {violations}"
            )

    def test_exempt_account_drops_out_when_expiry_was_its_only_finding(
            self, security_tools, mock_ldap_manager):
        """maxPwdAge unset domain-wide: never-expire is not a finding either."""
        user = _violation_user('svc.exempt',
                               uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                               pwd_age_days=500)
        mock_ldap_manager.search.side_effect = _violations_search([user], max_pwd_age=0)
        payload = json.loads(security_tools.get_password_policy_violations()[0].text)

        assert payload['count'] == 0
        assert payload['excluded_counts']['exempt_from_expiry'] == 0


class TestComputerAccountsAreNotAPasswordPolicyFinding:
    """Fix 1b: `(objectClass=user)` also matches computers in AD."""

    def test_machine_account_is_excluded_and_the_user_is_kept(
            self, security_tools, mock_ldap_manager):
        machine = _violation_user(
            'WKSTN01$',
            uac=UAC_WORKSTATION_TRUST | UAC_DONT_EXPIRE_PASSWORD,
            pwd_age_days=500,
            object_classes=('top', 'person', 'organizationalPerson', 'user', 'computer'),
            dn='CN=WKSTN01,CN=Computers,DC=test,DC=local',
        )
        person = _violation_user('user.expired', pwd_age_days=500)
        payload = _violations_payload(security_tools, mock_ldap_manager, [machine, person])

        assert [acc['sam_account_name'] for acc in payload['password_violations']] == \
            ['user.expired']
        assert payload['count'] == 1
        assert payload['excluded_counts']['computer_accounts'] == 1

    def test_machine_account_recognised_by_trailing_dollar_alone(
            self, security_tools, mock_ldap_manager):
        """An entry without objectClass still must not be reported as a user."""
        machine = _violation_user('SRV02$', pwd_age_days=500, object_classes=())
        payload = _violations_payload(security_tools, mock_ldap_manager, [machine])

        assert payload['count'] == 0
        assert payload['excluded_counts']['computer_accounts'] == 1

    def test_search_filter_excludes_computers_at_the_directory(
            self, security_tools, mock_ldap_manager):
        """The query itself must not ask for computers."""
        _violations_payload(security_tools, mock_ldap_manager,
                            [_violation_user('user.fresh', pwd_age_days=1)])

        user_filters = [
            call.kwargs['search_filter']
            for call in mock_ldap_manager.search.call_args_list
            if 'objectClass=domain' not in call.kwargs.get('search_filter', '')
        ]
        assert user_filters, 'expected a user search'
        for search_filter in user_filters:
            assert 'objectCategory=person' in search_filter
            assert search_filter != '(objectClass=user)'


class TestDisabledAccountsAreExcludedByDefault:
    """Fix 1c: 328 of the live domain's 545 hits were disabled accounts."""

    def _mixed_fixture(self):
        return [
            _violation_user('user.enabled', pwd_age_days=500),
            _violation_user('user.disabled',
                            uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE,
                            pwd_age_days=500),
            _violation_user('user.disabled.notreqd',
                            uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE | UAC_PASSWD_NOTREQD,
                            pwd_age_days=500),
        ]

    def test_default_excludes_disabled(self, security_tools, mock_ldap_manager):
        payload = _violations_payload(security_tools, mock_ldap_manager, self._mixed_fixture())

        assert [acc['sam_account_name'] for acc in payload['password_violations']] == \
            ['user.enabled']
        assert payload['include_disabled'] is False
        assert payload['excluded_counts']['disabled_accounts'] == 2
        assert payload['accounts_examined'] == 1

    def test_opt_in_restores_disabled(self, security_tools, mock_ldap_manager):
        payload = _violations_payload(security_tools, mock_ldap_manager,
                                      self._mixed_fixture(), include_disabled=True)

        assert len(payload['password_violations']) == 3
        assert payload['include_disabled'] is True
        assert payload['excluded_counts']['disabled_accounts'] == 0
        assert payload['accounts_examined'] == 3

    def test_default_is_the_signature_default(self):
        import inspect
        signature = inspect.signature(SecurityTools.get_password_policy_violations)
        parameter = signature.parameters['include_disabled']
        assert parameter.default is False
        assert parameter.annotation is bool

    def test_excluded_counts_distinguish_filtering_from_a_clean_domain(
            self, security_tools, mock_ldap_manager):
        """An empty list plus zero exclusions is the only 'clean domain' answer."""
        clean = _violations_payload(security_tools, mock_ldap_manager,
                                    [_violation_user('user.fine', pwd_age_days=3)])
        assert clean['count'] == 0
        assert set(clean['excluded_counts'].values()) == {0}

        filtered = _violations_payload(security_tools, mock_ldap_manager, [
            _violation_user('user.disabled',
                            uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE,
                            pwd_age_days=500),
            _violation_user('WKSTN01$', pwd_age_days=500, object_classes=('computer',)),
            _violation_user('svc.exempt',
                            uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                            pwd_age_days=500),
        ])
        assert filtered['excluded_counts'] == {
            'disabled_accounts': 1,
            'computer_accounts': 1,
            'exempt_from_expiry': 1,
        }
        assert filtered['notes'], 'excluded_counts must be explained in the payload'

    def test_schema_info_advertises_the_new_parameter(self, security_tools):
        parameters = security_tools.get_schema_info()['operation_parameters']
        assert 'include_disabled' in parameters['get_password_policy_violations']


# ---------------------------------------------------------------------------
# audit_admin_accounts risk model (P2-WP6 Fix 2)
# ---------------------------------------------------------------------------


class TestAdminRiskLevel:
    """Fix 2: a rating that is HIGH for every account tells the reader nothing.

    These call _calculate_admin_risk_level directly, over the combinations that
    the old model collapsed.
    """

    @pytest.mark.parametrize('facts,expected', [
        # --- nothing found -------------------------------------------------
        ({'enabled': True}, 'LOW'),
        ({'enabled': True, 'password_age_days': 30, 'days_since_logon': 1}, 'LOW'),

        # --- 2a: never-expire alone is MEDIUM, not HIGH --------------------
        ({'enabled': True, 'password_never_expires': True}, 'MEDIUM'),
        ({'enabled': True, 'password_never_expires': True,
          'password_age_days': 90}, 'MEDIUM'),
        # ...but age discriminates within it: an eleven-year-old credential.
        ({'enabled': True, 'password_never_expires': True,
          'password_age_days': 4015}, 'HIGH'),

        # --- 2b: disabled is informational, never HIGH ---------------------
        ({'enabled': False}, 'LOW'),
        ({'enabled': False, 'password_never_expires': True}, 'LOW'),
        # The whole point of 2b: disabled must not outrank an enabled account
        # with no password required.
        ({'enabled': False, 'password_not_required': True}, 'LOW'),
        ({'enabled': False, 'has_spn': True, 'password_age_days': 4015,
          'days_since_logon': 4000}, 'LOW'),

        # --- HIGH: reachable today -----------------------------------------
        ({'enabled': True, 'password_not_required': True}, 'HIGH'),
        ({'enabled': True, 'password_not_required': True,
          'password_age_days': 1}, 'HIGH'),
        # Kerberoastable: SPN plus an old password.
        ({'enabled': True, 'has_spn': True, 'password_age_days': 400}, 'HIGH'),
        ({'enabled': True, 'has_spn': True, 'password_never_expires': True,
          'password_age_days': 900}, 'HIGH'),

        # --- MEDIUM --------------------------------------------------------
        # An SPN on a privileged account still matters, but a fresh password
        # means offline cracking is the limiting factor.
        ({'enabled': True, 'has_spn': True, 'password_age_days': 30}, 'MEDIUM'),
        # pwdLastSet unset: the age is unknown, so do not claim the HIGH case.
        ({'enabled': True, 'has_spn': True, 'password_age_days': None}, 'MEDIUM'),
        ({'enabled': True, 'days_since_logon': 200}, 'MEDIUM'),

        # --- staleness below the escalation threshold ----------------------
        ({'enabled': True, 'days_since_logon': 120}, 'LOW'),
        ({'enabled': True, 'days_since_logon': 89}, 'LOW'),

        # --- thresholds are exact ------------------------------------------
        ({'enabled': True, 'has_spn': True, 'password_age_days': 365}, 'HIGH'),
        ({'enabled': True, 'has_spn': True, 'password_age_days': 364}, 'MEDIUM'),
        ({'enabled': True, 'password_never_expires': True,
          'password_age_days': 1825}, 'HIGH'),
        ({'enabled': True, 'password_never_expires': True,
          'password_age_days': 1824}, 'MEDIUM'),
        ({'enabled': True, 'days_since_logon': 180}, 'MEDIUM'),
        ({'enabled': True, 'days_since_logon': 179}, 'LOW'),
    ])
    def test_risk_level(self, security_tools, facts, expected):
        assert security_tools._calculate_admin_risk_level(**facts) == expected

    def test_never_expire_alone_is_not_high(self, security_tools):
        """2a in isolation: the medium branch used to return HIGH."""
        assert security_tools._calculate_admin_risk_level(
            enabled=True, password_never_expires=True) == 'MEDIUM'

    def test_password_not_required_outranks_disabled(self, security_tools):
        """2b: exploitable beats untidy."""
        exploitable = security_tools._calculate_admin_risk_level(
            enabled=True, password_not_required=True)
        untidy = security_tools._calculate_admin_risk_level(
            enabled=False, password_not_required=True)
        order = SecurityTools.ADMIN_RISK_ORDER
        assert order[exploitable] < order[untidy]

    def test_the_dead_medium_branch_is_gone(self):
        """2c: `return "MEDIUM" if security_issues else "LOW"` was unreachable."""
        import inspect
        source = (inspect.getsource(SecurityTools._assess_admin_risk)
                  + inspect.getsource(SecurityTools._calculate_admin_risk_level))
        assert 'if security_issues else' not in source
        # The model must not rate on the English of the finding strings either.
        assert 'high_risk_issues' not in source
        assert 'medium_risk_issues' not in source

    def test_low_is_reachable_beyond_the_empty_case(self, security_tools):
        """The dead branch made LOW unreachable once anything was found."""
        assert security_tools._calculate_admin_risk_level(
            enabled=True, days_since_logon=120) == 'LOW'
        assert security_tools._admin_security_issues(
            enabled=True, days_since_logon=120) == ['No logon for 120 days']

    @pytest.mark.parametrize('facts', [
        {'enabled': True, 'password_not_required': True},
        {'enabled': True, 'password_never_expires': True},
        {'enabled': True, 'has_spn': True, 'password_age_days': 400},
        {'enabled': True, 'days_since_logon': 200},
        {'enabled': False},
    ])
    def test_every_rating_says_what_drove_it(self, security_tools, facts):
        assert security_tools._assess_admin_risk(**facts)['drivers']


def _admin_entry(sam, *, uac=UAC_NORMAL_ACCOUNT, pwd_age_days=30,
                 logon_days_ago=1, spns=()):
    """One synthetic privileged account. Invented names, DC=test,DC=local."""
    dn = f'CN={sam},OU=Admins,DC=test,DC=local'
    attributes = {
        'sAMAccountName': [sam],
        'displayName': [sam],
        'userAccountControl': [uac],
        'lastLogon': [datetime.now() - timedelta(days=logon_days_ago)],
        'pwdLastSet': [datetime.now() - timedelta(days=pwd_age_days)],
    }
    if spns:
        attributes['servicePrincipalName'] = list(spns)
    return dn, attributes


def _admin_audit_payload(security_tools, mock_ldap_manager, entries):
    users_by_dn = {dn: [{'dn': dn, 'attributes': attrs}] for dn, attrs in entries}

    def side_effect(*args, **kwargs):
        search_filter = kwargs.get('search_filter', '')
        if 'objectClass=group' in search_filter:
            if 'sAMAccountName=Domain Admins' in search_filter:
                return [{
                    'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                    'attributes': {'member': list(users_by_dn)},
                }]
            return []
        return users_by_dn.get(kwargs.get('search_base', ''), [])

    mock_ldap_manager.search.side_effect = side_effect
    result = security_tools.audit_admin_accounts()
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


class TestAdminRiskDiscriminates:
    """Fix 2, end to end: the regression that mattered was a flat rating."""

    def _admins_differing_only_in_these_attributes(self):
        # Same shape of account throughout; only the attributes the model reads
        # differ, so any spread in the ratings comes from the model.
        return [
            _admin_entry('adm.clean'),
            _admin_entry('adm.neverexpires',
                         uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD),
            _admin_entry('adm.notreqd',
                         uac=UAC_NORMAL_ACCOUNT | UAC_PASSWD_NOTREQD),
            _admin_entry('adm.kerberoastable',
                         spns=('TEST/svc.test.local',), pwd_age_days=900),
            _admin_entry('adm.idle', logon_days_ago=400),
            _admin_entry('adm.disabled',
                         uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE
                             | UAC_PASSWD_NOTREQD),
        ]

    def test_more_than_one_risk_level_is_produced(self, security_tools, mock_ldap_manager):
        payload = _admin_audit_payload(security_tools, mock_ldap_manager,
                                       self._admins_differing_only_in_these_attributes())

        levels = {acc['sam_account_name']: acc['risk_level']
                  for acc in payload['admin_accounts']}
        assert len(set(levels.values())) > 1, (
            f'the rating must discriminate, got {levels}'
        )
        # In fact all three, which is the point of the exercise.
        assert set(levels.values()) == {'HIGH', 'MEDIUM', 'LOW'}
        assert levels == {
            'adm.clean': 'LOW',
            'adm.disabled': 'LOW',
            'adm.idle': 'MEDIUM',
            'adm.neverexpires': 'MEDIUM',
            'adm.notreqd': 'HIGH',
            'adm.kerberoastable': 'HIGH',
        }
        assert payload['high_risk_count'] == 2
        assert payload['medium_risk_count'] == 2
        assert payload['low_risk_count'] == 2

    def test_high_risk_first(self, security_tools, mock_ldap_manager):
        payload = _admin_audit_payload(security_tools, mock_ldap_manager,
                                       self._admins_differing_only_in_these_attributes())
        levels = [acc['risk_level'] for acc in payload['admin_accounts']]
        assert levels[:2] == ['HIGH', 'HIGH']
        assert levels[-2:] == ['LOW', 'LOW']

    def test_disabled_admin_is_reported_but_not_high(self, security_tools, mock_ldap_manager):
        """It should be removed from the group; it is not a live exposure."""
        payload = _admin_audit_payload(security_tools, mock_ldap_manager,
                                       self._admins_differing_only_in_these_attributes())
        disabled = next(acc for acc in payload['admin_accounts']
                        if acc['sam_account_name'] == 'adm.disabled')
        assert disabled['risk_level'] == 'LOW'
        assert 'Account disabled' in disabled['security_issues']
        assert 'Password not required' in disabled['security_issues']
        assert 'disabled' in disabled['risk_drivers'][0]

    def test_password_age_and_spn_are_carried_in_the_payload(
            self, security_tools, mock_ldap_manager):
        """A HIGH kerberoasting verdict has to show its evidence."""
        payload = _admin_audit_payload(security_tools, mock_ldap_manager,
                                       self._admins_differing_only_in_these_attributes())
        roastable = next(acc for acc in payload['admin_accounts']
                         if acc['sam_account_name'] == 'adm.kerberoastable')
        assert roastable['spn_count'] == 1
        assert roastable['password_age_days'] == 900
        assert roastable['password_last_set'] != 'Never'
        assert any('erberoast' in driver for driver in roastable['risk_drivers'])

    def test_payload_states_the_model_and_its_caveats(self, security_tools, mock_ldap_manager):
        payload = _admin_audit_payload(security_tools, mock_ldap_manager,
                                       [_admin_entry('adm.clean')])
        model = payload['risk_model']
        assert model['levels'] == ['HIGH', 'MEDIUM', 'LOW']
        assert model['HIGH'] and model['MEDIUM'] and model['LOW']
        # lastLogon is per-DC and not replicated: the audit must say so rather
        # than presenting days_since_logon as fact (WP6 out-of-scope follow-up).
        assert any('not replicated' in caveat for caveat in model['caveats'])

    def test_never_set_password_does_not_become_an_age(
            self, security_tools, mock_ldap_manager):
        dn, attributes = _admin_entry('adm.mustchange')
        attributes['pwdLastSet'] = [0]
        payload = _admin_audit_payload(security_tools, mock_ldap_manager, [(dn, attributes)])

        account = payload['admin_accounts'][0]
        assert account['password_age_days'] is None
        assert account['password_last_set'] == 'Never'


def test_schema_info_states_the_admin_risk_model(security_tools):
    """A caller has to be able to read the levels without reading the source."""
    schema = security_tools.get_schema_info()
    model = schema['admin_risk_model']
    assert model['levels'] == ['HIGH', 'MEDIUM', 'LOW']
    # The out-of-scope lastLogon replication bug must be disclosed, not implied.
    assert any('not replicated' in note for note in schema['notes'])
