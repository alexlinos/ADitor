"""Tests for organizational unit management tools."""

import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime, timedelta

from aditor.tools.organizational_unit import OrganizationalUnitTools
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
def ou_tools(mock_ldap_manager):
    """OU tools instance for testing."""
    return OrganizationalUnitTools(mock_ldap_manager)


class TestOrganizationalUnitTools:
    """Test organizational unit management functionality."""
    
    def test_list_organizational_units_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU listing."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'OU=Users,DC=test,DC=local',
                'attributes': {
                    'name': ['Users'],
                    'description': ['Default Users container'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=30)],
                    'managedBy': ['CN=OU Manager,OU=Users,DC=test,DC=local'],
                    'gPLink': ['[LDAP://cn={12345678-1234-1234-1234-123456789ABC},cn=policies,cn=system,DC=test,DC=local;0]'],
                    'ou': ['Users']
                }
            },
            {
                'dn': 'OU=Computers,DC=test,DC=local',
                'attributes': {
                    'name': ['Computers'],
                    'description': ['Default Computers container'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=60)],
                    'ou': ['Computers']
                }
            },
            {
                'dn': 'OU=Sales,OU=Departments,DC=test,DC=local',
                'attributes': {
                    'name': ['Sales'],
                    'description': ['Sales department organizational unit'],
                    'whenCreated': [datetime.now() - timedelta(days=180)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'managedBy': ['CN=Sales Manager,OU=Users,DC=test,DC=local'],
                    'ou': ['Sales']
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test list_organizational_units
        result = ou_tools.list_organizational_units()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['count'] == 3
        assert len(response_data['organizational_units']) == 3
        
        # Check the Users OU (results are sorted by level then name, not input order)
        ou1 = next(ou for ou in response_data['organizational_units'] if ou['name'] == 'Users')
        assert ou1['description'] == 'Default Users container'
        assert ou1['dn'] == 'OU=Users,DC=test,DC=local'
        assert 'linkedGPOs' in ou1 and len(ou1['linkedGPOs']) >= 1
        
        # Check nested OU
        sales_ou = next(ou for ou in response_data['organizational_units'] if ou['name'] == 'Sales')
        assert 'OU=Departments' in sales_ou['dn']  # Should be nested under Departments
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU retrieval."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'OU=Sales,OU=Departments,DC=test,DC=local',
                'attributes': {
                    'name': ['Sales'],
                    'description': ['Sales department organizational unit'],
                    'whenCreated': [datetime.now() - timedelta(days=180)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'managedBy': ['CN=Sales Manager,OU=Users,DC=test,DC=local'],
                    'gPLink': [
                        '[LDAP://cn={12345678-1234-1234-1234-123456789ABC},cn=policies,cn=system,DC=test,DC=local;0]',
                        '[LDAP://cn={87654321-4321-4321-4321-CBA987654321},cn=policies,cn=system,DC=test,DC=local;0]'
                    ],
                    'ou': ['Sales'],
                    'street': ['123 Business Ave'],
                    'l': ['Business City'],  # locality
                    'postalCode': ['12345'],
                    'c': ['US']  # country
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_organizational_unit
        result = ou_tools.get_organizational_unit('OU=Sales,OU=Departments,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['dn'] == 'OU=Sales,OU=Departments,DC=test,DC=local'
        assert response_data['attributes']['name'] == ['Sales']
        
        # Check computed fields (get_ou parses only the first gPLink value)
        computed = response_data['computed']
        assert len(computed['linked_gpos']) == 1
        # Location and management info live in the raw attributes
        assert response_data['attributes']['l'] == ['Business City']
        assert response_data['attributes']['managedBy'] == ['CN=Sales Manager,OU=Users,DC=test,DC=local']
        
        # get_ou also issues follow-up count queries; verify the primary lookup happened
        mock_ldap_manager.search.assert_called()
        first_call = mock_ldap_manager.search.call_args_list[0]
        assert first_call[1]['search_base'] == 'OU=Sales,OU=Departments,DC=test,DC=local'
    
    def test_get_organizational_unit_not_found(self, ou_tools, mock_ldap_manager):
        """Test OU not found scenario."""
        # Mock empty search results
        mock_ldap_manager.search.return_value = []
        
        # Test get_organizational_unit
        result = ou_tools.get_organizational_unit('OU=NonExistent,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'not found' in response_data['error']
    
    def test_create_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU creation."""
        # Mock search for existing OU (empty result)
        mock_ldap_manager.search.return_value = []
        
        # Mock successful LDAP add operation
        mock_ldap_manager.add.return_value = True
        
        # Test create_ou (the registered create_organizational_unit tool)
        result = ou_tools.create_ou(
            name='Marketing',
            parent_ou='OU=Departments,DC=test,DC=local',
            description='Marketing department OU',
            managed_by='CN=Marketing Manager,OU=Users,DC=test,DC=local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert response_data['ou_name'] == 'Marketing'
        assert response_data['dn'] == 'OU=Marketing,OU=Departments,DC=test,DC=local'
        assert response_data['parent_ou'] == 'OU=Departments,DC=test,DC=local'

        # Verify LDAP operations were called
        mock_ldap_manager.search.assert_called()  # Check for existing OU
        mock_ldap_manager.add.assert_called_once()  # Create OU

        # Verify attributes passed to add operation (add is called positionally)
        add_call = mock_ldap_manager.add.call_args
        attributes = add_call[0][1]
        assert attributes['objectClass'] == ['top', 'organizationalUnit']
        assert attributes['ou'] == 'Marketing'
        assert attributes['description'] == 'Marketing department OU'
        assert attributes['managedBy'] == 'CN=Marketing Manager,OU=Users,DC=test,DC=local'
    
    def test_create_organizational_unit_already_exists(self, ou_tools, mock_ldap_manager):
        """Test OU creation when OU already exists."""
        # Mock search for existing OU (OU found)
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=Existing,OU=Departments,DC=test,DC=local'}
        ]
        
        # Test create_ou (the registered create_organizational_unit tool)
        result = ou_tools.create_ou(
            name='Existing',
            parent_ou='OU=Departments,DC=test,DC=local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'already exists' in response_data['error']
        
        # Verify no add operation was called
        mock_ldap_manager.add.assert_not_called()
    
    def test_modify_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU modification."""
        # Mock search for OU
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=TestOU,DC=test,DC=local'}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test modify_organizational_unit
        attributes = {
            'description': 'Updated description',
            'managedBy': 'CN=New Manager,OU=Users,DC=test,DC=local',
            'street': '456 New Address',
            'l': 'New City'
        }
        result = ou_tools.modify_ou('OU=TestOU,DC=test,DC=local', attributes)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'modified successfully' in response_data['message']
        assert set(response_data['modified_attributes']) == set(attributes.keys())
        
        # Verify LDAP modify was called
        mock_ldap_manager.modify.assert_called_once()
    
    def test_delete_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU deletion."""
        # Mock search for OU (empty - no child objects)
        mock_ldap_manager.search.side_effect = [
            [{'dn': 'OU=EmptyOU,DC=test,DC=local'}],  # OU exists
            []  # No child objects
        ]
        
        # Mock successful delete operation
        mock_ldap_manager.delete.return_value = True
        
        # Test delete_ou (the registered delete_organizational_unit tool)
        result = ou_tools.delete_ou('OU=EmptyOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'deleted successfully' in response_data['message']
        
        # Verify LDAP operations were called
        assert mock_ldap_manager.search.call_count == 2  # Check OU exists + check for children
        mock_ldap_manager.delete.assert_called_once()
    
    def test_delete_organizational_unit_not_empty(self, ou_tools, mock_ldap_manager):
        """Test OU deletion when OU contains child objects."""
        # Mock search results
        mock_ldap_manager.search.side_effect = [
            [{'dn': 'OU=NotEmptyOU,DC=test,DC=local'}],  # OU exists
            [  # Has child objects
                {'dn': 'CN=Child User,OU=NotEmptyOU,DC=test,DC=local'},
                {'dn': 'OU=Child OU,OU=NotEmptyOU,DC=test,DC=local'}
            ]
        ]
        
        # Test delete_ou (the registered delete_organizational_unit tool)
        result = ou_tools.delete_ou('OU=NotEmptyOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'contains child objects' in response_data['error']
        assert response_data['child_count'] == 2
        
        # Verify no delete operation was called
        mock_ldap_manager.delete.assert_not_called()
    
    def test_move_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU move operation."""
        # Mock search for source OU (move_ou reads name from attributes to build the new DN)
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=MoveMe,OU=OldParent,DC=test,DC=local',
             'attributes': {'name': ['MoveMe']}}
        ]
        
        # Mock successful move operation
        mock_ldap_manager.move.return_value = True
        
        # Test move_ou (the registered move_organizational_unit tool)
        result = ou_tools.move_ou(
            'OU=MoveMe,OU=OldParent,DC=test,DC=local',
            'OU=NewParent,DC=test,DC=local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'moved successfully' in response_data['message']
        assert response_data['old_dn'] == 'OU=MoveMe,OU=OldParent,DC=test,DC=local'
        assert response_data['new_dn'] == 'OU=MoveMe,OU=NewParent,DC=test,DC=local'
        
        # Verify LDAP move was called
        mock_ldap_manager.move.assert_called_once()
        call_args = mock_ldap_manager.move.call_args
        assert call_args[0][0] == 'OU=MoveMe,OU=OldParent,DC=test,DC=local'
        assert call_args[0][1] == 'OU=NewParent,DC=test,DC=local'
    
    def test_get_ou_children_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU children listing."""
        # Mock LDAP search results for child objects
        mock_results = [
            {
                'dn': 'CN=User1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                    'sAMAccountName': ['user1'],
                    'displayName': ['User One']
                }
            },
            {
                'dn': 'CN=Computer1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                    'sAMAccountName': ['COMPUTER1$'],
                    'dNSHostName': ['computer1.test.local']
                }
            },
            {
                'dn': 'OU=ChildOU,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'organizationalUnit'],
                    'name': ['ChildOU'],
                    'description': ['Child organizational unit']
                }
            },
            {
                'dn': 'CN=Group1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'group'],
                    'sAMAccountName': ['Group1'],
                    'displayName': ['Group One'],
                    'groupType': [-2147483646]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_ou_children
        result = ou_tools.get_ou_children('OU=ParentOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # get_ou_children delegates to get_ou_contents; assert its real response shape
        response_data = json.loads(result[0].text)
        assert response_data['ou_dn'] == 'OU=ParentOU,DC=test,DC=local'
        assert response_data['total_count'] == 4

        # Check object type breakdown
        type_counts = response_data['type_counts']
        assert type_counts['user'] == 1
        assert type_counts['computer'] == 1
        assert type_counts['group'] == 1
        assert type_counts['organizationalUnit'] == 1

        # Check individual child objects
        children = response_data['contents']
        assert len(children) == 4

        user_child = next(child for child in children if child['type'] == 'user')
        assert user_child['displayName'] == 'User One'
        assert user_child['name'] == 'user1'

        ou_child = next(child for child in children if child['type'] == 'organizationalUnit')
        assert ou_child['name'] == 'ChildOU'
    
    def test_ou_hierarchy_validation(self, ou_tools):
        """Test OU hierarchy validation logic."""
        # Test valid DN
        assert ou_tools._validate_ou_dn('OU=Test,DC=domain,DC=local') == True
        
        # Test invalid DN (not an OU)
        assert ou_tools._validate_ou_dn('CN=User,OU=Users,DC=domain,DC=local') == False
        
        # Test empty DN
        assert ou_tools._validate_ou_dn('') == False
        
        # Test malformed DN
        assert ou_tools._validate_ou_dn('invalid') == False
    
    def test_extract_ou_name(self, ou_tools):
        """Test OU name extraction from DN."""
        # Test normal OU DN
        name = ou_tools._extract_ou_name('OU=Marketing,OU=Departments,DC=test,DC=local')
        assert name == 'Marketing'
        
        # Test nested OU
        name = ou_tools._extract_ou_name('OU=Sales Team,OU=Sales,OU=Departments,DC=test,DC=local')
        assert name == 'Sales Team'
        
        # Test invalid DN
        name = ou_tools._extract_ou_name('CN=NotAnOU,DC=test,DC=local')
        assert name == ''
    
    def test_detect_object_type(self, ou_tools):
        """Test object type detection from objectClass."""
        # Test user object
        user_classes = ['top', 'person', 'organizationalPerson', 'user']
        assert ou_tools._detect_object_type(user_classes) == 'user'
        
        # Test computer object
        computer_classes = ['top', 'person', 'organizationalPerson', 'user', 'computer']
        assert ou_tools._detect_object_type(computer_classes) == 'computer'
        
        # Test group object
        group_classes = ['top', 'group']
        assert ou_tools._detect_object_type(group_classes) == 'group'
        
        # Test OU object
        ou_classes = ['top', 'organizationalUnit']
        assert ou_tools._detect_object_type(ou_classes) == 'organizational_unit'
        
        # Test unknown object
        unknown_classes = ['top', 'unknown']
        assert ou_tools._detect_object_type(unknown_classes) == 'unknown'
    
    def test_ldap_error_handling(self, ou_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test list_organizational_units with error
        result = ou_tools.list_organizational_units()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, ou_tools):
        """Test schema information retrieval."""
        schema = ou_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'ou_attributes' in schema
        assert 'delegation_permissions' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations (real registered method names)
        operations = schema['operations']
        assert 'list_ous' in operations
        assert 'get_ou' in operations
        assert 'create_ou' in operations
        assert 'modify_ou' in operations
        assert 'delete_ou' in operations
        assert 'move_ou' in operations
        assert 'get_ou_contents' in operations
        assert 'list_organizational_units' in operations

        # Check delegation permissions
        delegation_perms = schema['delegation_permissions']
        assert 'Full Control' in delegation_perms
        assert 'Read' in delegation_perms
        assert 'Write' in delegation_perms


# --- gPLink regressions (WP3) ----------------------------------------------
#
# The OU tools carried their own copy of the gPLink parser with two live-
# confirmed bugs. Both are covered here; the parser itself now lives once, in
# aditor.gpo.parsers.parse_gp_link, and is unit-tested in test_gpo_parsers.py.
#
# Bug 1: the copy computed 'enabled': int(options) == 0. The option is a
#        bitmask (bit 0 = link disabled, bit 1 = enforced), so an *enforced*
#        link (options=2) was reported as disabled, and 'enforced' did not
#        exist as a concept at all.
# Bug 2: get_ou/list_ous did attributes.get('gPLink', [])[0]. ldap3 returns
#        gPLink as a str, so [0] was the character '[' and parsing it yielded
#        [] — every OU in the domain reported linked_gpos: [].

GPO_GUID_PLAIN = '11111111-1111-1111-1111-111111111111'
GPO_GUID_ENFORCED = '22222222-2222-2222-2222-222222222222'
GPO_GUID_DISABLED = '33333333-3333-3333-3333-333333333333'


def _gp_link(*links):
    """Build a gPLink value the way AD does: one concatenated string."""
    return ''.join(
        f'[LDAP://cn={{{guid}}},cn=policies,cn=system,DC=test,DC=local;{options}]'
        for guid, options in links
    )


# As returned by ldap3: a single str holding every link. Two links, the second
# enforced (options=2) and a third disabled (options=1).
STR_GP_LINK = _gp_link(
    (GPO_GUID_PLAIN, 0),
    (GPO_GUID_ENFORCED, 2),
    (GPO_GUID_DISABLED, 1),
)


class TestGpLinkRegressions:
    """Both gPLink bugs must stay fixed."""

    def test_get_ou_parses_a_str_gplink(self, ou_tools, mock_ldap_manager):
        """Bug 2: a str gPLink must yield the real, non-empty link list."""
        mock_ldap_manager.search.return_value = [{
            'dn': 'OU=Sales,DC=test,DC=local',
            'attributes': {'name': 'Sales', 'gPLink': STR_GP_LINK},
        }]

        response = json.loads(
            ou_tools.get_ou('OU=Sales,DC=test,DC=local')[0].text)

        linked = response['computed']['linked_gpos']
        assert len(linked) == 3, "a str gPLink must not parse to an empty list"
        assert [link['guid'] for link in linked] == [
            GPO_GUID_PLAIN, GPO_GUID_ENFORCED, GPO_GUID_DISABLED]

    def test_get_ou_reports_enforced_links_as_enabled_and_enforced(
            self, ou_tools, mock_ldap_manager):
        """Bug 1: options=2 means enabled AND enforced, not disabled."""
        mock_ldap_manager.search.return_value = [{
            'dn': 'OU=Sales,DC=test,DC=local',
            'attributes': {'name': 'Sales',
                           'gPLink': _gp_link((GPO_GUID_ENFORCED, 2))},
        }]

        response = json.loads(
            ou_tools.get_ou('OU=Sales,DC=test,DC=local')[0].text)

        link = response['computed']['linked_gpos'][0]
        assert link['link_enabled'] is True
        assert link['enforced'] is True
        # The inverted key from the deleted copy must not come back.
        assert 'enabled' not in link

    def test_get_ou_link_option_bitmask(self, ou_tools, mock_ldap_manager):
        """The whole bitmask: 0 plain, 1 disabled, 2 enforced."""
        mock_ldap_manager.search.return_value = [{
            'dn': 'OU=Sales,DC=test,DC=local',
            'attributes': {'name': 'Sales', 'gPLink': STR_GP_LINK},
        }]

        response = json.loads(
            ou_tools.get_ou('OU=Sales,DC=test,DC=local')[0].text)

        linked = response['computed']['linked_gpos']
        assert [link['link_enabled'] for link in linked] == [True, True, False]
        assert [link['enforced'] for link in linked] == [False, True, False]

    def test_list_ous_parses_a_str_gplink(self, ou_tools, mock_ldap_manager):
        """Bug 2 again, via the list path."""
        mock_ldap_manager.search.return_value = [{
            'dn': 'OU=Sales,DC=test,DC=local',
            'attributes': {'name': 'Sales', 'gPLink': STR_GP_LINK},
        }]

        response = json.loads(ou_tools.list_ous()[0].text)

        linked = response['organizational_units'][0]['linkedGPOs']
        assert len(linked) == 3
        assert linked[1]['guid'] == GPO_GUID_ENFORCED
        assert linked[1]['enforced'] is True
        assert linked[1]['link_enabled'] is True

    def test_ou_tools_use_the_shared_parser(self):
        """The duplicate implementation must not come back."""
        assert not hasattr(OrganizationalUnitTools, '_parse_gp_link'), (
            "gPLink parsing lives once, in aditor.gpo.parsers.parse_gp_link"
        )

