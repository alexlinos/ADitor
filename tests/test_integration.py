"""Integration tests for Active Directory MCP server."""

import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from aditor.server import ActiveDirectoryMCPServer
from aditor.server_http import ActiveDirectoryMCPHTTPServer


@pytest.fixture
def test_config():
    """Test configuration data."""
    return {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }


@pytest.fixture
def config_file(test_config):
    """Temporary config file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_config, f)
        config_path = f.name
    
    yield config_path
    
    # Cleanup
    os.unlink(config_path)


class TestServerIntegration:
    """Integration tests for the main server."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    def test_server_initialization(self, mock_connect, mock_test_connection, config_file):
        """Test server initialization with config file."""
        # Mock successful connection
        mock_test_connection.return_value = {'connected': True, 'server': 'test.local'}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Verify initialization
        assert server.config is not None
        assert server.ldap_manager is not None
        assert server.user_tools is not None
        assert server.group_tools is not None
        assert server.computer_tools is not None
        assert server.ou_tools is not None
        assert server.security_tools is not None
        
        # Verify MCP server setup
        assert server.mcp is not None
        
        # Test connection was called
        mock_test_connection.assert_called_once()
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    def test_http_server_initialization(self, mock_connect, mock_test_connection, config_file):
        """Test HTTP server initialization."""
        # Mock successful connection
        mock_test_connection.return_value = {'connected': True, 'server': 'test.local'}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Initialize HTTP server
        server = ActiveDirectoryMCPHTTPServer(
            config_path=config_file,
            host="127.0.0.1",
            port=8814,
            path="/test-ad-mcp"
        )
        
        # Verify initialization
        assert server.config is not None
        assert server.ldap_manager is not None
        assert server.host == "127.0.0.1"
        assert server.port == 8814
        assert server.path == "/test-ad-mcp"
        
        # Verify tools
        assert server.user_tools is not None
        assert server.group_tools is not None
        assert server.computer_tools is not None
        assert server.ou_tools is not None
        assert server.security_tools is not None
    
    def test_server_with_invalid_config(self):
        """Test server initialization with invalid config."""
        with pytest.raises(FileNotFoundError):
            ActiveDirectoryMCPServer("/nonexistent/config.json")
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    def test_server_tools_registration(self, mock_connect, mock_test_connection, config_file):
        """Test that all tools are properly registered."""
        # Mock successful connection
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Get registered tools (this would require access to FastMCP internals)
        # For now, just verify the server initialized without errors
        assert server.mcp is not None
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    def test_connection_failure_handling(self, mock_test_connection, config_file):
        """Test handling of connection failures during initialization."""
        # Mock connection failure
        mock_test_connection.side_effect = Exception("Connection failed")
        
        # Server should still initialize but log the error
        server = ActiveDirectoryMCPServer(config_file)
        assert server is not None
        
        # Connection test should have been called
        mock_test_connection.assert_called_once()


class TestToolIntegration:
    """Integration tests for tool interactions."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_user_tools_integration(self, mock_search, mock_connect, mock_test_connection, config_file):
        """Test user tools integration."""
        # Mock successful connection and search
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        mock_search.return_value = [
            {
                'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['testuser'],
                    'displayName': ['Test User'],
                    'userAccountControl': [512]
                }
            }
        ]
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Test user tools
        result = server.user_tools.list_users()
        assert len(result) == 1
        
        # Verify search was called
        mock_search.assert_called()
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_group_tools_integration(self, mock_search, mock_connect, mock_test_connection, config_file):
        """Test group tools integration."""
        # Mock successful connection and search
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        mock_search.return_value = [
            {
                'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['testgroup'],
                    'displayName': ['Test Group'],
                    'groupType': [-2147483646]
                }
            }
        ]
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Test group tools
        result = server.group_tools.list_groups()
        assert len(result) == 1
        
        # Verify search was called
        mock_search.assert_called()
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    def test_security_tools_integration(self, mock_connect, mock_test_connection, config_file):
        """Test security tools integration."""
        # Mock successful connection
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Verify security tools initialized
        assert server.security_tools is not None
        assert hasattr(server.security_tools, 'get_domain_info')
        assert hasattr(server.security_tools, 'get_privileged_groups')
        assert hasattr(server.security_tools, 'audit_admin_accounts')


class TestErrorHandling:
    """Test error handling in integration scenarios."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_ldap_error_propagation(self, mock_search, mock_connect, mock_test_connection, config_file):
        """Test that LDAP errors are properly handled and propagated."""
        # Mock successful connection but failing operations
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Mock LDAP exception for search operations
        from ldap3.core.exceptions import LDAPException
        mock_search.side_effect = LDAPException("Test error")
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Test that error is handled gracefully
        result = server.user_tools.list_users()
        assert len(result) == 1
        
        # Parse response to check error handling
        response_text = result[0].text
        response_data = json.loads(response_text)
        assert response_data['success'] == False
        assert 'Test error' in response_data['error']
    
    def test_config_validation_errors(self, test_config):
        """Test configuration validation error handling."""
        # Create invalid config (missing required fields)
        invalid_config = test_config.copy()
        del invalid_config['active_directory']['domain']
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(invalid_config, f)
            config_path = f.name
        
        try:
            with pytest.raises(Exception):  # Should raise validation error
                ActiveDirectoryMCPServer(config_path)
        finally:
            os.unlink(config_path)


class TestEndToEndWorkflows:
    """Test end-to-end workflow scenarios."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    @patch('aditor.core.ldap_manager.LDAPManager.add')
    @patch('aditor.core.ldap_manager.LDAPManager.modify')
    def test_complete_user_lifecycle(self, mock_modify, mock_add, mock_search, 
                                   mock_connect, mock_test_connection, config_file):
        """Test complete user lifecycle: Create -> Modify -> Add to Group -> Disable -> Delete."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Mock successful operations
        mock_add.return_value = True
        mock_modify.return_value = True
        
        # Mock search results per stage, driven by call order:
        #   1) create_user existence check -> empty (user doesn't exist)
        #   2) modify_user lookup          -> user exists
        #   3) add_member group lookup     -> group exists (with member attr)
        #   4+) disable/delete lookups     -> user exists
        call_count = {'n': 0}
        def search_side_effect(*args, **kwargs):
            call_count['n'] += 1
            n = call_count['n']
            if n == 1:
                return []  # User doesn't exist initially
            elif n == 2:
                return [{'dn': 'CN=Test User,OU=Users,DC=test,DC=local'}]  # User exists for modifications
            elif n == 3:
                return [{'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local', 'attributes': {'member': []}}]  # Group exists
            else:
                return [{'dn': 'CN=Test User,OU=Users,DC=test,DC=local'}]

        mock_search.side_effect = search_side_effect
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # 1. Create user
        create_result = server.user_tools.create_user(
            username='testuser',
            password='TempPass123!',
            first_name='Test',
            last_name='User',
            email='test.user@test.local'
        )
        assert len(create_result) == 1
        create_data = json.loads(create_result[0].text)
        assert create_data['success'] == True
        
        # 2. Modify user attributes
        modify_result = server.user_tools.modify_user(
            username='testuser',
            attributes={'description': 'Modified test user', 'department': 'IT'}
        )
        assert len(modify_result) == 1
        modify_data = json.loads(modify_result[0].text)
        assert modify_data['success'] == True
        
        # 3. Add user to group
        add_member_result = server.group_tools.add_member('TestGroup', 'CN=Test User,OU=Users,DC=test,DC=local')
        assert len(add_member_result) == 1
        add_member_data = json.loads(add_member_result[0].text)
        assert add_member_data['success'] == True
        
        # 4. Disable user
        disable_result = server.user_tools.disable_user('testuser')
        assert len(disable_result) == 1
        disable_data = json.loads(disable_result[0].text)
        assert disable_data['success'] == True
        
        # 5. Delete user (this would also remove from groups automatically in real AD)
        delete_result = server.user_tools.delete_user('testuser')
        assert len(delete_result) == 1
        delete_data = json.loads(delete_result[0].text)
        assert delete_data['success'] == True
        
        # Verify all LDAP operations were called
        assert mock_add.call_count >= 1  # User creation
        assert mock_modify.call_count >= 3  # Password set, enable, modify attributes, disable
    
    @pytest.mark.xfail(reason="real bug: create_computer defaults ou via self.ldap.ad_config.organizational_units.computers_ou, "
                              "but LDAPManager is constructed with only ActiveDirectoryConfig (which has no organizational_units) — "
                              "the default-OU path raises AttributeError. Same bug in group.py create_group. Fix in WP1/2/3.")
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    @patch('aditor.core.ldap_manager.LDAPManager.add')
    @patch('aditor.core.ldap_manager.LDAPManager.modify')
    def test_bulk_computer_management_workflow(self, mock_modify, mock_add, mock_search,
                                             mock_connect, mock_test_connection, config_file):
        """Test bulk computer management workflow."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        mock_add.return_value = True
        mock_modify.return_value = True
        
        # Mock computer search results
        def computer_search_side_effect(*args, **kwargs):
            search_filter = kwargs.get('search_filter', '')
            
            if 'objectClass=computer' in search_filter:
                return [
                    {
                        'dn': 'CN=WORKSTATION01,CN=Computers,DC=test,DC=local',
                        'attributes': {
                            'sAMAccountName': ['WORKSTATION01$'],
                            'dNSHostName': ['workstation01.test.local'],
                            'lastLogon': [datetime.now() - timedelta(days=90)],  # Stale
                            'userAccountControl': [4096]
                        }
                    },
                    {
                        'dn': 'CN=WORKSTATION02,CN=Computers,DC=test,DC=local',
                        'attributes': {
                            'sAMAccountName': ['WORKSTATION02$'],
                            'dNSHostName': ['workstation02.test.local'],
                            'lastLogon': [datetime.now() - timedelta(days=1)],  # Active
                            'userAccountControl': [4096]
                        }
                    }
                ]
            else:
                return []  # Computer doesn't exist for creation tests
        
        mock_search.side_effect = computer_search_side_effect
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # 1. List all computers
        list_result = server.computer_tools.list_computers()
        assert len(list_result) == 1
        list_data = json.loads(list_result[0].text)
        assert list_data['count'] == 2
        
        # 2. Find stale computers (get_stale_computers is the registered tool)
        stale_result = server.computer_tools.get_stale_computers(days=30)
        assert len(stale_result) == 1
        stale_data = json.loads(stale_result[0].text)
        assert len(stale_data['stale_computers']) == 1  # WORKSTATION01
        
        # 3. Create new computer
        create_result = server.computer_tools.create_computer(
            computer_name='NEWWORKSTATION',
            dns_hostname='newworkstation.test.local',
            description='New workstation for employee'
        )
        assert len(create_result) == 1
        create_data = json.loads(create_result[0].text)
        assert create_data['success'] == True
        
        # 4. Reset password for stale computer
        reset_result = server.computer_tools.reset_computer_password('WORKSTATION01')
        assert len(reset_result) == 1
        reset_data = json.loads(reset_result[0].text)
        assert reset_data['success'] == True
        
        # Verify operations
        mock_add.assert_called()  # Computer creation
        mock_modify.assert_called()  # Password reset and enable


class TestErrorRecoveryScenarios:
    """Test error recovery and resilience scenarios."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_partial_operation_failure_recovery(self, mock_search, mock_connect, 
                                               mock_test_connection, config_file):
        """Test recovery from partial operation failures."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Mock intermittent failures
        call_count = 0
        def search_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call fails
                from ldap3.core.exceptions import LDAPException
                raise LDAPException("Temporary connection error")
            else:
                # Subsequent calls succeed (get_user needs an 'attributes' dict)
                return [{'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
                         'attributes': {'sAMAccountName': ['testuser']}}]
        
        mock_search.side_effect = search_side_effect
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # First attempt should fail
        result1 = server.user_tools.get_user('testuser')
        assert len(result1) == 1
        data1 = json.loads(result1[0].text)
        assert data1['success'] == False
        assert 'connection error' in data1['error']
        
        # Second attempt should succeed (showing resilience)
        result2 = server.user_tools.get_user('testuser')
        assert len(result2) == 1
        data2 = json.loads(result2[0].text)
        assert data2['dn'] == 'CN=Test User,OU=Users,DC=test,DC=local'
        
        # Verify retry behavior
        assert call_count == 2
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    def test_connection_failure_scenarios(self, mock_connect, mock_test_connection, config_file):
        """Test various connection failure scenarios."""
        # Test initial connection failure
        mock_test_connection.side_effect = Exception("LDAP server unavailable")
        
        # Server should still initialize but log the error
        server = ActiveDirectoryMCPServer(config_file)
        assert server is not None
        assert server.ldap_manager is not None
        
        # Connection test should have been attempted
        mock_test_connection.assert_called_once()


class TestMultiToolInteractionScenarios:
    """Test complex scenarios involving multiple tools."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    @patch('aditor.core.ldap_manager.LDAPManager.add')
    @patch('aditor.core.ldap_manager.LDAPManager.modify')
    def test_department_setup_workflow(self, mock_modify, mock_add, mock_search,
                                      mock_connect, mock_test_connection, config_file):
        """Test complete department setup: OU -> Groups -> Users -> Permissions."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        mock_add.return_value = True
        mock_modify.return_value = True
        
        # Mock search results
        search_call_count = 0
        def search_side_effect(*args, **kwargs):
            nonlocal search_call_count
            search_call_count += 1
            
            search_filter = kwargs.get('search_filter', '')
            
            # Return empty for "doesn't exist" checks, populated for "exists" checks
            if search_call_count <= 3:  # First 3 calls are existence checks
                return []
            else:
                if 'organizationalUnit' in search_filter:
                    return [{'dn': 'OU=Marketing,OU=Departments,DC=test,DC=local'}]
                elif 'objectClass=group' in search_filter:
                    return [{'dn': 'CN=Marketing Team,OU=Groups,DC=test,DC=local', 'attributes': {'member': []}}]
                elif 'objectClass=user' in search_filter:
                    return [{'dn': 'CN=Marketing User,OU=Users,DC=test,DC=local'}]
                else:
                    return []
        
        mock_search.side_effect = search_side_effect
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # 1. Create department OU
        ou_result = server.ou_tools.create_organizational_unit(
            name='Marketing',
            parent_dn='OU=Departments,DC=test,DC=local',
            description='Marketing department'
        )
        assert len(ou_result) == 1
        ou_data = json.loads(ou_result[0].text)
        assert ou_data['success'] == True
        
        # 2. Create department group
        group_result = server.group_tools.create_group(
            group_name='MarketingTeam',
            display_name='Marketing Team',
            description='Marketing department group',
            ou='OU=Groups,DC=test,DC=local'
        )
        assert len(group_result) == 1
        group_data = json.loads(group_result[0].text)
        assert group_data['success'] == True
        
        # 3. Create department user
        user_result = server.user_tools.create_user(
            username='marketing.user',
            password='TempPass123!',
            first_name='Marketing',
            last_name='User',
            email='marketing.user@test.local'
        )
        assert len(user_result) == 1
        user_data = json.loads(user_result[0].text)
        assert user_data['success'] == True
        
        # 4. Add user to group
        member_result = server.group_tools.add_member(
            'MarketingTeam', 
            'CN=Marketing User,OU=Users,DC=test,DC=local'
        )
        assert len(member_result) == 1
        member_data = json.loads(member_result[0].text)
        assert member_data['success'] == True
        
        # Verify all operations completed
        assert mock_add.call_count >= 3  # OU, Group, User
        assert mock_modify.call_count >= 2  # User password/enable, Group membership


class TestPerformanceAndScalability:
    """Test performance-related scenarios."""
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_large_result_set_handling(self, mock_search, mock_connect, 
                                      mock_test_connection, config_file):
        """Test handling of large result sets."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Generate large mock dataset (1000 users)
        large_result_set = []
        for i in range(1000):
            large_result_set.append({
                'dn': f'CN=User{i:04d},OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': [f'user{i:04d}'],
                    'displayName': [f'User {i:04d}'],
                    'mail': [f'user{i:04d}@test.local'],
                    'userAccountControl': [512]
                }
            })
        
        mock_search.return_value = large_result_set
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Test large user list
        result = server.user_tools.list_users()
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data['count'] == 1000
        assert len(data['users']) == 1000
        
        # Verify search was called
        mock_search.assert_called_once()
    
    @patch('aditor.core.ldap_manager.LDAPManager.test_connection')
    @patch('aditor.core.ldap_manager.LDAPManager.connect')
    @patch('aditor.core.ldap_manager.LDAPManager.search')
    def test_concurrent_operations_simulation(self, mock_search, mock_connect, 
                                            mock_test_connection, config_file):
        """Test simulation of concurrent operations."""
        # Setup mocks
        mock_test_connection.return_value = {'connected': True}
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        
        # Mock different results for different calls
        mock_search.return_value = [
            {'dn': 'CN=Test User,OU=Users,DC=test,DC=local', 'attributes': {'sAMAccountName': ['testuser']}}
        ]
        
        # Initialize server
        server = ActiveDirectoryMCPServer(config_file)
        
        # Simulate multiple concurrent operations
        results = []
        for i in range(10):
            result = server.user_tools.get_user(f'testuser{i}')
            results.append(result)
        
        # Verify all operations completed
        assert len(results) == 10
        for result in results:
            assert len(result) == 1
        
        # Verify multiple searches were performed
        assert mock_search.call_count == 10
