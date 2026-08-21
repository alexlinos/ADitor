"""Tests for LDAP manager."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from aditor.core.ldap_manager import LDAPManager
from aditor.config.models import ActiveDirectoryConfig, SecurityConfig, PerformanceConfig


@pytest.fixture
def ad_config():
    """Test Active Directory configuration."""
    return ActiveDirectoryConfig(
        server="ldap://test.local:389",
        domain="test.local",
        base_dn="DC=test,DC=local",
        bind_dn="CN=admin,DC=test,DC=local",
        password="password123"
    )


@pytest.fixture
def security_config():
    """Test security configuration."""
    return SecurityConfig()


@pytest.fixture
def performance_config():
    """Test performance configuration."""
    return PerformanceConfig()


@pytest.fixture
def ldap_manager(ad_config, security_config, performance_config):
    """Test LDAP manager instance."""
    with patch('aditor.core.ldap_manager.Server'), \
         patch('aditor.core.ldap_manager.Connection'):
        manager = LDAPManager(ad_config, security_config, performance_config)
        return manager


class TestLDAPManager:
    """Test LDAP manager functionality."""
    
    def test_initialization(self, ad_config, security_config, performance_config):
        """Test LDAP manager initialization."""
        with patch('aditor.core.ldap_manager.Server') as mock_server:
            manager = LDAPManager(ad_config, security_config, performance_config)
            assert manager.ad_config == ad_config
            assert manager.security_config == security_config
            assert manager.performance_config == performance_config
            mock_server.assert_called()
    
    @patch('aditor.core.ldap_manager.Connection')
    @patch('aditor.core.ldap_manager.Server')
    def test_connect_success(self, mock_server, mock_connection, ldap_manager):
        """Test successful LDAP connection."""
        # Setup mocks
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = True
        mock_connection_instance.bound = True
        mock_connection.return_value = mock_connection_instance
        
        ldap_manager._server_pool = [mock_server_instance]
        
        # Test connection
        connection = ldap_manager.connect()
        
        assert connection == mock_connection_instance
        assert ldap_manager._connection == mock_connection_instance
        mock_connection_instance.bind.assert_called_once()
    
    @patch('aditor.core.ldap_manager.Connection')
    @patch('aditor.core.ldap_manager.Server')
    def test_connect_failure(self, mock_server, mock_connection, ldap_manager):
        """Test LDAP connection failure."""
        # Setup mocks
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = False
        mock_connection.return_value = mock_connection_instance
        
        ldap_manager._server_pool = [mock_server_instance]
        
        # Test connection failure
        with pytest.raises(Exception):
            ldap_manager.connect()
    
    def test_disconnect(self, ldap_manager):
        """Test LDAP disconnection."""
        # Setup mock connection
        mock_connection = Mock()
        ldap_manager._connection = mock_connection
        
        # Test disconnection
        ldap_manager.disconnect()
        
        mock_connection.unbind.assert_called_once()
        assert ldap_manager._connection is None
    
    @patch('aditor.core.ldap_manager.Connection')
    def test_search(self, mock_connection, ldap_manager):
        """Test LDAP search operation."""
        # Setup mock connection
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = True
        mock_connection_instance.bound = True
        mock_connection_instance.search.return_value = True
        
        # Mock search results
        mock_entry = Mock()
        mock_entry.entry_dn = "CN=testuser,OU=Users,DC=test,DC=local"
        mock_entry.entry_attributes = ['sAMAccountName', 'displayName']
        mock_entry.sAMAccountName = Mock()
        mock_entry.sAMAccountName.value = "testuser"
        mock_entry.displayName = Mock()
        mock_entry.displayName.value = "Test User"
        
        mock_connection_instance.entries = [mock_entry]
        mock_connection_instance.result = {'controls': {}}
        
        ldap_manager._connection = mock_connection_instance
        
        # Test search
        results = ldap_manager.search(
            search_base="OU=Users,DC=test,DC=local",
            search_filter="(objectClass=user)"
        )
        
        assert len(results) == 1
        assert results[0]['dn'] == "CN=testuser,OU=Users,DC=test,DC=local"
        assert results[0]['attributes']['sAMAccountName'] == "testuser"
        assert results[0]['attributes']['displayName'] == "Test User"
        
        mock_connection_instance.search.assert_called()
    
    @patch('aditor.core.ldap_manager.Connection')
    def test_add(self, mock_connection, ldap_manager):
        """Test LDAP add operation."""
        # Setup mock connection
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = True
        mock_connection_instance.bound = True
        mock_connection_instance.add.return_value = True
        
        ldap_manager._connection = mock_connection_instance
        
        # Test add operation
        dn = "CN=newuser,OU=Users,DC=test,DC=local"
        attributes = {
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'sAMAccountName': 'newuser',
            'displayName': 'New User'
        }
        
        result = ldap_manager.add(dn, attributes)
        
        assert result == True
        mock_connection_instance.add.assert_called_once_with(dn, attributes=attributes)
    
    @patch('aditor.core.ldap_manager.Connection')
    def test_modify(self, mock_connection, ldap_manager):
        """Test LDAP modify operation."""
        # Setup mock connection
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = True
        mock_connection_instance.bound = True
        mock_connection_instance.modify.return_value = True
        
        ldap_manager._connection = mock_connection_instance
        
        # Test modify operation
        dn = "CN=testuser,OU=Users,DC=test,DC=local"
        changes = {
            'displayName': [('MODIFY_REPLACE', ['Modified User'])]
        }
        
        result = ldap_manager.modify(dn, changes)
        
        assert result == True
        mock_connection_instance.modify.assert_called_once_with(dn, changes)
    
    @patch('aditor.core.ldap_manager.Connection')
    def test_delete(self, mock_connection, ldap_manager):
        """Test LDAP delete operation."""
        # Setup mock connection
        mock_connection_instance = Mock()
        mock_connection_instance.bind.return_value = True
        mock_connection_instance.bound = True
        mock_connection_instance.delete.return_value = True
        
        ldap_manager._connection = mock_connection_instance
        
        # Test delete operation
        dn = "CN=testuser,OU=Users,DC=test,DC=local"
        
        result = ldap_manager.delete(dn)
        
        assert result == True
        mock_connection_instance.delete.assert_called_once_with(dn)
    
    def test_test_connection_success(self, ldap_manager):
        """Test connection test with success."""
        # Setup mock connection
        mock_connection = Mock()
        mock_connection.server.host = "test.local"
        mock_connection.server.port = 389
        mock_connection.server.ssl = False
        mock_connection.bound = True
        mock_connection.user = "CN=admin,DC=test,DC=local"
        mock_connection.search.return_value = True
        
        ldap_manager._connection = mock_connection
        
        with patch.object(ldap_manager, 'connect', return_value=mock_connection):
            result = ldap_manager.test_connection()
        
        assert result['connected'] == True
        assert result['server'] == "test.local"
        assert result['port'] == 389
        assert result['search_test'] == True
    
    def test_test_connection_failure(self, ldap_manager):
        """Test connection test with failure."""
        with patch.object(ldap_manager, 'connect', side_effect=Exception("Connection failed")):
            result = ldap_manager.test_connection()
        
        assert result['connected'] == False
        assert "Connection failed" in result['error']
    
    def test_context_manager(self, ldap_manager):
        """Test LDAP manager as context manager."""
        with patch.object(ldap_manager, 'disconnect') as mock_disconnect:
            with ldap_manager:
                pass
            
            mock_disconnect.assert_called_once()


class TestLDAPManagerRetry:
    """Test LDAP manager retry functionality."""
    
    @patch('time.sleep')  # Mock sleep to speed up tests
    @patch('aditor.core.ldap_manager.Connection')
    @patch('aditor.core.ldap_manager.Server')
    def test_connection_retry(self, mock_server, mock_connection, mock_sleep, 
                            ad_config, security_config, performance_config):
        """Test connection retry logic."""
        # Setup mocks
        mock_server_instance = Mock()
        mock_server.return_value = mock_server_instance
        
        # First two attempts fail, third succeeds
        mock_connection_instance = Mock()
        mock_connection_instance.bind.side_effect = [False, False, True]
        mock_connection_instance.bound = True
        mock_connection.return_value = mock_connection_instance
        
        # Set max_retries to 3
        performance_config.max_retries = 3
        performance_config.retry_delay = 0.1
        
        manager = LDAPManager(ad_config, security_config, performance_config)
        manager._server_pool = [mock_server_instance]
        
        # Test connection with retries
        connection = manager.connect()
        
        assert connection == mock_connection_instance
        assert mock_connection_instance.bind.call_count == 3
        assert mock_sleep.call_count == 2  # Sleep called between retries


class TestConnectionErrorsAreNotBlindlyRetried:
    """Some connection failures must fail fast, not retry.

    A credential failure retried ``max_retries`` times is ``max_retries`` failed
    logons against the domain's lockout policy — the retry turns one wrong
    password into a locked service account. A certificate failure is
    deterministic, so retrying cannot help, and it loses the diagnosis: ldap3's
    ``Server`` is unusable afterwards and later attempts report "invalid server
    address", which sends the reader after DNS instead of the certificate.
    """

    def test_a_certificate_failure_is_terminal(self):
        from ldap3.core.exceptions import LDAPSocketOpenError
        from aditor.core.ldap_manager import is_terminal_connection_error
        err = LDAPSocketOpenError(
            "socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate verify failed: unable to get local issuer certificate")
        assert is_terminal_connection_error(err) is True

    def test_a_bind_failure_is_terminal_because_retrying_locks_the_account(self):
        from ldap3.core.exceptions import LDAPBindError
        from aditor.core.ldap_manager import is_terminal_connection_error
        assert is_terminal_connection_error(LDAPBindError("invalidCredentials")) is True

    def test_an_unreachable_host_is_transient_and_still_worth_retrying(self):
        from ldap3.core.exceptions import LDAPSocketOpenError
        from aditor.core.ldap_manager import is_terminal_connection_error
        for msg in ("connection refused", "timed out", "No route to host"):
            assert is_terminal_connection_error(LDAPSocketOpenError(msg)) is False, msg

    def test_the_certificate_error_survives_instead_of_invalid_server_address(self):
        """The regression: the real cause must reach the caller."""
        from ldap3.core.exceptions import LDAPSocketOpenError, LDAPException
        from unittest.mock import Mock, patch
        import aditor.core.ldap_manager as M

        ad = Mock(bind_dn="T\\svc", password="x", auto_bind=True, receive_timeout=5,
                  server="ldaps://dc.test.local:636", server_pool=None,
                  base_dn="DC=test,DC=local", domain="test.local")
        sec = Mock(validate_certificate=True, ca_cert_file=None, enable_tls=True)
        perf = Mock(max_retries=3, retry_delay=0, connection_pool_size=1, page_size=100)

        cert_error = LDAPSocketOpenError(
            "socket ssl wrapping error: [SSL: CERTIFICATE_VERIFY_FAILED] "
            "certificate verify failed: unable to get local issuer certificate")
        attempts = []

        def exploding_connection(*a, **k):
            attempts.append(1)
            # after the first failure ldap3 reports a downstream symptom
            raise cert_error if len(attempts) == 1 else LDAPSocketOpenError("invalid server address")

        with patch.object(M, "Connection", side_effect=exploding_connection):
            mgr = M.LDAPManager(ad, sec, perf)
            with pytest.raises(LDAPException) as excinfo:
                mgr.connect()

        message = str(excinfo.value)
        assert "CERTIFICATE_VERIFY_FAILED" in message, message
        assert "invalid server address" not in message, message
        assert len(attempts) == 1, f"failed fast? attempts={len(attempts)}"

    def test_a_bind_failure_costs_exactly_one_logon_not_max_retries(self):
        """The lockout regression: one wrong password, one failed logon."""
        from ldap3.core.exceptions import LDAPBindError, LDAPException
        from unittest.mock import Mock, patch
        import aditor.core.ldap_manager as M

        ad = Mock(bind_dn="T\\svc", password="wrong", auto_bind=True, receive_timeout=5,
                  server="ldaps://dc.test.local:636", server_pool=None,
                  base_dn="DC=test,DC=local", domain="test.local")
        sec = Mock(validate_certificate=False, ca_cert_file=None, enable_tls=True)
        perf = Mock(max_retries=3, retry_delay=0, connection_pool_size=1, page_size=100)

        binds = []

        def failing_bind(*a, **k):
            binds.append(1)
            raise LDAPBindError("invalidCredentials")

        with patch.object(M, "Connection", side_effect=failing_bind):
            mgr = M.LDAPManager(ad, sec, perf)
            with pytest.raises(LDAPException):
                mgr.connect()

        assert len(binds) == 1, (
            f"a wrong password cost {len(binds)} failed logons; with a lockout "
            f"threshold of 3-5 that locks the account")
