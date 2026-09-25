"""LDAP connection manager for Active Directory."""

import logging
import ssl
import time
from typing import Optional, List, Dict, Any, Union
from threading import Lock

import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError

from ..config.models import ActiveDirectoryConfig, SecurityConfig, PerformanceConfig

logger = logging.getLogger(__name__)


#: Markers that identify a TLS/certificate failure. ldap3 wraps these in
#: ``LDAPSocketOpenError``, so the exception type alone cannot tell them apart
#: from a genuinely transient socket problem.
_TLS_FAILURE_MARKERS = (
    "certificate_verify_failed",
    "ssl wrapping error",
    "certificate verify failed",
    "sslerror",
    "ssl:",
)

#: Text that means "the directory rejected these credentials". Needed because a
#: bind failure does not always arrive as an ``LDAPBindError``: ``connect()``
#: aggregates its attempts and re-raises, and a caller that loops over several
#: searches sees the aggregate. Recognising the type alone let five bind
#: attempts through one button press against a domain whose lockout threshold
#: was five.
#:
#: Deliberately distinctive strings. The bare LDAP result code ``49`` is not on
#: this list -- it would match a serial number, a timestamp or a DN, and a
#: classifier that fires on the wrong error is how a transient network blip
#: becomes an unretried failure.
_CREDENTIAL_FAILURE_MARKERS = (
    "invalidcredentials",
    "ldapinvalidcredentialsresult",
    "acceptsecuritycontext error",
    "data 525",   # no such user
    "data 52e",   # wrong password
    "data 530",   # not permitted at this time
    "data 531",   # not permitted at this workstation
    "data 532",   # password expired
    "data 533",   # account disabled
    "data 701",   # account expired
    "data 773",   # must change password
    "data 775",   # account locked out -- retrying extends the lockout
)


class TerminalConnectionError(LDAPException):
    """A connection failure that retrying cannot fix, and may make worse.

    Its own type, not a plain ``LDAPException``, so the broad ``except
    Exception`` in the retry loop can re-raise it instead of swallowing it and
    retrying anyway — which is exactly the bug this class exists to prevent.
    """


def is_terminal_connection_error(error: Exception) -> bool:
    """Would retrying this connection error be pointless, or harmful?

    Two classes of failure must not be retried:

    * **Credential failures.** Every retry is another failed logon against the
      domain's lockout policy, so retrying a wrong password is how a service
      account gets locked out — the retry turns one mistake into ``max_retries``
      of them per operation.
    * **Certificate failures.** Verification is deterministic: the same chain
      will fail the same way every time. Retrying also loses the diagnosis,
      because ldap3's ``Server`` is unusable afterwards and later attempts report
      ``invalid server address`` — which overwrites the certificate error with
      one that sends the reader after DNS instead.

    A socket that could not be opened for any other reason (refused, unreachable,
    timed out) is genuinely transient and is worth retrying.
    """
    if isinstance(error, (LDAPBindError, TerminalConnectionError)):
        return True
    text = str(error).lower()
    return any(marker in text
               for marker in _TLS_FAILURE_MARKERS + _CREDENTIAL_FAILURE_MARKERS)



class LDAPManager:
    """
    LDAP connection manager for Active Directory operations.
    
    Provides connection pooling, automatic reconnection, and error handling
    for LDAP operations against Active Directory.
    """
    
    def __init__(self, 
                 ad_config: ActiveDirectoryConfig,
                 security_config: SecurityConfig,
                 performance_config: PerformanceConfig):
        """
        Initialize LDAP manager.
        
        Args:
            ad_config: Active Directory configuration
            security_config: Security configuration
            performance_config: Performance configuration
        """
        self.ad_config = ad_config
        self.security_config = security_config
        self.performance_config = performance_config
        
        self._connection: Optional[Connection] = None
        self._server_pool: Optional[List[Server]] = None
        self._lock = Lock()
        
        self._setup_servers()
        
    def _setup_servers(self) -> None:
        """Setup LDAP servers and server pool."""
        try:
            # Setup TLS configuration
            tls_config = None
            if self.security_config.enable_tls:
                tls_config = ldap3.Tls(
                    validate=ssl.CERT_REQUIRED if self.security_config.validate_certificate else ssl.CERT_NONE,
                    ca_certs_file=self.security_config.ca_cert_file
                )
            
            # Create primary server
            primary_server = Server(
                self.ad_config.server,
                get_info=ALL,
                tls=tls_config,
                connect_timeout=self.ad_config.timeout
            )
            
            servers = [primary_server]
            
            # Add additional servers from pool
            if self.ad_config.server_pool:
                for server_url in self.ad_config.server_pool:
                    server = Server(
                        server_url,
                        get_info=ALL,
                        tls=tls_config,
                        connect_timeout=self.ad_config.timeout
                    )
                    servers.append(server)
            
            # Create server pool for failover
            self._server_pool = servers
            logger.info(f"Configured {len(servers)} LDAP servers")
            
        except Exception as e:
            logger.error(f"Error setting up LDAP servers: {e}")
            raise
    
    def connect(self) -> Connection:
        """
        Establish LDAP connection with retry logic.
        
        Returns:
            Connection: Active LDAP connection
            
        Raises:
            LDAPException: If connection fails after all retries
        """
        with self._lock:
            if self._connection and self._connection.bound:
                return self._connection
            
            last_error = None
            first_error = None
            
            for attempt in range(self.performance_config.max_retries):
                try:
                    # Try each server in the pool
                    for server in self._server_pool:
                        try:
                            logger.debug(f"Attempting connection to {server.host}:{server.port}")
                            
                            connection = Connection(
                                server,
                                user=self.ad_config.bind_dn,
                                password=self.ad_config.password,
                                auto_bind=self.ad_config.auto_bind,
                                receive_timeout=self.ad_config.receive_timeout,
                                authentication=ldap3.SIMPLE,
                                check_names=True,
                                raise_exceptions=True
                            )
                            
                            # Test the connection
                            if connection.bind():
                                self._connection = connection
                                logger.info(f"Successfully connected to {server.host}:{server.port}")
                                return connection
                            else:
                                logger.warning(f"Failed to bind to {server.host}:{server.port}")
                                
                        except (LDAPSocketOpenError, LDAPBindError) as e:
                            logger.warning(f"Connection failed to {server.host}:{server.port}: {e}")
                            if first_error is None:
                                first_error = e
                            last_error = e
                            if is_terminal_connection_error(e):
                                # Retrying cannot help and can do harm - see
                                # is_terminal_connection_error. Surface the real
                                # cause instead of burying it under a retry.
                                raise TerminalConnectionError(
                                    f"Failed to connect to {server.host}:{server.port}: {e}"
                                ) from e
                            continue
                    
                    # If we get here, all servers failed for this attempt
                    if attempt < self.performance_config.max_retries - 1:
                        logger.info(f"Retry {attempt + 1}/{self.performance_config.max_retries} after {self.performance_config.retry_delay}s")
                        time.sleep(self.performance_config.retry_delay)
                    
                except TerminalConnectionError:
                    # Deliberately not retried: see TerminalConnectionError.
                    raise
                except Exception as e:
                    logger.error(f"Unexpected error during connection attempt {attempt + 1}: {e}")
                    last_error = e
                    
                    if attempt < self.performance_config.max_retries - 1:
                        time.sleep(self.performance_config.retry_delay)
            
            # All attempts failed
            error_msg = f"Failed to connect to any LDAP server after {self.performance_config.max_retries} attempts"
            # The first error is the informative one: once a connection attempt
            # fails, later attempts often report a downstream symptom instead.
            reported = first_error or last_error
            if reported:
                error_msg += f". Error: {reported}"
            
            logger.error(error_msg)
            # Preserve *which kind* of failure this was through the aggregation.
            # A caller looping over several searches re-enters connect() for each
            # one, so flattening a rejected credential into a plain
            # LDAPException turns one wrong password into one failed logon per
            # search -- five of them, on a domain whose lockout threshold is
            # five. The text check above is the backstop; this is the fix.
            if reported is not None and is_terminal_connection_error(reported):
                raise TerminalConnectionError(error_msg) from reported
            raise LDAPException(error_msg)
    
    def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        with self._lock:
            if self._connection:
                try:
                    self._connection.unbind()
                    logger.info("Disconnected from LDAP server")
                except Exception as e:
                    logger.warning(f"Error during disconnect: {e}")
                finally:
                    self._connection = None
    
    def search(self, 
               search_base: str,
               search_filter: str,
               attributes: Union[List[str], str] = ALL_ATTRIBUTES,
               search_scope: str = SUBTREE,
               size_limit: int = 0) -> List[Dict[str, Any]]:
        """
        Perform LDAP search operation.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: Attributes to retrieve
            search_scope: Search scope (SUBTREE, ONELEVEL, BASE)
            size_limit: Maximum number of results (0 = no limit)
            
        Returns:
            List of LDAP entries as dictionaries
            
        Raises:
            LDAPException: If search fails
        """
        connection = self.connect()
        
        try:
            logger.debug(f"Searching: base={search_base}, filter={search_filter}")
            
            # Perform paged search for large result sets
            paged_size = min(self.performance_config.page_size, size_limit) if size_limit > 0 else self.performance_config.page_size
            
            entries = []
            cookie = None
            
            while True:
                success = connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    paged_size=paged_size,
                    paged_cookie=cookie
                )
                
                # ldap3's Connection.search returns False for a successful
                # search with zero entries, so check the LDAP result code
                # (0 = success) instead of the boolean to detect failure.
                if not success and connection.result.get('result') != 0:
                    logger.error(f"Search failed: {connection.result}")
                    raise LDAPException(f"Search failed: {connection.result}")
                
                # Add entries to results
                for entry in connection.entries:
                    entry_dict = {
                        'dn': entry.entry_dn,
                        'attributes': {}
                    }
                    
                    for attr_name in entry.entry_attributes:
                        attr_value = getattr(entry, attr_name)
                        if hasattr(attr_value, 'value'):
                            entry_dict['attributes'][attr_name] = attr_value.value
                        else:
                            entry_dict['attributes'][attr_name] = str(attr_value)
                    
                    entries.append(entry_dict)
                    
                    # Check size limit
                    if size_limit > 0 and len(entries) >= size_limit:
                        logger.debug(f"Size limit reached: {size_limit}")
                        return entries[:size_limit]
                
                # Check for more pages
                cookie = connection.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                if not cookie:
                    break
            
            logger.debug(f"Search returned {len(entries)} entries")
            return entries
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            raise
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test LDAP connection and return server information.
        
        Returns:
            Dictionary with connection test results
        """
        try:
            connection = self.connect()
            
            # Get server info
            server_info = {
                'connected': True,
                'server': connection.server.host,
                'port': connection.server.port,
                'ssl': connection.server.ssl,
                'bound': connection.bound,
                'user': connection.user
            }
            
            # Try a simple search to test functionality
            try:
                connection.search(
                    search_base=self.ad_config.base_dn,
                    search_filter='(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=['namingContexts']
                )
                server_info['search_test'] = True
            except Exception as e:
                server_info['search_test'] = False
                server_info['search_error'] = str(e)
            
            logger.info("Connection test successful")
            return server_info
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                'connected': False,
                'error': str(e)
            }

