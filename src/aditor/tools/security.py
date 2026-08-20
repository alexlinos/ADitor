"""Security and audit tools for Active Directory."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import base64
import json

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
from mcp.types import TextContent as Content

from .base import BaseTool
from ..core.logging import log_ldap_operation


class SecurityTools(BaseTool):
    """Tools for Active Directory security operations and auditing."""

    # Real user accounts only. `(objectClass=user)` on its own also matches
    # computers (and msDS-ManagedServiceAccounts), because in the AD schema
    # `computer` derives from `user`; objectCategory is single-valued, so
    # `person` excludes them.
    USER_ACCOUNT_FILTER = "(&(objectCategory=person)(objectClass=user))"

    def _is_computer_account(self, attributes: Dict[str, Any]) -> bool:
        """True if this entry is a machine account rather than a person.

        Checks objectClass, then falls back to the trailing ``$`` that AD
        mandates on a machine account's sAMAccountName, so an entry fetched
        without objectClass is still recognised.
        """
        object_classes = {
            str(value).lower()
            for value in self._get_attr_list(attributes, 'objectClass')
        }
        if object_classes & {'computer', 'msds-managedserviceaccount',
                             'msds-groupmanagedserviceaccount'}:
            return True

        sam_account_name = self._get_attr_value(attributes, 'sAMAccountName', '') or ''
        return str(sam_account_name).endswith('$')


    def get_domain_info(self) -> List[Dict[str, Any]]:
        """
        Get domain information and security settings.
        
        Returns:
            List of MCP content objects with domain information
        """
        try:
            # Get domain root object
            domain_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter="(objectClass=domain)",
                attributes=[
                    'name', 'dc', 'objectSid', 'whenCreated', 'whenChanged',
                    'lockoutThreshold', 'lockoutDuration', 'maxPwdAge', 'minPwdAge',
                    'minPwdLength', 'pwdHistoryLength', 'forceLogoff',
                    'msDS-Behavior-Version', 'gPLink'
                ],
                search_scope=ldap3.BASE
            )
            
            if not domain_results:
                raise Exception("Domain information not found")
            
            domain_entry = domain_results[0]
            # Handle bytes objects for JSON serialization
            object_sid = self._get_attr_value(domain_entry['attributes'], 'objectSid', b'')
            if isinstance(object_sid, bytes):
                object_sid = base64.b64encode(object_sid).decode('utf-8')

            domain_info = {
                'dn': domain_entry['dn'],
                'name': self._get_attr_value(domain_entry['attributes'], 'name', ''),
                'domain_component': self._get_attr_value(domain_entry['attributes'], 'dc', ''),
                'object_sid': object_sid,
                'when_created': self._get_attr_value(domain_entry['attributes'], 'whenCreated'),
                'when_changed': self._get_attr_value(domain_entry['attributes'], 'whenChanged')
            }

            # Password policy information
            password_policy = {
                'lockout_threshold': self._get_attr_value(domain_entry['attributes'], 'lockoutThreshold', 0),
                'lockout_duration': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'lockoutDuration', 0)),
                'max_password_age': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'maxPwdAge', 0)),
                'min_password_age': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'minPwdAge', 0)),
                'min_password_length': self._get_attr_value(domain_entry['attributes'], 'minPwdLength', 0),
                'password_history_length': self._get_attr_value(domain_entry['attributes'], 'pwdHistoryLength', 0)
            }
            
            domain_info['password_policy'] = password_policy
            domain_info['domain_functional_level'] = self._get_attr_value(
                domain_entry['attributes'], 'msDS-Behavior-Version', 'unknown'
            )
            
            log_ldap_operation("get_domain_info", self.ldap.ad_config.base_dn, True, "Retrieved domain information")
            
            return self._format_response(domain_info, "get_domain_info")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_domain_info", self.ldap.ad_config.base_dn)
    
    def get_privileged_groups(self) -> List[Dict[str, Any]]:
        """
        Get information about privileged groups in the domain.
        
        Returns:
            List of MCP content objects with privileged group information
        """
        try:
            # Well-known privileged groups
            privileged_groups = [
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Account Operators", "Backup Operators",
                "Print Operators", "Server Operators", "Domain Controllers"
            ]
            
            groups_info = []
            
            for group_name in privileged_groups:
                try:
                    # Search for the group
                    group_results = self.ldap.search(
                        search_base=self.ldap.ad_config.base_dn,
                        search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                        attributes=['sAMAccountName', 'displayName', 'description', 'member', 'objectSid']
                    )
                    
                    if group_results:
                        group_entry = group_results[0]
                        members = self._get_attr_list(group_entry['attributes'], 'member')

                        # Handle bytes objects for JSON serialization
                        object_sid = self._get_attr_value(group_entry['attributes'], 'objectSid', b'')
                        if isinstance(object_sid, bytes):
                            object_sid = base64.b64encode(object_sid).decode('utf-8')

                        group_info = {
                            'dn': group_entry['dn'],
                            'sam_account_name': self._get_attr_value(group_entry['attributes'], 'sAMAccountName', ''),
                            'display_name': self._get_attr_value(group_entry['attributes'], 'displayName', ''),
                            'description': self._get_attr_value(group_entry['attributes'], 'description', ''),
                            'member_count': len(members),
                            'members': members[:10],  # First 10 members
                            'object_sid': object_sid
                        }
                        
                        if len(members) > 10:
                            group_info['members_truncated'] = True
                            group_info['total_members'] = len(members)
                        
                        groups_info.append(group_info)
                        
                except LDAPException:
                    # Bind/connection failures must surface as errors, not an
                    # empty-success payload — re-raise to the outer handler.
                    raise
                except Exception as group_error:
                    # Continue with other groups if one fails
                    self.logger.warning(f"Failed to get info for group {group_name}: {group_error}")
                    continue
            
            log_ldap_operation("get_privileged_groups", self.ldap.ad_config.base_dn, True, f"Retrieved {len(groups_info)} privileged groups")
            
            return self._format_response({
                "privileged_groups": groups_info,
                "total_groups": len(groups_info)
            }, "get_privileged_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_privileged_groups", self.ldap.ad_config.base_dn)
    
    def get_user_permissions(self, username: str) -> List[Dict[str, Any]]:
        """
        Get effective permissions for a user by analyzing group memberships.
        
        Args:
            username: Username to analyze permissions for
            
        Returns:
            List of MCP content objects with user permission information
        """
        try:
            # Get user information
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName', 'displayName', 'memberOf', 'userAccountControl']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user_permissions")
            
            user_entry = user_results[0]
            member_of = user_entry['attributes'].get('memberOf', [])
            
            # Analyze group memberships
            group_analysis = []
            privileged_groups = []
            
            for group_dn in member_of:
                try:
                    group_info = self.ldap.search(
                        search_base=group_dn,
                        search_filter="(objectClass=group)",
                        attributes=['sAMAccountName', 'displayName', 'description', 'objectSid'],
                        search_scope=ldap3.BASE
                    )
                    
                    if group_info:
                        group_data = group_info[0]['attributes']
                        group_name = self._get_attr_value(group_data, 'sAMAccountName', '')

                        group_entry = {
                            'dn': group_dn,
                            'sam_account_name': group_name,
                            'display_name': self._get_attr_value(group_data, 'displayName', ''),
                            'description': self._get_attr_value(group_data, 'description', '')
                        }

                        # Check if it's a privileged group
                        if self._is_privileged_group(group_name):
                            group_entry['privileged'] = True
                            privileged_groups.append(group_entry)
                        else:
                            group_entry['privileged'] = False

                        group_analysis.append(group_entry)

                except Exception:
                    # Skip groups that can't be analyzed
                    continue

            # Check account status
            uac = self._get_attr_value(user_entry['attributes'], 'userAccountControl', 0)
            account_status = {
                'enabled': not bool(uac & 0x0002),  # ACCOUNTDISABLE
                'locked': bool(uac & 0x0010),       # LOCKOUT
                'password_not_required': bool(uac & 0x0020),  # PASSWD_NOTREQD
                'password_cant_change': bool(uac & 0x0040),   # PASSWD_CANT_CHANGE
                'password_never_expires': bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
            }

            user_permissions = {
                'username': username,
                'user_dn': user_entry['dn'],
                'display_name': self._get_attr_value(user_entry['attributes'], 'displayName', ''),
                'account_status': account_status,
                'total_groups': len(member_of),
                'privileged_groups_count': len(privileged_groups),
                'privileged_groups': privileged_groups,
                'all_groups': group_analysis,
                'security_assessment': self._assess_user_security(account_status, privileged_groups)
            }
            
            log_ldap_operation("get_user_permissions", username, True, f"Analyzed permissions for user: {username}")
            
            return self._format_response(user_permissions, "get_user_permissions")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_user_permissions", username)
    
    def get_inactive_users(self, days: int = 90, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """
        Get users who haven't logged in for specified number of days.
        
        Args:
            days: Number of days to consider inactive (default: 90)
            include_disabled: Include disabled accounts in results (default: False)
            
        Returns:
            List of MCP content objects with inactive user information
        """
        try:
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_filetime = self._convert_datetime_to_filetime(cutoff_date)
            
            # Build search filter
            search_filter = "(objectClass=user)"
            if not include_disabled:
                search_filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            
            # Search for all users
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=[
                    'sAMAccountName', 'displayName', 'mail', 'lastLogon',
                    'pwdLastSet', 'userAccountControl', 'whenCreated', 'memberOf'
                ]
            )
            
            inactive_users = []
            for entry in results:
                last_logon = self._get_attr_value(entry['attributes'], 'lastLogon', 0)
                last_logon_dt = self._normalize_filetime(last_logon)

                # Check if user is inactive (never logged on, or before cutoff)
                if last_logon_dt is None or last_logon_dt < cutoff_date:
                    uac = self._get_attr_value(entry['attributes'], 'userAccountControl', 0)
                    member_of = self._get_attr_list(entry['attributes'], 'memberOf')

                    user_info = {
                        'dn': entry['dn'],
                        'sam_account_name': self._get_attr_value(entry['attributes'], 'sAMAccountName', ''),
                        'display_name': self._get_attr_value(entry['attributes'], 'displayName', ''),
                        'mail': self._get_attr_value(entry['attributes'], 'mail', ''),
                        'last_logon': last_logon_dt.isoformat() if last_logon_dt else 'Never',
                        'days_inactive': (datetime.now() - last_logon_dt).days if last_logon_dt else None,
                        'enabled': not bool(uac & 0x0002),
                        'group_count': len(member_of),
                        'has_privileged_groups': self._has_privileged_groups(member_of)
                    }

                    inactive_users.append(user_info)
            
            # Sort by days inactive (descending)
            inactive_users.sort(key=lambda x: x['days_inactive'] or 99999, reverse=True)
            
            log_ldap_operation("get_inactive_users", self.ldap.ad_config.base_dn, True, f"Found {len(inactive_users)} inactive users")
            
            return self._format_response({
                "inactive_users": inactive_users,
                "count": len(inactive_users),
                "criteria_days": days,
                "include_disabled": include_disabled,
                "cutoff_date": cutoff_date.isoformat()
            }, "get_inactive_users")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_inactive_users", self.ldap.ad_config.base_dn)
    
    def get_password_policy_violations(self, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """
        Get enabled user accounts with password policy violations.

        Covers user accounts only (never computers) and, by default, only
        enabled ones: a disabled account cannot authenticate, so its password
        state is housekeeping rather than a policy breach. Whatever is left out
        is counted in ``excluded_counts`` so a short list can be told apart from
        a clean domain.

        Args:
            include_disabled: Include disabled accounts in results (default: False)

        Returns:
            List of MCP content objects with password policy violation information
        """
        try:
            # Get domain password policy first
            domain_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter="(objectClass=domain)",
                attributes=['maxPwdAge', 'minPwdAge'],
                search_scope=ldap3.BASE
            )
            
            if not domain_results:
                raise Exception("Could not retrieve domain password policy")

            max_pwd_age_raw = self._get_attr_value(domain_results[0]['attributes'], 'maxPwdAge', 0)

            # Convert timedelta to FILETIME integer if needed
            if isinstance(max_pwd_age_raw, timedelta):
                # Convert timedelta to 100-nanosecond intervals (negative for AD)
                max_pwd_age = int(max_pwd_age_raw.total_seconds() * 10000000)
            else:
                max_pwd_age = max_pwd_age_raw if max_pwd_age_raw is not None else 0

            # Search for users.
            #
            # (objectClass=user) is NOT a user filter: in AD `computer` is a
            # subclass of `user`, so a bare objectClass search returns every
            # machine account too (40 of them on the live domain). Machine
            # passwords are rotated automatically by the machine, so they are
            # not a password-policy finding about a person. objectCategory is
            # single-valued and indexed, and person/computer are distinct
            # categories, which is what makes this the correct discriminator.
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=self.USER_ACCOUNT_FILTER,
                attributes=[
                    'sAMAccountName', 'displayName', 'pwdLastSet',
                    'userAccountControl', 'accountExpires', 'objectClass'
                ]
            )

            violations = []
            # An account can be exempt from maxPwdAge rather than in breach of it;
            # count those instead of silently dropping the finding.
            exempt_from_expiry = 0
            computer_accounts = 0
            disabled_accounts = 0
            accounts_examined = 0
            current_time = self._convert_datetime_to_filetime(datetime.now())

            for entry in user_results:
                # Belt and braces behind the filter above: never report a
                # machine account in a user password-policy report, whatever the
                # directory returned.
                if self._is_computer_account(entry['attributes']):
                    computer_accounts += 1
                    continue

                uac = self._get_attr_value(entry['attributes'], 'userAccountControl', 0)

                # Disabled accounts are filtered here rather than in the LDAP
                # filter on purpose: the count of what was left out is the whole
                # point of reporting it, and a directory-side filter would make
                # it unknowable. 328 of the live domain's 545 hits were disabled.
                if bool(uac & 0x0002) and not include_disabled:  # ACCOUNTDISABLE
                    disabled_accounts += 1
                    continue

                accounts_examined += 1
                pwd_last_set_raw = self._get_attr_value(entry['attributes'], 'pwdLastSet', 0)
                account_expires_raw = self._get_attr_value(entry['attributes'], 'accountExpires', 0)

                # Convert datetime objects to FILETIME integers if needed
                if isinstance(pwd_last_set_raw, datetime):
                    pwd_last_set = self._convert_datetime_to_filetime(pwd_last_set_raw)
                else:
                    pwd_last_set = pwd_last_set_raw if pwd_last_set_raw is not None else 0

                if isinstance(account_expires_raw, datetime):
                    account_expires = self._convert_datetime_to_filetime(account_expires_raw)
                else:
                    account_expires = account_expires_raw if account_expires_raw is not None else 0

                user_violations = []
                password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD

                # Check if password never expires but should
                if password_never_expires and max_pwd_age != 0:
                    user_violations.append("Password set to never expire")

                # Check if password not required
                if bool(uac & 0x0020):  # PASSWD_NOTREQD
                    user_violations.append("Password not required")

                # Check if account expired
                if account_expires != 0 and account_expires != 9223372036854775807 and account_expires < current_time:
                    user_violations.append("Account expired")

                # Check if password is old (only if max age is set).
                #
                # DONT_EXPIRE_PASSWORD exempts the account from maxPwdAge
                # entirely, so such a password is never "expired" no matter how
                # old it is. Reporting both "Password expired" and "Password set
                # to never expire" on one account is self-contradictory; the
                # never-expire finding above already carries the real concern.
                # Count the suppression so the reader can see it happened.
                if max_pwd_age != 0 and pwd_last_set != 0:
                    password_age = current_time - pwd_last_set
                    if password_age > abs(max_pwd_age):
                        if password_never_expires:
                            exempt_from_expiry += 1
                        else:
                            user_violations.append("Password expired")

                # Check if password never set
                if pwd_last_set == 0:
                    user_violations.append("Password never set")

                if user_violations:
                    violation_info = {
                        'dn': entry['dn'],
                        'sam_account_name': self._get_attr_value(entry['attributes'], 'sAMAccountName', ''),
                        'display_name': self._get_attr_value(entry['attributes'], 'displayName', ''),
                        'violations': user_violations,
                        'enabled': not bool(uac & 0x0002),
                        'pwd_last_set': self._convert_filetime_to_datetime(pwd_last_set) if pwd_last_set > 0 else 'Never'
                    }

                    violations.append(violation_info)
            
            log_ldap_operation(
                "get_password_policy_violations",
                self.ldap.ad_config.base_dn,
                True,
                f"Found {len(violations)} violations across {accounts_examined} "
                f"accounts (excluded {disabled_accounts} disabled, "
                f"{computer_accounts} computer; {exempt_from_expiry} exempt from expiry)"
            )
            
            return self._format_response({
                "password_violations": violations,
                "count": len(violations),
                "include_disabled": include_disabled,
                "accounts_examined": accounts_examined,
                "excluded_counts": {
                    "disabled_accounts": disabled_accounts,
                    "computer_accounts": computer_accounts,
                    "exempt_from_expiry": exempt_from_expiry,
                },
                "notes": [
                    "excluded_counts.disabled_accounts: accounts skipped because "
                    "they are disabled and cannot authenticate. Pass "
                    "include_disabled=true to include them.",
                    "excluded_counts.exempt_from_expiry: accounts whose password "
                    "is older than maxPwdAge but which carry "
                    "DONT_EXPIRE_PASSWORD. maxPwdAge does not apply to them, so "
                    "they are exempt rather than expired and are reported only "
                    "as 'Password set to never expire'.",
                    "excluded_counts.computer_accounts: machine accounts dropped "
                    "after the search. This report covers user accounts only; "
                    "machine passwords are rotated automatically by the machine. "
                    "The search filter already excludes computers, so on a "
                    "healthy directory this is 0.",
                ],
            }, "get_password_policy_violations")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_password_policy_violations", self.ldap.ad_config.base_dn)
    
    def audit_admin_accounts(self) -> List[Dict[str, Any]]:
        """
        Audit administrative accounts for security compliance.

        Every account carries a ``risk_level`` rating how exploitable it is (see
        :meth:`_assess_admin_risk` for the ladder and the reasoning) plus
        ``risk_drivers`` saying what drove that rating, and the payload restates
        the model in ``risk_model``. Rating everything HIGH would leave a reader
        with nothing to prioritise.

        Returns:
            List of MCP content objects with admin account audit information
        """
        try:
            # Get members of privileged groups
            privileged_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
            
            admin_accounts = []
            
            for group_name in privileged_groups:
                try:
                    group_results = self.ldap.search(
                        search_base=self.ldap.ad_config.base_dn,
                        search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                        attributes=['member']
                    )
                    
                    if group_results:
                        members = self._get_attr_list(group_results[0]['attributes'], 'member')

                        for member_dn in members:
                            # Get user details
                            user_results = self.ldap.search(
                                search_base=member_dn,
                                search_filter="(objectClass=user)",
                                attributes=[
                                    'sAMAccountName', 'displayName', 'mail',
                                    'userAccountControl', 'lastLogon', 'pwdLastSet',
                                    'logonCount', 'badPwdCount', 'servicePrincipalName'
                                ],
                                search_scope=ldap3.BASE
                            )

                            if user_results:
                                user_entry = user_results[0]
                                attributes = user_entry['attributes']
                                uac = self._get_attr_value(attributes, 'userAccountControl', 0)

                                enabled = not bool(uac & 0x0002)           # ACCOUNTDISABLE
                                password_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
                                password_not_required = bool(uac & 0x0020)    # PASSWD_NOTREQD

                                spns = [
                                    str(spn) for spn in
                                    self._get_attr_list(attributes, 'servicePrincipalName')
                                ]

                                pwd_last_set_dt = self._normalize_filetime(
                                    self._get_attr_value(attributes, 'pwdLastSet', 0)
                                )
                                password_age_days = (
                                    max(0, (datetime.now() - pwd_last_set_dt).days)
                                    if pwd_last_set_dt else None
                                )

                                # Check last logon (may be datetime or FILETIME int)
                                last_logon = self._get_attr_value(attributes, 'lastLogon', 0)
                                last_logon_dt = self._normalize_filetime(last_logon)
                                days_since_logon = max(0, (datetime.now() - last_logon_dt).days) if last_logon_dt else None

                                security_issues = self._admin_security_issues(
                                    enabled=enabled,
                                    password_never_expires=password_never_expires,
                                    password_not_required=password_not_required,
                                    spns=spns,
                                    password_age_days=password_age_days,
                                    days_since_logon=days_since_logon,
                                )

                                risk = self._assess_admin_risk(
                                    enabled=enabled,
                                    password_never_expires=password_never_expires,
                                    password_not_required=password_not_required,
                                    has_spn=bool(spns),
                                    password_age_days=password_age_days,
                                    days_since_logon=days_since_logon,
                                )

                                admin_info = {
                                    'dn': user_entry['dn'],
                                    'sam_account_name': self._get_attr_value(attributes, 'sAMAccountName', ''),
                                    'display_name': self._get_attr_value(attributes, 'displayName', ''),
                                    'mail': self._get_attr_value(attributes, 'mail', ''),
                                    'privileged_group': group_name,
                                    'enabled': enabled,
                                    'last_logon': last_logon_dt.isoformat() if last_logon_dt else 'Never',
                                    'days_since_logon': days_since_logon,
                                    'password_last_set': pwd_last_set_dt.isoformat() if pwd_last_set_dt else 'Never',
                                    'password_age_days': password_age_days,
                                    'password_never_expires': password_never_expires,
                                    'password_not_required': password_not_required,
                                    'spn_count': len(spns),
                                    'logon_count': self._get_attr_value(attributes, 'logonCount', 0),
                                    'bad_pwd_count': self._get_attr_value(attributes, 'badPwdCount', 0),
                                    'security_issues': security_issues,
                                    'risk_level': risk['level'],
                                    'risk_drivers': risk['drivers']
                                }

                                # Avoid duplicates
                                if not any(acc['sam_account_name'] == admin_info['sam_account_name'] for acc in admin_accounts):
                                    admin_accounts.append(admin_info)
                                
                except LDAPException:
                    # Bind/connection failures must surface as errors, not an
                    # empty-success payload — re-raise to the outer handler.
                    raise
                except Exception as group_error:
                    self.logger.warning(f"Failed to audit group {group_name}: {group_error}")
                    continue
            
            # Sort by severity, then name. Sorting on the level *string* put
            # HIGH, LOW, MEDIUM in that order, which is not a priority order.
            admin_accounts.sort(
                key=lambda x: (self.ADMIN_RISK_ORDER.get(x['risk_level'], 99),
                               x['sam_account_name'])
            )

            log_ldap_operation("audit_admin_accounts", self.ldap.ad_config.base_dn, True, f"Audited {len(admin_accounts)} admin accounts")

            return self._format_response({
                "admin_accounts": admin_accounts,
                "total_admin_accounts": len(admin_accounts),
                "high_risk_count": len([acc for acc in admin_accounts if acc['risk_level'].lower() == 'high']),
                "medium_risk_count": len([acc for acc in admin_accounts if acc['risk_level'].lower() == 'medium']),
                "low_risk_count": len([acc for acc in admin_accounts if acc['risk_level'].lower() == 'low']),
                "risk_model": self._admin_risk_model_description(),
            }, "audit_admin_accounts")
            
        except Exception as e:
            return self._handle_ldap_error(e, "audit_admin_accounts", self.ldap.ad_config.base_dn)
    
    def _convert_time_interval(self, value: Any) -> Dict[str, Any]:
        """Convert AD time interval to human readable format.

        ldap3 may return Integer8 interval attributes (maxPwdAge, minPwdAge,
        lockoutDuration) as a timedelta when the schema is loaded, or as a raw
        100-nanosecond count (negative for intervals). Normalize to int first.
        """
        if isinstance(value, timedelta):
            value = int(value.total_seconds() * 10000000)

        if not value or abs(value) >= 0x7FFFFFFFFFFFFFF8:
            # 0 or the 0x8000000000000000 sentinel both mean "never"
            return {"raw": 0, "description": "Never"}

        # AD time intervals are in 100-nanosecond units (negative for intervals)
        seconds = abs(value) / 10000000
        
        if seconds < 60:
            return {"raw": value, "seconds": seconds, "description": f"{seconds:.0f} seconds"}
        elif seconds < 3600:
            minutes = seconds / 60
            return {"raw": value, "seconds": seconds, "description": f"{minutes:.0f} minutes"}
        elif seconds < 86400:
            hours = seconds / 3600
            return {"raw": value, "seconds": seconds, "description": f"{hours:.0f} hours"}
        else:
            days = seconds / 86400
            return {"raw": value, "seconds": seconds, "description": f"{days:.0f} days"}
    
    def _is_privileged_group(self, group_name: str) -> bool:
        """Check if a group is considered privileged."""
        privileged_groups = [
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "account operators", "backup operators",
            "print operators", "server operators", "domain controllers",
            "cert publishers", "dns admins", "group policy creator owners"
        ]
        return group_name.lower() in privileged_groups
    
    def _has_privileged_groups(self, member_of: List[str]) -> bool:
        """Check if user is member of any privileged groups."""
        for group_dn in member_of:
            # Extract CN from DN
            if group_dn.upper().startswith('CN='):
                cn_end = group_dn.find(',')
                if cn_end > 3:
                    group_name = group_dn[3:cn_end]
                    if self._is_privileged_group(group_name):
                        return True
        return False
    
    def _assess_user_security(self, account_status: Dict[str, Any], privileged_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess user security risk level."""
        risk_factors = []
        risk_level = "low"
        
        if not account_status['enabled']:
            risk_factors.append("Account disabled")
        
        if account_status['password_not_required']:
            risk_factors.append("Password not required")
            risk_level = "high"
        
        if account_status['password_never_expires'] and privileged_groups:
            risk_factors.append("Privileged account with non-expiring password")
            risk_level = "high"
        
        if len(privileged_groups) > 0:
            risk_factors.append(f"Member of {len(privileged_groups)} privileged groups")
            if risk_level == "low":
                risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": self._get_security_recommendation(risk_level, risk_factors)
        }
    
    # ---- Privileged-account risk model (P2-WP6) ----------------------------
    # The thresholds are named constants, not inline numbers, so the judgement
    # is auditable and can be asserted in tests.
    #
    # Any domain user can request a service ticket for an SPN-bearing account
    # and crack it offline at their leisure, so such an account's only defences
    # are password length and rotation. A year is the longest rotation interval
    # mainstream guidance tolerates for a service account - Microsoft's own
    # managed service accounts rotate every 30 days - so past a year the
    # credential has had unbounded offline exposure.
    KERBEROASTABLE_PASSWORD_AGE_DAYS = 365

    # A non-expiring privileged credential older than five years cannot have
    # been rotated in response to any breach, staff departure or guidance change
    # in that window, and is far past "we rotate annually and slipped".
    STALE_ADMIN_PASSWORD_DAYS = 1825

    # An unused privileged account is a removal candidate; on its own it is not
    # a way in. Reported from 90 days, escalated at 180. Note that lastLogon is
    # per-DC and not replicated, so this signal reads older than reality on a
    # multi-DC domain - a second reason it never drives HIGH by itself.
    STALE_LOGON_REPORT_DAYS = 90
    STALE_LOGON_MEDIUM_DAYS = 180

    ADMIN_RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    def _admin_security_issues(
        self,
        *,
        enabled: bool,
        password_never_expires: bool = False,
        password_not_required: bool = False,
        spns: Optional[List[str]] = None,
        password_age_days: Optional[int] = None,
        days_since_logon: Optional[int] = None,
    ) -> List[str]:
        """List the reportable findings for one privileged account.

        Reporting and severity are deliberately separate: everything worth
        telling the reader about is listed here, and
        :meth:`_assess_admin_risk` decides how much of it is exploitable.
        """
        spns = spns or []
        issues: List[str] = []

        if not enabled:
            issues.append("Account disabled")

        if password_never_expires:
            issues.append("Password never expires")

        if password_not_required:
            issues.append("Password not required")

        if spns:
            issues.append(
                f"Service principal name set on a privileged account ({len(spns)} SPN)"
            )

        # Reported from the kerberoasting threshold whether or not an SPN is
        # set: a year-old privileged password is worth a reader's attention
        # even where it is not the top of the ladder.
        if (password_age_days is not None
                and password_age_days >= self.KERBEROASTABLE_PASSWORD_AGE_DAYS):
            issues.append(f"Password unchanged for {password_age_days} days")

        if (days_since_logon is not None
                and days_since_logon > self.STALE_LOGON_REPORT_DAYS):
            issues.append(f"No logon for {days_since_logon} days")

        return issues

    def _assess_admin_risk(
        self,
        *,
        enabled: bool,
        password_never_expires: bool = False,
        password_not_required: bool = False,
        has_spn: bool = False,
        password_age_days: Optional[int] = None,
        days_since_logon: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Rate one privileged account, and say why.

        Severity here means *how usable this account is to an attacker*, so
        that a reader with seven admins to triage can tell them apart. The
        ladder:

        HIGH - reachable today:
          * ``PASSWD_NOTREQD`` on an enabled account (the password may be empty
            and the length policy does not apply to it);
          * an enabled account with an SPN whose password is at least
            :attr:`KERBEROASTABLE_PASSWORD_AGE_DAYS` old (kerberoastable: the
            documented path from any domain user to Domain Admin);
          * an enabled non-expiring password at least
            :attr:`STALE_ADMIN_PASSWORD_DAYS` old.

        MEDIUM - weakens the account without handing anyone a way in:
          non-expiring password, an SPN with a fresher (or unknown-age)
          password, or no logon for :attr:`STALE_LOGON_MEDIUM_DAYS`+ days.

        LOW - informational: a disabled account (it cannot authenticate, so
          nothing about it is exploitable - it should still be removed from the
          privileged group), a 90-179 day logon gap, or nothing found.

        Password *age* is used rather than the never-expire flag alone: a
        non-expiring password set last quarter is a different proposition from
        one set eleven years ago, and flattening them was half of why every
        account came back HIGH.
        """
        # A disabled account cannot authenticate. Rating it HIGH (as this model
        # used to) put untidiness above an enabled account with no password
        # required, which is backwards.
        if not enabled:
            return {
                "level": "LOW",
                "drivers": [
                    "Account is disabled, so it cannot authenticate and is not "
                    "exploitable. Still worth removing from the privileged group."
                ],
            }

        high: List[str] = []

        if password_not_required:
            high.append(
                "PASSWD_NOTREQD is set on an enabled privileged account: its "
                "password may be empty and the domain minimum-length policy "
                "does not apply to it."
            )

        if (has_spn and password_age_days is not None
                and password_age_days >= self.KERBEROASTABLE_PASSWORD_AGE_DAYS):
            high.append(
                f"Kerberoastable: an SPN is set and the password has not changed "
                f"for {password_age_days} days, so any authenticated domain user "
                f"can request a service ticket for it and crack it offline with "
                f"no lockout or rate limit."
            )

        if (password_never_expires and password_age_days is not None
                and password_age_days >= self.STALE_ADMIN_PASSWORD_DAYS):
            high.append(
                f"Password never expires and has not changed for "
                f"{password_age_days} days, so this privileged credential has "
                f"survived every incident and policy change of that period."
            )

        if high:
            return {"level": "HIGH", "drivers": high}

        medium: List[str] = []

        if password_never_expires:
            age = ("age unknown" if password_age_days is None
                   else f"{password_age_days} days old")
            medium.append(
                f"Password never expires ({age}), so the domain maximum password "
                f"age does not apply to a privileged account."
            )

        if has_spn:
            medium.append(
                "An SPN is set on a privileged account, which exposes it to "
                "kerberoasting; the password is recent enough that offline "
                "cracking is the limiting factor."
            )

        if (days_since_logon is not None
                and days_since_logon >= self.STALE_LOGON_MEDIUM_DAYS):
            medium.append(
                f"No logon recorded for {days_since_logon} days: privilege that "
                f"nobody is using, and misuse would be unlikely to be noticed."
            )

        if medium:
            return {"level": "MEDIUM", "drivers": medium}

        drivers: List[str] = []
        if (days_since_logon is not None
                and days_since_logon > self.STALE_LOGON_REPORT_DAYS):
            drivers.append(
                f"No logon recorded for {days_since_logon} days; below the "
                f"{self.STALE_LOGON_MEDIUM_DAYS}-day threshold that raises this "
                f"to MEDIUM."
            )

        return {"level": "LOW", "drivers": drivers}

    def _admin_risk_model_description(self) -> Dict[str, Any]:
        """The risk model, stated in the payload so a verdict can be checked."""
        return {
            "levels": ["HIGH", "MEDIUM", "LOW"],
            "meaning": "How usable the account is to an attacker today, not how "
                       "untidy it is.",
            "HIGH": [
                "PASSWD_NOTREQD on an enabled account",
                f"enabled account with an SPN and a password at least "
                f"{self.KERBEROASTABLE_PASSWORD_AGE_DAYS} days old (kerberoastable)",
                f"enabled account with a non-expiring password at least "
                f"{self.STALE_ADMIN_PASSWORD_DAYS} days old",
            ],
            "MEDIUM": [
                "non-expiring password on an enabled account",
                "SPN on an enabled account with a more recent password",
                f"no logon for {self.STALE_LOGON_MEDIUM_DAYS}+ days",
            ],
            "LOW": [
                "disabled account: it cannot authenticate, so it is not "
                "exploitable, but it should be removed from the privileged group",
                f"no logon for {self.STALE_LOGON_REPORT_DAYS}-"
                f"{self.STALE_LOGON_MEDIUM_DAYS - 1} days",
                "nothing found",
            ],
            "caveats": [
                "days_since_logon comes from lastLogon, which is maintained "
                "per-domain-controller and is not replicated, so it can read far "
                "older than reality. Treat a staleness finding as a prompt to "
                "check every DC, not as proof. This is why staleness never "
                "drives HIGH on its own.",
                "password_age_days comes from pwdLastSet; 'Never' means the "
                "account must change its password at next logon, and the age is "
                "reported as null rather than guessed.",
            ],
        }

    def _calculate_admin_risk_level(self, **facts: Any) -> str:
        """Risk level for one privileged account.

        Thin wrapper over :meth:`_assess_admin_risk`, which carries the model
        and the reasoning; takes the same keyword arguments.
        """
        return self._assess_admin_risk(**facts)['level']


    def _get_security_recommendation(self, risk_level: str, risk_factors: List[str]) -> str:
        """Get security recommendation based on risk assessment."""
        if risk_level == "HIGH":
            return "Immediate action required: Review and remediate high-risk security issues"
        elif risk_level == "MEDIUM":
            return "Review account permissions and consider implementing additional security controls"
        else:
            return "Monitor account activity and maintain current security posture"
    
    def _convert_filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
    
    def _convert_datetime_to_filetime(self, dt: datetime) -> int:
        """Convert datetime to Windows FILETIME."""
        from datetime import timezone

        # If dt is timezone-aware, convert to UTC and make naive
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)

        epoch = datetime(1601, 1, 1)
        delta = dt - epoch
        return int(delta.total_seconds() * 10000000)
    
    def _normalize_filetime(self, value: Any) -> Optional[datetime]:
        """Normalize a lastLogon/pwdLastSet value to a naive-UTC datetime, or None if unset.

        ldap3 may return these Integer8 timestamp attributes either as a
        (timezone-aware) datetime when the schema is loaded, or as a raw
        Windows FILETIME integer. Handle both, plus the 0/never sentinel.
        """
        from datetime import timezone
        if value in (0, None, ''):
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            try:
                ft = int(value)
            except (TypeError, ValueError):
                return None
            if ft <= 0 or ft >= 0x7FFFFFFFFFFFFFFF:
                return None
            dt = self._convert_filetime_to_datetime(ft)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    def _get_days_since_last_logon(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Get number of days since last logon."""
        last_logon = attributes.get('lastLogon') if 'lastLogon' in attributes \
            else self._get_attr_value(attributes, 'lastLogon', 0)
        last_logon_date = self._normalize_filetime(last_logon)
        if last_logon_date is None:
            return None
        return (datetime.now() - last_logon_date).days
    
    # Baseline thresholds the domain password policy is evaluated against.
    # Kept explicit (and asserted in tests) so the judgement is auditable.
    MIN_PASSWORD_LENGTH = 8
    MIN_PASSWORD_HISTORY = 5

    def check_password_policy(self) -> List[Content]:
        """
        Evaluate the domain password policy against ADitor's baseline.

        Reads the real domain policy through :meth:`get_domain_info` and compares
        the keys that method actually emits inside ``password_policy``
        (``min_password_length`` and ``password_history_length``) against
        :attr:`MIN_PASSWORD_LENGTH` / :attr:`MIN_PASSWORD_HISTORY`.

        Lockout settings are reported for context but not scored: lockout
        thresholds are a Phase-2 hardening-catalog decision.

        Returns:
            List of MCP content objects with the compliance assessment
        """
        try:
            # get_domain_info returns List[Content], parse the JSON response
            domain_response = self.get_domain_info()
            if not domain_response:
                return self._format_response(
                    {
                        'success': False,
                        'error': 'Domain info not found',
                        'operation': 'check_password_policy',
                    },
                    'check_password_policy'
                )

            domain_info = json.loads(domain_response[0].text)

            # get_domain_info only sets 'success' when it failed.
            if not domain_info.get('success', True):
                return self._format_response(
                    {
                        'success': False,
                        'error': domain_info.get('error', 'Unknown error'),
                        'operation': 'check_password_policy',
                    },
                    'check_password_policy'
                )

            pwd_policy = domain_info.get('password_policy', {})
            min_length = self._as_int(pwd_policy.get('min_password_length'))
            history_length = self._as_int(pwd_policy.get('password_history_length'))

            checks = [
                {
                    'check': 'minimum_password_length',
                    'attribute': 'min_password_length',
                    'required_minimum': self.MIN_PASSWORD_LENGTH,
                    'actual': min_length,
                    'passed': min_length >= self.MIN_PASSWORD_LENGTH
                },
                {
                    'check': 'password_history_length',
                    'attribute': 'password_history_length',
                    'required_minimum': self.MIN_PASSWORD_HISTORY,
                    'actual': history_length,
                    'passed': history_length >= self.MIN_PASSWORD_HISTORY
                }
            ]

            recommendations = []
            if not checks[0]['passed']:
                recommendations.append(
                    f'Increase minimum password length to at least '
                    f'{self.MIN_PASSWORD_LENGTH} characters'
                )
            if not checks[1]['passed']:
                recommendations.append(
                    f'Increase password history to at least '
                    f'{self.MIN_PASSWORD_HISTORY} passwords'
                )

            compliance = {
                'policy_compliant': all(check['passed'] for check in checks),
                'checks': checks,
                'recommendations': recommendations,
                'password_policy': pwd_policy,
                # get_domain_info reports lockout settings inside password_policy;
                # surface them here for context (reported, not scored).
                'lockout_policy': {
                    'lockout_threshold': pwd_policy.get('lockout_threshold'),
                    'lockout_duration': pwd_policy.get('lockout_duration')
                }
            }

            log_ldap_operation(
                'check_password_policy',
                self.ldap.ad_config.base_dn,
                True,
                f"Password policy compliant: {compliance['policy_compliant']}"
            )

            return self._format_response(compliance, 'check_password_policy')

        except Exception as e:
            return self._handle_ldap_error(e, 'check_password_policy', 'domain')

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        """Coerce an LDAP-sourced policy value to int, defaulting on junk."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default


    def _assess_account_risk(self, account_data: Dict[str, Any]) -> str:
        """Assess risk level of an account."""
        risk_score = 0
        
        # Check for admin privileges
        member_of = account_data.get('memberOf', [])
        admin_groups = ['Domain Admins', 'Enterprise Admins', 'Administrators']
        for group in member_of:
            if any(admin_group in group for admin_group in admin_groups):
                risk_score += 30
        
        # Check last logon
        last_logon_days = self._get_days_since_last_logon(account_data)
        if last_logon_days and last_logon_days > 90:
            risk_score += 20
        elif last_logon_days and last_logon_days > 30:
            risk_score += 10
            
        # Check password age
        pwd_age = self._calculate_password_age(account_data)
        if pwd_age and pwd_age > 365:
            risk_score += 25
        elif pwd_age and pwd_age > 180:
            risk_score += 15
            
        # Determine risk level
        if risk_score >= 50:
            return 'high'
        elif risk_score >= 25:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_password_age(self, account_data: Dict[str, Any]) -> Optional[int]:
        """Calculate password age in days."""
        pwd_last_set = self._get_attr_value(account_data, 'pwdLastSet', 0)
        if pwd_last_set == 0 or pwd_last_set is None:
            return -1  # Test expects -1 for never set or None

        try:
            # Handle datetime objects directly (for tests)
            if isinstance(pwd_last_set, datetime):
                pwd_set_date = pwd_last_set
            else:
                pwd_set_date = self._convert_filetime_to_datetime(pwd_last_set)
            return (datetime.now() - pwd_set_date).days
        except:
            return -1  # Test expects -1 for errors

    def generate_security_report(self) -> List[Content]:
        """
        Generate a comprehensive security report.

        PROTOTYPE -- deliberately not registered as an MCP tool. This is the seed
        of ADitor's Phase-2 report pipeline (see docs/HARDENING_CATALOG.md) and is
        superseded by it; its shape is not committed to. It aggregates the real
        get_domain_info, audit_admin_accounts, get_privileged_groups and
        check_password_policy results. Findings are pass/fail evidence: there is
        deliberately no aggregate score.

        Returns:
            List of MCP content objects with the aggregated report
        """
        try:
            report_timestamp = datetime.now().isoformat()

            # Collect data from various security methods
            domain_info_response = self.get_domain_info()
            admin_audit_response = self.audit_admin_accounts()
            privileged_groups_response = self.get_privileged_groups()
            password_policy_response = self.check_password_policy()

            # Parse responses (they are List[Content])
            domain_info = json.loads(domain_info_response[0].text) if domain_info_response else {}
            admin_audit = json.loads(admin_audit_response[0].text) if admin_audit_response else {}
            privileged_groups = json.loads(privileged_groups_response[0].text) if privileged_groups_response else {}
            password_policy = json.loads(password_policy_response[0].text) if password_policy_response else {}
            
            # Generate executive summary
            total_admins = admin_audit.get('total_admin_accounts', 0)
            high_risk_admins = admin_audit.get('high_risk_count', 0)
            total_privileged_groups = privileged_groups.get('total_groups', 0)
            policy_compliant = password_policy.get('policy_compliant', True)
            
            executive_summary = {
                'total_admin_accounts': total_admins,
                'high_risk_admin_accounts': high_risk_admins,
                'total_privileged_groups': total_privileged_groups,
                'password_policy_compliant': policy_compliant
            }
            
            # Detailed findings
            detailed_findings = {
                'domain_information': domain_info,
                'admin_account_audit': admin_audit,
                'privileged_groups_analysis': privileged_groups,
                'password_policy_assessment': password_policy
            }
            
            report = {
                'report_timestamp': report_timestamp,
                'executive_summary': executive_summary,
                'detailed_findings': detailed_findings,
                'recommendations': self._generate_security_recommendations(executive_summary)
            }
            
            return self._format_response(report, "generate_security_report")
            
        except Exception as e:
            return self._handle_ldap_error(e, "generate_security_report", "security_report")
    
    def _generate_security_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if summary.get('high_risk_admin_accounts', 0) > 0:
            recommendations.append("Review and remediate high-risk administrative accounts")
            
        if not summary.get('password_policy_compliant', True):
            recommendations.append("Update password policy to meet security standards")

        return recommendations or ["Security posture appears satisfactory - continue regular monitoring"]

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for security operations."""
        return {
            "operations": [
                "get_domain_info", "get_privileged_groups", "get_user_permissions",
                "get_inactive_users", "get_password_policy_violations", "audit_admin_accounts",
                "check_password_policy", "generate_security_report"
            ],
            "security_attributes": [
                "userAccountControl", "memberOf", "lastLogon", "pwdLastSet",
                "accountExpires", "lockoutTime", "badPwdCount", "logonCount"
            ],
            "privileged_groups": [
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Account Operators", "Backup Operators"
            ],
            "required_permissions": [
                "Read Domain Security Policy", "Read User Attributes",
                "Read Group Membership", "Audit User Activity"
            ],
            "risk_levels": ["low", "medium", "high", "critical"],
            "operation_parameters": {
                "get_user_permissions": {"username": "string, required"},
                "get_inactive_users": {
                    "days": "integer, default 90",
                    "include_disabled": "boolean, default false",
                },
                "get_password_policy_violations": {
                    "include_disabled": "boolean, default false",
                },
            },
            "admin_risk_model": self._admin_risk_model_description(),
            "notes": [
                "audit_admin_accounts rates each privileged account HIGH/MEDIUM/"
                "LOW by how usable it is to an attacker (see admin_risk_model), "
                "and carries risk_drivers per account. The generic risk_levels "
                "list above is the lowercase scale used by get_user_permissions.",
                "get_inactive_users and get_stale_computers read lastLogon, "
                "which is maintained per-domain-controller and is not "
                "replicated, so on a multi-DC domain they can report an active "
                "account as stale. Known limitation, not yet fixed: the fix is "
                "lastLogonTimestamp, or querying every DC and taking the "
                "maximum.",
                "get_password_policy_violations reports user accounts only "
                "((objectCategory=person)(objectClass=user)): in the AD schema "
                "`computer` derives from `user`, so a bare (objectClass=user) "
                "filter would report machine accounts, whose passwords are "
                "rotated automatically by the machine. It excludes disabled "
                "accounts unless include_disabled is set, and never reports a "
                "DONT_EXPIRE_PASSWORD account as expired, because maxPwdAge "
                "does not apply to it. Everything left out is counted in "
                "excluded_counts.",
            ],
        }
