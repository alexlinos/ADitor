"""Audit logging for ADitor's LDAP operations."""

import logging
from typing import Optional


def log_ldap_operation(operation: str, dn: str, success: bool, details: Optional[str] = None) -> None:
    """
    Log LDAP operation for audit purposes.
    
    Args:
        operation: Operation type (search, add, modify, delete, etc.)
        dn: Distinguished name involved
        success: Whether operation was successful
        details: Additional details
    """
    logger = logging.getLogger("aditor.audit")
    
    status = "SUCCESS" if success else "FAILED"
    message = f"LDAP {operation.upper()} {status}: {dn}"
    
    if details:
        message += f" - {details}"
    
    if success:
        logger.info(message)
    else:
        logger.warning(message)
