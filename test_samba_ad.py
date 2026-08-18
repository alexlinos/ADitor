#!/usr/bin/env python3
"""
Samba Active Directory test script.
Tests ActiveDirectoryMCP with real Samba AD container.
"""

import os
import sys
import json
import time
import requests

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from aditor.config.loader import load_config
from aditor.core.ldap_manager import LDAPManager
from aditor.tools.user import UserTools
from aditor.tools.group import GroupTools

def wait_for_ad_ready(max_wait=120):
    """Wait for Samba AD to be ready."""
    print("🕐 Waiting for Samba AD to be ready...")
    
    for i in range(max_wait):
        try:
            # Try to connect to LDAP port
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('192.168.1.100', 389))
            sock.close()
            
            if result == 0:
                print(f"✅ Samba AD is ready! (took {i+1} seconds)")
                time.sleep(5)  # Extra wait for full initialization
                return True
                
        except Exception:
            pass
        
        if i % 10 == 0:
            print(f"   Still waiting... ({i+1}/{max_wait}s)")
        time.sleep(1)
    
    print("❌ Timeout waiting for Samba AD")
    return False

def test_samba_ad_connection():
    """Test connection to Samba AD."""
    try:
        # Load Samba AD config
        config = load_config('ad-config/ad-config.json')
        print(f"✅ Config loaded: {config.active_directory.server}")
        
        # Initialize LDAP manager
        ldap_manager = LDAPManager(
            config.active_directory,
            config.security,
            config.performance
        )
        print("✅ LDAP Manager initialized")
        
        # Test connection
        connection_result = ldap_manager.test_connection()
        if connection_result.get('connected'):
            print(f"✅ Connected to Samba AD: {connection_result.get('server')}")
        else:
            print(f"❌ Connection failed: {connection_result.get('error')}")
            return False
        
        # Test user tools
        print("\n👥 Testing User Management...")
        user_tools = UserTools(ldap_manager)
        
        # List users
        users = user_tools.list_users()
        if users and len(users) > 0:
            user_data = json.loads(users[0].text)
            if user_data.get('success'):
                user_list = user_data.get('data', [])
                print(f"✅ Found {len(user_list)} users:")
                
                for user in user_list[:5]:  # Show first 5
                    print(f"   📁 {user.get('name')} ({user.get('username')})")
            else:
                print(f"❌ User query failed: {user_data.get('error')}")
        
        # Test group tools
        print("\n🔐 Testing Group Management...")
        group_tools = GroupTools(ldap_manager)
        
        groups = group_tools.list_groups()
        if groups and len(groups) > 0:
            group_data = json.loads(groups[0].text)
            if group_data.get('success'):
                group_list = group_data.get('data', [])
                print(f"✅ Found {len(group_list)} groups:")
                
                for group in group_list[:5]:  # Show first 5
                    print(f"   👥 {group.get('name')} - {group.get('description', 'No description')}")
            else:
                print(f"❌ Group query failed: {group_data.get('error')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_http_api():
    """Test HTTP API endpoints."""
    print("\n🌐 Testing HTTP API...")
    
    base_url = "http://localhost:8813/activedirectory-mcp"
    
    try:
        # Test health endpoint
        response = requests.post(
            base_url,
            json={"method": "health", "params": {}},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ HTTP API health check: {result}")
        else:
            print(f"❌ HTTP API failed: {response.status_code}")
            return False
        
        # Test list users via HTTP
        response = requests.post(
            base_url,
            json={"method": "list_users", "params": {}},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ HTTP API user listing successful")
        else:
            print(f"❌ HTTP API user listing failed: {response.status_code}")
        
        return True
        
    except Exception as e:
        print(f"❌ HTTP API error: {e}")
        return False

def main():
    """Main test function."""
    print("🏢 Samba Active Directory Test with ActiveDirectoryMCP")
    print("=" * 60)
    
    print("\n📋 Test Environment:")
    print("   🐳 Samba AD Domain Controller: test.local")
    print("   🌐 HTTP API: http://localhost:8813/activedirectory-mcp")
    print("   🖥️ LDAP Admin: http://localhost:8080")
    print("   👤 Admin User: Administrator / Admin123!")
    
    # Wait for AD to be ready
    if not wait_for_ad_ready():
        print("\n💡 To start Samba AD:")
        print("   docker-compose -f docker-samba-ad.yml up -d")
        print("   # Wait 2-3 minutes for full initialization")
        return
    
    print("\n🚀 Starting tests...")
    
    # Test direct connection
    print("\n" + "="*50)
    print("📡 Direct LDAP Connection Test")
    print("="*50)
    success = test_samba_ad_connection()
    
    # Test HTTP API
    print("\n" + "="*50)
    print("🌐 HTTP API Test")
    print("="*50)
    http_success = test_http_api()
    
    # Summary
    print("\n" + "="*50)
    print("📊 Test Summary")
    print("="*50)
    
    if success:
        print("✅ Direct LDAP connection: SUCCESS")
    else:
        print("❌ Direct LDAP connection: FAILED")
    
    if http_success:
        print("✅ HTTP API: SUCCESS")
    else:
        print("❌ HTTP API: FAILED")
    
    if success and http_success:
        print("\n🎉 All tests passed! Samba AD integration successful!")
        print("\n📚 Next steps:")
        print("   1. Use HTTP API in Cursor/VS Code")
        print("   2. Explore LDAP Admin: http://localhost:8080")
        print("   3. Test with real AD operations")
    else:
        print("\n💡 Troubleshooting:")
        print("   1. Check Docker containers: docker ps")
        print("   2. Check AD logs: docker logs samba-ad-dc")
        print("   3. Verify network connectivity")
        print("   4. Wait longer for AD initialization")

if __name__ == "__main__":
    main()
