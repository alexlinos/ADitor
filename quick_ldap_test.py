#!/usr/bin/env python3
"""Hızlı LDAP bağlantı testi"""

import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE

def test_openldap():
    print("🔍 OpenLDAP Bağlantı Testi")
    print("=" * 50)
    
    try:
        # Server bağlantısı
        server = Server('192.168.1.100', port=389, get_info=ALL)
        print(f"✅ Server: {server}")
        
        # Bağlantı
        conn = Connection(
            server, 
            user='cn=admin,dc=test,dc=local', 
            password='Admin123!',
            auto_bind=True
        )
        print(f"✅ Connected: {conn}")
        
        # Root DSE bilgileri
        print(f"✅ Naming contexts: {server.info.naming_contexts}")
        print(f"✅ Supported schemas: {len(server.info.schema.object_classes)} object classes")
        
        # Basit arama
        result = conn.search(
            search_base='dc=test,dc=local',
            search_filter='(objectClass=*)',
            search_scope=SUBTREE,
            attributes=['dn', 'objectClass'],
            size_limit=10
        )
        
        print(f"✅ Search result: {result}")
        print(f"✅ Found {len(conn.entries)} entries")
        
        # Entries'leri listele
        for i, entry in enumerate(conn.entries[:5]):
            print(f"   {i+1}. {entry.entry_dn}")
        
        # Connection kapat
        conn.unbind()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_with_mcp_config():
    print("\n🔧 ActiveDirectoryMCP Config ile Test")
    print("=" * 50)
    
    try:
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
        
        from aditor.config.loader import load_config
        from aditor.core.ldap_manager import LDAPManager
        
        # Config yükle
        config = load_config('ad-config/samba-ad-config.json')
        print(f"✅ Config loaded: {config.active_directory.server}")
        
        # LDAP Manager
        ldap_manager = LDAPManager(
            config.active_directory,
            config.security,
            config.performance
        )
        print("✅ LDAP Manager created")
        
        # Connection test
        result = ldap_manager.test_connection()
        print(f"✅ Connection test: {result}")
        
        return result.get('connected', False)
        
    except Exception as e:
        print(f"❌ MCP Config Error: {e}")
        return False

def test_http_api():
    print("\n🌐 HTTP API Testi")
    print("=" * 50)
    
    try:
        import requests
        
        # Health check
        response = requests.get('http://localhost:8813', timeout=5)
        print(f"✅ HTTP Status: {response.status_code}")
        print(f"✅ Response: {response.text[:200]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ HTTP Error: {e}")
        return False

if __name__ == "__main__":
    print("🧪 ActiveDirectoryMCP + OpenLDAP Test Suite")
    print("=" * 60)
    
    # Test 1: Direct LDAP
    ldap_ok = test_openldap()
    
    # Test 2: MCP Config
    mcp_ok = test_with_mcp_config()
    
    # Test 3: HTTP API
    http_ok = test_http_api()
    
    # Summary
    print("\n📊 Test Sonuçları")
    print("=" * 50)
    print(f"🔍 Direct LDAP: {'✅ SUCCESS' if ldap_ok else '❌ FAILED'}")
    print(f"🔧 MCP Config: {'✅ SUCCESS' if mcp_ok else '❌ FAILED'}")
    print(f"🌐 HTTP API: {'✅ SUCCESS' if http_ok else '❌ FAILED'}")
    
    if ldap_ok and mcp_ok and http_ok:
        print("\n🎉 Tüm testler başarılı!")
        print("💡 Web arayüzleri:")
        print("   - LDAP Admin: http://localhost:8080")
        print("   - ActiveDirectoryMCP: http://localhost:8813")
    else:
        print("\n💡 Bazı testler başarısız oldu.")
