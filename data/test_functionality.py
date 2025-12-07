#!/usr/bin/env python3
"""
Test script to verify KeySentinel Pro functionality
"""

import sys
import os
import sqlite3
import datetime

def test_database():
    """Test database functionality"""
    print("🔍 Testing database functionality...")
    
    try:
        from keylogger_db import KeyloggerThreatDB
        db = KeyloggerThreatDB()
        
        # Test logging a threat
        db.log_threat("test_process.exe", 12345, "Medium", "Detected")
        print("✅ Database logging test passed")
        
        # Test fetching threats
        threats = db.fetch_all_threats()
        print(f"✅ Database fetch test passed - Found {len(threats)} threats")
        
        db.close()
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_process_scanner():
    """Test process scanner functionality"""
    print("🔍 Testing process scanner...")
    
    try:
        from process_scanner import scan_processes_with_scores
        results = scan_processes_with_scores()
        print(f"✅ Process scanner test passed - Found {len(results)} potential threats")
        return True
        
    except Exception as e:
        print(f"❌ Process scanner test failed: {e}")
        return False

def test_report_viewer():
    """Test report viewer functionality"""
    print("🔍 Testing report viewer...")
    
    try:
        from report_viewer import ThreatReportViewer
        print("✅ Report viewer import test passed")
        return True
        
    except Exception as e:
        print(f"❌ Report viewer test failed: {e}")
        return False

def test_process_protection():
    """Test process protection manager"""
    print("🔍 Testing process protection manager...")
    
    try:
        from process_protection_manager import ProcessProtectionManager
        print("✅ Process protection manager import test passed")
        return True
        
    except Exception as e:
        print(f"❌ Process protection manager test failed: {e}")
        return False

def test_advanced_main():
    """Test advanced main application"""
    print("🔍 Testing advanced main application...")
    
    try:
        from advanced_main import AdvancedKeySenintelProApp
        print("✅ Advanced main application import test passed")
        return True
        
    except Exception as e:
        print(f"❌ Advanced main application test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🛡️ KeySentinel Pro Functionality Test")
    print("=" * 50)
    
    tests = [
        ("Database", test_database),
        ("Process Scanner", test_process_scanner),
        ("Report Viewer", test_report_viewer),
        ("Process Protection", test_process_protection),
        ("Advanced Main", test_advanced_main)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Testing {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"⚠️ {test_name} test failed")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! KeySentinel Pro is ready to use.")
        print("\n🚀 To start the application, run:")
        print("   python advanced_main.py")
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
