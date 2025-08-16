#!/usr/bin/env python3
"""
KeySentinel Installation Script
Automatically sets up the environment and installs dependencies
"""

import sys
import subprocess
import os
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_platform():
    """Check if platform is supported"""
    if platform.system() != "Windows":
        print("⚠️  Warning: KeySentinel is optimized for Windows")
        print(f"Current platform: {platform.system()}")
        print("Some features may not work correctly on other platforms")
    else:
        print(f"✅ Platform: {platform.system()} {platform.release()}")
    return True

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        
        # Install requirements
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        
        print("✅ Dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = ["logs", "backups", "config"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def check_admin_privileges():
    """Check if running with admin privileges"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✅ Running with administrator privileges")
        else:
            print("⚠️  Not running with administrator privileges")
            print("Some features may require admin rights")
        return is_admin
    except:
        print("⚠️  Could not determine admin privileges")
        return False

def run_tests():
    """Run basic functionality tests"""
    print("\n🧪 Running basic tests...")
    
    try:
        result = subprocess.run([sys.executable, "test_functionality.py"], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ All tests passed")
            return True
        else:
            print("⚠️  Some tests failed")
            print(result.stdout)
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Tests timed out")
        return False
    except Exception as e:
        print(f"⚠️  Could not run tests: {e}")
        return False

def main():
    """Main installation process"""
    print("🛡️ KeySentinel Installation")
    print("=" * 50)
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    check_platform()
    
    # Check admin privileges
    check_admin_privileges()
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Installation failed. Please check the error messages above.")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Run tests
    run_tests()
    
    print("\n" + "=" * 50)
    print("🎉 Installation completed successfully!")
    print("\n🚀 To start KeySentinel:")
    print("   python Main.py")
    print("\n📚 For more information, check the documentation.")
    print("\n⚠️  Remember to run as administrator for full functionality.")

if __name__ == "__main__":
    main()
