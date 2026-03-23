#!/usr/bin/env python3
"""
Test Ghidra Server connection to diagnose issues
"""
import os
import sys
import jpype

# Start JVM with Ghidra
os.environ['GHIDRA_INSTALL_DIR'] = '/opt/ghidra'
import pyghidra
pyghidra.start()

# Import required Java classes
from ghidra.framework.client import ClientUtil
from ghidra.framework.client import HeadlessClientAuthenticator
from javax.net.ssl import SSLContext, HttpsURLConnection, SSLParameters
from java.security import SecureRandom
from java.lang import System

print("=== Ghidra Server Connection Test ===")
print()

# Disable SSL hostname verification (same as in main code)
try:
    @jpype.JImplements("javax.net.ssl.X509TrustManager")
    class AllTrustManager:
        @jpype.JOverride
        def checkClientTrusted(self, chain, authType):
            pass
        @jpype.JOverride
        def checkServerTrusted(self, chain, authType):
            pass
        @jpype.JOverride
        def getAcceptedIssuers(self):
            return None

    @jpype.JImplements("javax.net.ssl.HostnameVerifier")
    class AllHostnameVerifier:
        @jpype.JOverride
        def verify(self, hostname, session):
            return True

    sc = SSLContext.getInstance("TLS")
    trust_managers = jpype.JArray(jpype.JClass("javax.net.ssl.TrustManager"))([AllTrustManager()])
    sc.init(None, trust_managers, SecureRandom())

    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier())
    SSLContext.setDefault(sc)

    System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3")
    System.setProperty("https.protocols", "TLSv1.2,TLSv1.3")

    print("✓ SSL configuration applied")
except Exception as e:
    print(f"✗ SSL configuration failed: {e}")
    sys.exit(1)

# Install headless authenticator
SERVER_HOST = "ghidra-server"
SERVER_PORT = 13100
SERVER_USER = "bridge"
SERVER_KEYSTORE = "/root/.ghidra/ssh_key"

print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
print(f"User: {SERVER_USER}")
print(f"Keystore: {SERVER_KEYSTORE}")
print()

try:
    if os.path.exists(SERVER_KEYSTORE):
        print("Installing headless authenticator...")
        HeadlessClientAuthenticator.installHeadlessClientAuthenticator(
            SERVER_USER,
            SERVER_KEYSTORE,
            False
        )
        print("✓ Authenticator installed")
    else:
        print(f"✗ Keystore not found: {SERVER_KEYSTORE}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Authenticator installation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Try to connect
print()
print("Attempting connection...")
try:
    server_handle = ClientUtil.getRepositoryServer(SERVER_HOST, SERVER_PORT, True)
    print(f"Server handle created: {server_handle}")
    print(f"Is connected: {server_handle.isConnected()}")

    if server_handle.isConnected():
        print(f"✓ Connected successfully!")
        print(f"  User: {server_handle.getUser()}")

        repos = server_handle.getRepositoryNames()
        print(f"  Repositories: {list(repos) if repos else '(none)'}")
    else:
        print("✗ Connection failed - isConnected() returned False")
        print()
        print("Debugging info:")
        print(f"  Server handle type: {type(server_handle)}")
        print(f"  Server handle: {server_handle}")

except Exception as e:
    print(f"✗ Connection failed with exception: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
