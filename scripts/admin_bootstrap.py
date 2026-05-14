#!/usr/bin/env python3
"""Admin bootstrap: one-shot Ghidra Server operations as the bridgectl SSH user.

Runs inside the bridge image with --entrypoint python3. Used by gmcp CLI to perform
server-admin operations (createRepository, etc.) that can't be done via svrAdmin.

Required env:
  GHIDRA_SERVER_HOST   - server hostname (e.g. ghidra-server)
  GHIDRA_SERVER_PORT   - server port (default 13100)
  GHIDRA_SERVER_USER   - SSH user (default bridgectl)
  GHIDRA_SERVER_KEYSTORE - path to SSH private key

Usage:
  python3 admin_bootstrap.py create-repo <name>
  python3 admin_bootstrap.py list-repos
"""
import os
import sys


def _connect():
    """Bootstrap pyghidra, install SSL/auth, return connected server handle."""
    import pyghidra
    pyghidra.start()

    from ghidra.framework.client import ClientUtil, HeadlessClientAuthenticator
    from java.lang import System
    from javax.net.ssl import HttpsURLConnection, SSLContext
    from java.security import SecureRandom
    import jpype

    @jpype.JImplements("javax.net.ssl.X509TrustManager")
    class AllTrustManager:
        @jpype.JOverride
        def checkClientTrusted(self, chain, authType): pass
        @jpype.JOverride
        def checkServerTrusted(self, chain, authType): pass
        @jpype.JOverride
        def getAcceptedIssuers(self): return None

    @jpype.JImplements("javax.net.ssl.HostnameVerifier")
    class AllHostnameVerifier:
        @jpype.JOverride
        def verify(self, hostname, session): return True

    sc = SSLContext.getInstance("TLS")
    trust_managers = jpype.JArray(jpype.JClass("javax.net.ssl.TrustManager"))([AllTrustManager()])
    sc.init(None, trust_managers, SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier())
    SSLContext.setDefault(sc)
    System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.3")
    System.setProperty("https.protocols", "TLSv1.2,TLSv1.3")

    host = os.environ.get("GHIDRA_SERVER_HOST", "ghidra-server")
    port = int(os.environ.get("GHIDRA_SERVER_PORT", "13100"))
    user = os.environ.get("GHIDRA_SERVER_USER", "bridgectl")
    keystore = os.environ.get("GHIDRA_SERVER_KEYSTORE", "")

    if not keystore or not os.path.exists(keystore):
        sys.stderr.write(f"ERROR: keystore not found: {keystore}\n")
        sys.exit(2)

    HeadlessClientAuthenticator.installHeadlessClientAuthenticator(user, keystore, False)
    handle = ClientUtil.getRepositoryServer(host, port, True)
    if not handle.isConnected():
        sys.stderr.write("ERROR: failed to connect to Ghidra Server\n")
        sys.exit(1)
    return handle


def cmd_create_repo(name):
    handle = _connect()
    bare = name.lstrip("/")
    existing = list(handle.getRepositoryNames() or [])
    if bare in existing:
        print(f"already-exists:{bare}")
        return 0
    handle.createRepository(bare)
    print(f"created:{bare}")
    return 0


def cmd_list_repos():
    handle = _connect()
    for r in handle.getRepositoryNames() or []:
        print(r)
    return 0


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    op = sys.argv[1]
    args = sys.argv[2:]
    try:
        if op == "create-repo":
            if not args:
                sys.stderr.write("ERROR: create-repo requires <name>\n")
                return 2
            return cmd_create_repo(args[0])
        if op == "list-repos":
            return cmd_list_repos()
        sys.stderr.write(f"ERROR: unknown operation '{op}'\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"ERROR: {type(e).__name__}: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
