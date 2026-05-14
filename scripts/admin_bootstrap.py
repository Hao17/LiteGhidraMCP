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
  python3 admin_bootstrap.py list-files <repo>
  python3 admin_bootstrap.py release-user-checkouts <user> [<repo>]
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


def cmd_list_files(repo_name):
    """Walk the repo's project tree as bridgectl and print each file's full path.

    Output: one path per line, e.g. `/12.7.0/all_init.o`. Final stderr line
    `# total: <N>` summarises the count. Used by `gmcp server repo ls` to let
    callers discover nested binary paths before passing them to
    `gmcp client start --binary <path>`.
    """
    handle = _connect()
    bare = repo_name.lstrip("/")
    try:
        repo = handle.getRepository(bare)
    except Exception as e:
        sys.stderr.write(f"ERROR: cannot open repo '{bare}': {e}\n")
        return 1
    if repo is None:
        sys.stderr.write(f"ERROR: repo '{bare}' not found\n")
        return 1

    total = 0
    stack = ["/"]
    seen = set()
    while stack:
        folder_path = stack.pop()
        if folder_path in seen:
            continue
        seen.add(folder_path)
        try:
            sub_folders = list(repo.getSubfolderList(folder_path) or [])
        except Exception:
            sub_folders = []
        for sub in sub_folders:
            child = (folder_path.rstrip("/") + "/" + str(sub)) or "/"
            stack.append(child)
        try:
            items = list(repo.getItemList(folder_path) or [])
        except Exception:
            items = []
        for item in items:
            name = str(item.getName())
            full = folder_path.rstrip("/") + "/" + name
            print(full)
            total += 1
    sys.stderr.write(f"# total: {total}\n")
    return 0


def cmd_release_user_checkouts(user, repo_name=None):
    """Terminate every checkout held by `user` on the given repo (or all repos).

    Requires bridgectl's +a admin rights on the target repo(s). Used by
    `gmcp client stop` / `gmcp client clean` after the client container has
    exited, to release any server-side lock the container failed to drop
    (e.g. due to SIGKILL on slow checkin).

    Output: `released:<repo>:<folder>:<file>:<checkout_id>` per terminated lock,
    `total-released:<N>` summary.
    """
    handle = _connect()
    if repo_name:
        repo_names = [repo_name.lstrip("/")]
    else:
        repo_names = [str(r) for r in (handle.getRepositoryNames() or [])]

    total = 0
    for rn in repo_names:
        try:
            repo = handle.getRepository(rn)
        except Exception as e:
            sys.stderr.write(f"WARN: cannot open repo {rn}: {e}\n")
            continue
        if repo is None:
            continue

        # Walk every folder and inspect each item's checkout list.
        stack = ["/"]
        seen = set()
        while stack:
            folder_path = stack.pop()
            if folder_path in seen:
                continue
            seen.add(folder_path)
            try:
                sub_folders = list(repo.getSubfolderList(folder_path) or [])
            except Exception:
                sub_folders = []
            for sub in sub_folders:
                stack.append((folder_path.rstrip("/") + "/" + str(sub)) or "/")
            try:
                items = list(repo.getItemList(folder_path) or [])
            except Exception:
                items = []
            for item in items:
                item_name = str(item.getName())
                try:
                    checkouts = repo.getCheckouts(folder_path, item_name) or []
                except Exception:
                    checkouts = []
                for co in checkouts:
                    if str(co.getUser()) != user:
                        continue
                    cid = co.getCheckoutId()
                    try:
                        repo.terminateCheckout(folder_path, item_name, cid, False)
                        print(f"released:{rn}:{folder_path}:{item_name}:{cid}")
                        total += 1
                    except Exception as e:
                        sys.stderr.write(
                            f"WARN: terminate {rn}{folder_path}/{item_name} cid={cid}: {e}\n"
                        )
    print(f"total-released:{total}")
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
        if op == "list-files":
            if not args:
                sys.stderr.write("ERROR: list-files requires <repo>\n")
                return 2
            return cmd_list_files(args[0])
        if op == "release-user-checkouts":
            if not args:
                sys.stderr.write("ERROR: release-user-checkouts requires <user> [<repo>]\n")
                return 2
            user = args[0]
            repo = args[1] if len(args) > 1 else None
            return cmd_release_user_checkouts(user, repo)
        sys.stderr.write(f"ERROR: unknown operation '{op}'\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"ERROR: {type(e).__name__}: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
