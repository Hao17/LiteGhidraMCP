#!/usr/bin/env bash
# troubleshoot.sh - Auto-diagnose and fix Ghidra MCP Bridge issues
#
# Usage:
#   ./troubleshoot.sh [check|fix] [--repo REPO]
#
# Commands:
#   check   (default) - Detect problems and show summary
#   fix               - Auto-fix all detected problems

set -euo pipefail

REPOS_DIR="${GHIDRA_DATA_DIR:?GHIDRA_DATA_DIR not set}/${GHIDRA_VERSION:?GHIDRA_VERSION not set}/repos"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PROBLEM_COUNT=0
MODE="check"
FILTER_REPO=""
PROBLEM_COUNT_FILE=$(mktemp)
echo 0 > "$PROBLEM_COUNT_FILE"
trap "rm -f '$PROBLEM_COUNT_FILE'" EXIT

# ============================================
# Argument parsing
# ============================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        check)  MODE="check"; shift ;;
        fix)    MODE="fix"; shift ;;
        --repo) FILTER_REPO="$2"; shift 2 ;;
        *)      echo "Usage: troubleshoot.sh [check|fix] [--repo REPO]"; exit 1 ;;
    esac
done

# ============================================
# Helpers
# ============================================

problem() {
    local count
    count=$(cat "$PROBLEM_COUNT_FILE")
    echo $((count + 1)) > "$PROBLEM_COUNT_FILE"
    echo -e "  ${RED}[PROBLEM]${NC} $1"
}

ok() {
    echo -e "  ${GREEN}[OK]${NC} $1"
}

info() {
    echo -e "  ${DIM}$1${NC}"
}

fix_action() {
    echo -e "  ${CYAN}[FIX]${NC} $1"
}

get_running_container_ids() {
    docker ps --format '{{.ID}}' --filter "name=ghidra" 2>/dev/null || true
}

ts_to_date() {
    local ts_sec=$(($1 / 1000))
    date -r "$ts_sec" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
    date -d "@$ts_sec" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "unknown"
}

# ============================================
# Check: Server running
# ============================================

check_server() {
    echo -e "${BOLD}Server${NC}"

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "ghidra-server"; then
        local status
        status=$(docker inspect --format '{{.State.Health.Status}}' ghidra-server-standalone 2>/dev/null || echo "unknown")
        if [ "$status" = "healthy" ]; then
            ok "Ghidra Server running (healthy)"
        else
            problem "Ghidra Server running but $status"
        fi
    else
        problem "Ghidra Server not running"
        if [ "$MODE" = "fix" ]; then
            fix_action "Cannot auto-start server. Run: make server-up"
        fi
    fi
    echo ""
}

# ============================================
# Check: Client containers
# ============================================

check_clients() {
    echo -e "${BOLD}Clients${NC}"

    local clients
    clients=$(docker ps --format '{{.Names}}\t{{.Status}}' --filter "name=ghidra-mcp-bridge-client" 2>/dev/null || true)

    if [ -z "$clients" ]; then
        info "No client containers running"
        echo ""
        return
    fi

    while IFS=$'\t' read -r name status; do
        if echo "$status" | grep -q "unhealthy"; then
            problem "$name is unhealthy — may be blocked by checkout lock"
        elif echo "$status" | grep -q "healthy"; then
            ok "$name ($status)"
        else
            info "$name ($status)"
        fi
    done <<< "$clients"
    echo ""
}

# ============================================
# Check: Zombie checkouts
# ============================================

check_checkouts() {
    echo -e "${BOLD}Checkout Locks${NC}"

    if [ ! -d "$REPOS_DIR" ]; then
        problem "Repos directory not found: $REPOS_DIR"
        echo ""
        return
    fi

    local running_ids
    running_ids=$(get_running_container_ids)
    local found_any=false

    for repo_dir in "$REPOS_DIR"/*/; do
        local repo_name
        repo_name=$(basename "$repo_dir")

        # Skip system dirs
        [[ "$repo_name" =~ ^(~admin|~ssh|users)$ ]] && continue
        [[ "$repo_name" == *.log* ]] && continue

        # Filter
        if [ -n "$FILTER_REPO" ] && [ "$repo_name" != "$FILTER_REPO" ]; then
            continue
        fi

        for num_dir in "$repo_dir"/*/; do
            [ -d "$num_dir" ] || continue
            [[ "$(basename "$num_dir")" =~ ^[0-9]+$ ]] || continue

            for db_dir in "$num_dir"/~*.db; do
                [ -d "$db_dir" ] || continue
                local checkout_file="$db_dir/checkout.dat"
                [ -f "$checkout_file" ] || continue

                # Fast check: skip if no CHECKOUT ID
                grep -q 'CHECKOUT ID=' "$checkout_file" 2>/dev/null || continue

                # Get file name
                local item_id
                item_id=$(basename "$db_dir" | sed 's/~//;s/.db//')
                local prp_file="$num_dir/${item_id}.prp"
                local file_name="unknown"
                [ -f "$prp_file" ] && file_name=$(grep 'NAME="NAME"' "$prp_file" 2>/dev/null | sed 's/.*VALUE="//;s/".*//' || echo "unknown")
                local parent="/"
                [ -f "$prp_file" ] && parent=$(grep 'NAME="PARENT"' "$prp_file" 2>/dev/null | sed 's/.*VALUE="//;s/".*//' || echo "/")
                local display="${parent%/}/$file_name"

                # Parse each checkout entry
                while read -r line; do
                    local user time_ms project exclusive container_id
                    user=$(echo "$line" | sed 's/.*USER="//;s/".*//')
                    time_ms=$(echo "$line" | sed 's/.*TIME="//;s/".*//')
                    project=$(echo "$line" | sed 's/.*PROJECT="//;s/".*//')
                    exclusive=$(echo "$line" | sed 's/.*EXCLUSIVE="//;s/".*//')
                    container_id=$(echo "$project" | cut -d: -f1)

                    local is_alive=false
                    if [ -n "$running_ids" ]; then
                        echo "$running_ids" | grep -q "^${container_id:0:12}" && is_alive=true
                    fi

                    local lock_label="shared"
                    [ "$exclusive" = "true" ] && lock_label="EXCLUSIVE"

                    if $is_alive; then
                        found_any=true
                        ok "${repo_name}:${display} checked out by ${user} ($lock_label) since $(ts_to_date "$time_ms")"
                    else
                        found_any=true
                        problem "${repo_name}:${display} locked by ${user} ($lock_label) since $(ts_to_date "$time_ms") — container $container_id is dead"
                    fi
                done < <(grep 'CHECKOUT ID=' "$checkout_file" 2>/dev/null)
            done
        done
    done

    if ! $found_any; then
        ok "No checkout locks"
    fi

    echo ""
}

# ============================================
# Fix: Clear zombie checkouts
# ============================================

fix_checkouts() {
    local running_ids
    running_ids=$(get_running_container_ids)
    local cleared=0

    for repo_dir in "$REPOS_DIR"/*/; do
        local repo_name
        repo_name=$(basename "$repo_dir")
        [[ "$repo_name" =~ ^(~admin|~ssh|users)$ ]] && continue
        [[ "$repo_name" == *.log* ]] && continue
        if [ -n "$FILTER_REPO" ] && [ "$repo_name" != "$FILTER_REPO" ]; then
            continue
        fi

        for num_dir in "$repo_dir"/*/; do
            [ -d "$num_dir" ] || continue
            [[ "$(basename "$num_dir")" =~ ^[0-9]+$ ]] || continue

            for db_dir in "$num_dir"/~*.db; do
                [ -d "$db_dir" ] || continue
                local checkout_file="$db_dir/checkout.dat"
                [ -f "$checkout_file" ] || continue
                grep -q 'CHECKOUT ID=' "$checkout_file" 2>/dev/null || continue

                local item_id
                item_id=$(basename "$db_dir" | sed 's/~//;s/.db//')
                local prp_file="$num_dir/${item_id}.prp"
                local file_name="unknown"
                [ -f "$prp_file" ] && file_name=$(grep 'NAME="NAME"' "$prp_file" 2>/dev/null | sed 's/.*VALUE="//;s/".*//' || echo "unknown")

                # Check if ALL checkouts are zombies
                local all_zombie=true
                local has_checkouts=false

                while read -r line; do
                    has_checkouts=true
                    local container_id
                    container_id=$(echo "$line" | sed 's/.*PROJECT="//;s/".*//' | cut -d: -f1)
                    if [ -n "$running_ids" ] && echo "$running_ids" | grep -q "^${container_id:0:12}"; then
                        all_zombie=false
                        break
                    fi
                done < <(grep 'CHECKOUT ID=' "$checkout_file" 2>/dev/null)

                if $has_checkouts && $all_zombie; then
                    local next_id
                    next_id=$(grep -o 'NEXT_ID="[0-9]*"' "$checkout_file" | grep -o '[0-9]*')
                    [ -z "$next_id" ] && next_id="1"

                    cat > "$checkout_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<CHECKOUT_LIST NEXT_ID="${next_id}" />

EOF
                    fix_action "Cleared zombie checkout: $repo_name/$file_name"
                    cleared=$((cleared + 1))
                fi
            done
        done
    done

    if [ "$cleared" -eq 0 ]; then
        echo -e "  ${GREEN}No zombie checkouts to fix${NC}"
    else
        echo -e "  ${GREEN}Cleared $cleared zombie checkout(s)${NC}"
        echo ""
        echo -e "  ${YELLOW}Note:${NC} Restart affected clients for changes to take effect:"
        echo -e "    make client-stop N=<n> && make client N=<n> REPO=<repo> BINARY=<binary>"
    fi
}

# ============================================
# Main
# ============================================

echo ""
echo -e "${BOLD}Ghidra MCP Bridge Troubleshoot${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

check_server
check_clients
check_checkouts

if [ "$MODE" = "check" ]; then
    # Summary
    pcount=$(cat "$PROBLEM_COUNT_FILE")
    echo -e "${BOLD}Summary${NC}"
    if [ "$pcount" -eq 0 ]; then
        echo -e "  ${GREEN}All checks passed.${NC}"
    else
        echo -e "  ${RED}${pcount} problem(s) found.${NC}"
        echo ""
        echo -e "  Run ${BOLD}make troubleshoot-fix${NC} to auto-fix."
    fi
elif [ "$MODE" = "fix" ]; then
    echo -e "${BOLD}Fixing${NC}"
    fix_checkouts
fi

echo ""
