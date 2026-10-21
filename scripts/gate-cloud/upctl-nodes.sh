#!/usr/bin/env bash
# upctl-nodes.sh: create, list and delete the UpCloud gate nodes (taso-a,
# taso-b, ...) from a terminal instead of the console.  Runs where your
# UpCloud credentials are (the laptop), never on a gate node.
#
#   scripts/gate-cloud/upctl-nodes.sh check
#   scripts/gate-cloud/upctl-nodes.sh create a b       # taso-a, taso-b
#   scripts/gate-cloud/upctl-nodes.sh list
#   scripts/gate-cloud/upctl-nodes.sh delete a b       # shows what it would delete
#   scripts/gate-cloud/upctl-nodes.sh delete --yes a b # deletes them
#
# Needs upctl (UpCloud's CLI, 3.x) logged in, either `upctl account login
# --with-token` (system keyring) or UPCLOUD_TOKEN in the environment, and
# jq.  The token never goes to a node, the repo or a chat.
#
# What it does, and why (lessons of 2026-10-20/21):
#   create  One server per name: hostname taso-<name>, title "taso gate
#           node taso-<name>", zone $ZONE, the hub's plan unless $PLAN is
#           set, Ubuntu 26.04 (the one public template whose title starts
#           with "Ubuntu Server 26.04", or $OS), your public key.  A
#           first-boot script installs the security updates (a fresh
#           image predates them: the emSign root, 2026-10-21).  Refused if
#           a server with that hostname exists; after creating, checks
#           that exactly one exists (the console's deploy button made
#           duplicates twice).  Prints the public and utility addresses.
#   list    The gate nodes: servers whose title starts with "taso gate
#           node ".  The hub is never one of them.
#   delete  Gate nodes only, by UUID (upctl matches names as globs: a
#           name like taso-* would also match the hub), hub name refused,
#           stopped and deleted with their storage.  Without --yes it only
#           prints what it would delete.
#
# Environment: HUB (taso-test)  ZONE (fi-hel1)  PLAN (the hub's)
#              OS (resolved, see above)  SSH_KEY (~/.ssh/id_ed25519.pub)
#              UPCTL (upctl)
#
# Touches: only servers it creates or that carry its title; nothing on the
# hub.  Then, on each new node: scripts/gate-cloud/README.md, "Setting up".

set -euo pipefail

HUB=${HUB:-taso-test}
ZONE=${ZONE:-fi-hel1}
PLAN=${PLAN:-}
OS=${OS:-}
SSH_KEY=${SSH_KEY:-$HOME/.ssh/id_ed25519.pub}
UPCTL=${UPCTL:-upctl}
TITLE_PREFIX="taso gate node "

die() { echo "error: $*" >&2; exit 1; }
usage() { die "usage: $0 check | create <name>... | list | delete [--yes] <name>..."; }

# Every server as one JSON object per line: uuid, hostname, title.  The
# list's wrapper shape is not relied on: any object with those three keys.
servers() {
    "$UPCTL" server list -o json | jq -c '.. | objects | select(has("uuid") and has("hostname") and has("title")) | {uuid, hostname, title}'
}
by_hostname() { servers | jq -r --arg h "$1" 'select(.hostname == $h) | .uuid'; }
show() { "$UPCTL" server show "$1" -o json; }
address() { # $1 uuid, $2 public|utility: its first IPv4 address
    show "$1" | jq -r --arg t "$2" '[.networking.interfaces[] | select(.type == $t) | .ip_addresses[] | .address | select(contains(":") | not)] | first // "-"'
}
valid_name() { [[ "$1" =~ ^[a-z][a-z0-9-]{0,15}$ ]] && [ "taso-$1" != "$HUB" ]; }

preflight() {
    command -v "$UPCTL" >/dev/null || die "upctl not found (UpCloud's CLI: github.com/UpCloudLtd/upcloud-cli)"
    command -v jq >/dev/null || die "jq not found"
    "$UPCTL" version >/dev/null 2>&1 || die "upctl does not run"
    "$UPCTL" account show >/dev/null 2>&1 || die "upctl is not logged in: upctl account login --with-token (or set UPCLOUD_TOKEN)"
}

resolve_plan() {
    [ -n "$PLAN" ] && return
    local u
    u=$(by_hostname "$HUB")
    [ "$(printf '%s\n' "$u" | grep -c .)" = 1 ] || die "cannot read the plan: no single server with hostname $HUB (set PLAN)"
    PLAN=$(show "$u" | jq -r '.plan // empty')
    [ -n "$PLAN" ] || die "the hub's plan is not in its details (set PLAN)"
}

resolve_os() {
    [ -n "$OS" ] && return
    local found
    found=$("$UPCTL" storage list --public --template -o json \
        | jq -r '[.. | objects | select(has("uuid") and has("title")) | select(.title | startswith("Ubuntu Server 26.04"))] | unique_by(.uuid) | .[] | "\(.uuid)\t\(.title)"')
    [ "$(printf '%s\n' "$found" | grep -c .)" = 1 ] || die "not exactly one public template titled Ubuntu Server 26.04*: ${found:-none} (set OS)"
    OS=${found%%$'\t'*}
    echo "template: ${found#*$'\t'} ($OS)"
}

# The first-boot script: the security updates.  node-setup.sh waits for
# the apt lock it holds, so the roles may start while it runs.
FIRST_BOOT='#!/bin/sh
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get upgrade -y -q
'

cmd=${1:-}; [ $# -gt 0 ] && shift
case "$cmd" in
check)
    preflight
    resolve_plan
    resolve_os
    [ -f "$SSH_KEY" ] || die "no public key at $SSH_KEY (set SSH_KEY)"
    echo "ok: logged in; hub $HUB, zone $ZONE, plan $PLAN, key $SSH_KEY"
    ;;
create)
    [ $# -ge 1 ] || usage
    for n in "$@"; do valid_name "$n" || die "'$n': a name is [a-z][a-z0-9-]* (at most 16), and not the hub's"; done
    preflight
    [ -f "$SSH_KEY" ] || die "no public key at $SSH_KEY (set SSH_KEY)"
    resolve_plan
    resolve_os
    for n in "$@"; do
        [ -z "$(by_hostname "taso-$n")" ] || die "a server with hostname taso-$n exists already (list, or delete it first); nothing created"
    done
    for n in "$@"; do
        h="taso-$n"
        echo "== creating $h ($ZONE, $PLAN)"
        "$UPCTL" server create --hostname "$h" --title "$TITLE_PREFIX$h" --zone "$ZONE" \
            --plan "$PLAN" --os "$OS" --ssh-keys "$SSH_KEY" --user-data "$FIRST_BOOT" --wait >/dev/null
        u=$(by_hostname "$h")
        count=$(printf '%s\n' "$u" | grep -c . || true)
        [ "$count" = 1 ] || die "$count servers with hostname $h after one create: $(echo "$u" | tr '\n' ' ') -- delete the extra one(s) by UUID"
        echo "$h: uuid $u, public $(address "$u" public), utility $(address "$u" utility)"
    done
    echo "next, on each node: scripts/gate-cloud/README.md, \"Setting up\" (the first-boot updates may still be running; the roles wait for them)"
    ;;
list)
    preflight
    servers | jq -r --arg p "$TITLE_PREFIX" 'select(.title | startswith($p)) | "\(.hostname)\t\(.uuid)"' | while IFS=$'\t' read -r h u; do
        echo "$h  uuid $u  state $(show "$u" | jq -r '.state')  public $(address "$u" public)  utility $(address "$u" utility)"
    done
    ;;
delete)
    yes=0
    [ "${1:-}" = --yes ] && { yes=1; shift; }
    [ $# -ge 1 ] || usage
    for n in "$@"; do valid_name "$n" || die "'$n': not a gate node name (the hub, $HUB, is never deleted here)"; done
    preflight
    uuids=()
    for n in "$@"; do
        h="taso-$n"
        found=$(servers | jq -r --arg h "$h" --arg t "$TITLE_PREFIX$h" 'select(.hostname == $h) | "\(.uuid)\t\(.title)"')
        [ -n "$found" ] || die "no server with hostname $h; nothing deleted"
        [ "$(printf '%s\n' "$found" | grep -c .)" = 1 ] || die "several servers with hostname $h: $(echo "$found" | cut -f1 | tr '\n' ' ') -- delete by UUID in the console; nothing deleted"
        [ "${found#*$'\t'}" = "$TITLE_PREFIX$h" ] || die "$h is not titled \"$TITLE_PREFIX$h\" (not made by this script); nothing deleted"
        uuids+=("${found%%$'\t'*}")
        echo "$h: uuid ${found%%$'\t'*}, public $(address "${found%%$'\t'*}" public)"
    done
    if [ "$yes" != 1 ]; then
        echo "would stop and delete the above with their storage; again with --yes to do it"
        exit 0
    fi
    for u in "${uuids[@]}"; do
        "$UPCTL" server delete "$u" --stop --delete-storages >/dev/null
        echo "deleted $u"
    done
    ;;
*) usage ;;
esac
