#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

# Get actual directory of this bash script
SDIR="$(dirname "${BASH_SOURCE[0]}")"
SDIR="$(realpath "$SDIR")"

TMPF="/tmp/TEMP.MSG"

function On_exit {
    rm -f "$TMPF"
}

trap On_exit EXIT

function Check_commit {
    printf "%s\n" "$2" > "$TMPF"

    echo "--- Commit $1 ----------"
    cat "$TMPF"
    echo "-----------------------"
    "${SDIR}/check-commit.sh" --noninteractive "$TMPF"
    return $?
}

function Help {
    echo "This script is supposed to be called from the github actions"
    echo ""
    echo "check-commits.sh check-script       Run shellcheck and bashate on check-commit.sh and the script itself"
    echo "check-commits.sh [help|-h|--help]   Show this help"
    echo ""
    exit 7
}

case "${1,,}" in
check-script)
    if shellcheck --help > /dev/null 2>&1 && bashate --help > /dev/null 2>&1; then
        if shellcheck "$0" && bashate -i E006 "$0"; then
            echo "Nothing to complain"
        fi
    else
        echo "Please install shellcheck and bashate to use check-script functionality"
    fi
    exit 7
;;
help|-h|--help)
    Help
;;
"")
    : # Pass
;;
*)
    echo "Invalid parameter: ${1}"
    echo ""
    Help
;;
esac

if [ -z "$GITHUB_CONTEXT" ]; then
    echo "GITHUB_CONTEXT is not set"
    echo ""
    Help
fi

if ! jq --version > /dev/null 2>&1; then
    echo "::error title=ERROR::jq required for check-commits.sh to run"
    exit 254
fi

if ! EVENT="$(jq -r .event_name <<< "$GITHUB_CONTEXT")"; then
    echo "Invalid GITHUB_CONTEXT"
    exit 7
fi

RET=0
case $EVENT in
push)
    COMMITS="$(jq '.event.commits | length' <<< "$GITHUB_CONTEXT")"
    I=0
    while [ "$I" -lt "$COMMITS" ]; do
        CMSG="$(jq -r ".event.commits[${I}].message" <<< "$GITHUB_CONTEXT")"
        I=$((I + 1))
        Check_commit "$I" "$CMSG"
        RET=$((RET | $?))
    done
;;
pull_request)
    HREF="$(jq -r .event.pull_request._links.commits.href <<< "$GITHUB_CONTEXT")"
    if ! JSONS="$(curl -s "$HREF")" || [ "$(jq -r '. | type' <<< "$JSONS")" != "array" ]; then
        echo "::error title=ERROR::Failed to retrieve commits (${HREF})"
        if [ -n "$JSONS" ]; then
            MSG="$(jq -r .message <<< "$JSONS")"
            if [ "$MSG" != "null" ] && [ "$MSG" != "" ]; then
                echo "::error title=MESSAGE::${MSG}"
            fi
        fi
        exit 7
    fi
    COMMITS="$(jq '. | length' <<< "$JSONS")"
    I=0
    while [ "$I" -lt "$COMMITS" ]; do
        CMSG="$(jq -r ".[${I}].commit.message" <<< "$JSONS")"
        I=$((I + 1))
        Check_commit "$I" "$CMSG"
        RET=$((RET | $?))
    done
;;
*)
    echo "::error title=ERROR::Invalid event"
    exit 255
;;
esac

case "$RET" in
1)
    # Return success even if there were warnings
    exit 0
;;
*)
    exit $RET
esac
