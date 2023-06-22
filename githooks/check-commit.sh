#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2021-2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

function Error {
    if [ -z "$NONINTERACTIVE" ]; then
        echo "ERROR: ${1}"
    else
        echo "::error title=ERROR::${1}"
    fi
    FAILED=1
}

function Warning {
    if [ -z "$NONINTERACTIVE" ]; then
        echo "WARNING: ${1}"
    else
        echo "::warning title=WARNING::${1}"
    fi
    WARNED=1
}

# Checks count of given field
function Check_count {
    local field
    local count
    local dest
    local allowmany

    field="$1"
    dest="$2"
    allowmany="${3:-0}"

    count="$(grep -c -e "^${field}:" "$dest" || true)"

    case "$count" in
    0)
        Error "Missing ${field} field"
    ;;
    1)
        : # Ok
    ;;
    *)
        if [ "$allowmany" == "0" ]; then
            Error "Multiple ${field} fields (Only one required and allowed)"
        fi
    ;;
    esac
}

function Exit_message {
    if [ -z "$NONINTERACTIVE" ]; then
        echo ""
        echo "Your commit message is not lost (yet), it's saved in the .git dir of the repo"
        echo "You probably can use something like this to edit your message:"
        echo "git commit -e --file=\$(git rev-parse --git-dir)/COMMIT_EDITMSG"
        echo ""
    fi
    exit 2
}

set -e

MATCH=1
while [ "$MATCH" -eq 1 ]; do
    case "${1,,}" in
    check-script)
        if shellcheck --help > /dev/null 2>&1 && bashate --help > /dev/null 2>&1; then
            if shellcheck "$0" && bashate -i E006 "$0"; then
                echo "Nothing to complain"
            fi
        else
            echo "Please install shellcheck and bashate to use check-script functionality"
        fi
        exit 1
    ;;
    ""|help|-h|--help)
        echo "This script is supposed to be called from the git commit-msg hook (or check-commits.sh)"
        echo ""
        echo "check-commit.sh [--noninteractive] COMMIT_MSG_FILE      Check commit message (noninteractively if specified)"
        echo "check-commit.sh check-script                            Run shellcheck and bashate on the script itself"
        echo "check-commit.sh [help|-h|--help]                        Show this help"
        echo ""
        exit 1
    ;;
    --noninteractive)
        NONINTERACTIVE=1
        shift
    ;;
    *)
        MATCH=0
    ;;
    esac
done

DEST="$1"

if [ -z "$NONINTERACTIVE" ]; then
    # Remove trailing spaces
    sed -i 's/[[:space:]]*$//g' "$DEST"

    # Remove preceding spaces from subject line
    sed -i '1 s/^[[:space:]]*//' "$DEST"

    # Reformat Signed-off-by field
    sed -i 's/^[[:blank:]]*[sS][iI][gG][nN][eE][dD][ _-]*[oO][fF][fF][ _-]*[bB][yY][[:blank:]]*:[[:blank:]]*/Signed-off-by: /g' "$DEST"
fi

SUBJECT="$(head -n 1 "$DEST")"
SECONDLINE="$(head -n 2 "$DEST" | tail -n 1)"
# Get the longest line length ignoring comments and Signed-off-by field
BODYLINELEN="$(grep -v -e "^[[:blank:]]*#" -e "^Signed-off-by:" "$DEST" | tail -n +2 | wc -L | cut -d ' ' -f 1)"

FAILED=
WARNED=

if [ -z "$NONINTERACTIVE" ]; then
    echo ""
fi

if [ -z "$SUBJECT" ]; then
    Error "Subject line is empty"
else
    if [ "${#SUBJECT}" -gt 50 ]; then
        Error "Subject line is longer than 50 characters"
    fi
fi

if [ -n "$SECONDLINE" ]; then
    Error "There is no empty line after subject line"
fi

if [ "$BODYLINELEN" -gt 72 ]; then
    Error "Message body contains lines longer than 72 characters"
fi

Check_count "Signed-off-by" "$DEST" 0

# If first word ends with "ing" or "ed" it is suspected that subject is not in imperative mood.
# If there is a colon (:) in the subject then check the first word after colon. (Allows e.g. a filename at the start)
# As the rule is not perfect, this will only give a warning and confirmation prompt.
if printf "%s" "$SUBJECT" | grep -q -e '\(^.*\?:[[:blank:]]*[^[:blank:]]*\([eE][dD]\|[iI][nN][gG]\)[[:blank:]]\|^[^[:blank:]]*\([eE][dD]\|[iI][nN][gG]\)[[:blank:]]\)'; then
    Warning "Subject might not be in imperative (commanding) mood"
fi

# If first letter of first word is not upper case or if first letter of first word after colon (:) is not upper case
# Incorrect capitalization is suspected. As the rule might not be perfect, this only gives a warning and confirmation prompt.
if printf "%s" "$SUBJECT" | grep -q -e '\(^.*\?:[[:blank:]]*[a-z].*$\|^[a-z][^:]*$\)'; then
    Warning "Subject capitalization might not be correct"
fi

if [ -n "$FAILED" ]; then
    Exit_message
fi

if [ -z "$NONINTERACTIVE" ]; then
    # Grab Signed-off-lines
    SIGNOFF="$(grep -e "^Signed-off-by:" "$DEST")"

    # Delete the Signed-off-by: -line
    sed -i '/^Signed-off-by:/d' "$DEST"

    # Delete leading and trailing empty lines
    sed -i -e '/./,$!d' -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$DEST"

    {
        # Add an empty line
        printf "\n"
        # Add Signed-off-by lines
        printf "%s\n" "$SIGNOFF"
    } >> "$DEST"

    if [ -n "$WARNED" ]; then
        STR=
        while [ -z "$STR" ]; do
            echo -e "\n${SUBJECT}\n"
            echo -n "Are you sure you want to continue with this? (Y/N): "
            read -r STR < /dev/tty
            case "$STR" in
            y|Y)
                echo "Commit message accepted with warnings"
                exit 0
            ;;
            n|N)
                echo "Aborted"
                Exit_message
            ;;
            *)
                STR=
            ;;
            esac
        done
    fi

    echo "Commit message seems OK"
else
    if [ -n "$WARNED" ]; then
        exit 1
    fi
fi
