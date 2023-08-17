#!/bin/bash

# SPDX-FileCopyrightText: 2022 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

################################################################################

MYDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

remove_dups () {
    if [ -z "$1" ]; then return; fi
    VAR=$1 n='' IFS=':'
    for e in $VAR; do 
        [[ :$n == *:$e:* ]] || n+=$e:
    done
    echo "${n:0: -1}"
}

################################################################################

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: this script needs to be sourced, not executed."
    echo "Re-run with: 'source $0'"
    exit 1
fi

################################################################################

REPOROOTDIR=$(cd "$MYDIR/.." 2>/dev/null && pwd || echo "$MYDIR")
if [ -n "$PYTHONPATH" ]; then
    PYTHONPATH=$REPOROOTDIR:$PYTHONPATH
else
    PYTHONPATH=$REPOROOTDIR
fi
# Remove duplicates from the PYTHONPATH, preserving order
PYTHONPATH=$(remove_dups "$PYTHONPATH")
export PYTHONPATH="$PYTHONPATH"
# Add all subdirs of REPOROOTDIR/scripts/ to PATH
for d in "$REPOROOTDIR/scripts/"*; do if [ -d "$d" ]; then PATH="$d:$PATH"; fi; done
PATH=$(remove_dups "$PATH")
export PATH="$PATH"

################################################################################
