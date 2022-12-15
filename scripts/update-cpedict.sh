#!/bin/sh

# SPDX-FileCopyrightText: 2022 Unikie
#
# SPDX-License-Identifier: BSD-3-Clause

################################################################################

CPE_URL="https://nvd.nist.gov/feeds/xml/cpe/dictionary/"
CPE_GZ="official-cpe-dictionary_v2.3.xml.gz"

################################################################################

usage () {
    echo "Usage: $(basename "$0") [-h] [-f OUT_FILE]"
    echo ""
    echo "Updates cpe dictionary data from NVD, writing the output to OUT_FILE"
    echo ""
}

################################################################################

main () {
    OPTIND=1
    OUT_FILE=""
    while getopts "hf:" opt; do
        case "${opt}" in
            h)
                usage; exit 0 ;;
            f)
                OUT_FILE=$OPTARG ;;
            *)
                usage; exit 1 ;;
        esac
    done
    shift $((OPTIND-1))
    
    if [ -n "$1" ]; then
        err_print "unexpected arguments"
        usage; exit 1
    fi

    if [ ! "$OUT_FILE" ]; then
        OUT_FILE="$HOME/.cache/sbomnix/cpes.csv"
    fi

    exit_unless_command_exists "curl"
    exit_unless_command_exists "gzip"
    exit_unless_command_exists "sort"
    exit_unless_command_exists "uniq"
    exit_unless_command_exists "cut"
    exit_unless_command_exists "sed"

    outfile="$(realpath "$OUT_FILE" 2>/dev/null || echo "$OUT_FILE")"
    outdir="$(dirname "$outfile")"

    if [ -d "$outfile" ]; then
        err_print "Specified OUT_FILE is a directory, expecting file path instead"
        exit 1
    fi
    mkdir -p "$outdir" || exit 1

    echo "[+] Downloading CPE dictionary"
    ret=$(cd "$outdir" && curl -LO "$CPE_URL/$CPE_GZ" >/dev/null; echo "$?")
    if ! [ "$ret" = "0" ]; then
        err_print "failed to download $CPE_URL/$CPE_GZ"
        exit 1
    fi

    echo "[+] Finding unique cpe identifiers"

    # Print the header line
    echo "\"type\",\"vendor\",\"product\"" >"$outfile"

    # Find unique CPEs by (part:vendor:product), print them to outfile

    if ! gzip -dcf "$outdir/$CPE_GZ" | # uncompress to stdout
        # match only cpe identifiers with type 'a' (application)
        grep -Po "cpe:2\.3:[a]:.*/>" | 
        # replace all '\:' with '!COLON!' (possible escaped ':' in cpe values)
        sed -E 's|\\:|!COLON!|g' |
        # select the three cpe values we are interested (part:vendor:product)
        cut -d":" -f3-5 |
        # remove duplicate and empty lines
        sort | uniq | sed -E '/^$/d' |
        # quote all cpe identifiers in the output
        sed -E 's|([^:]+):([^:]+):([^:]+)|"\1","\2","\3"|g' |
        # replace all '!COLON!' with '\:'
        sed -E 's|!COLON!|\\:|g' \
        >>"$outfile" # write the results to outfile
    then
        err_print "converting '$outdir/$CPE_GZ' to csv failed"
        exit 1
    fi

    # Coarse sanity check for the outfile contents 
    out_lines=$(sed -n '$=' "$outfile")
    if [ "$out_lines" -le 10000 ]; then
        err_print "unexpected output in '$outfile'"
        exit 1
    fi

    # Cleanup
    rm -f "$outdir/$CPE_GZ" 2>/dev/null

    echo "[+] Wrote: $outfile"
    exit 0
}

################################################################################

exit_unless_command_exists () {
    if ! [ -x "$(command -v "$1")" ]; then
        err_print "command '$1' is not installed" >&2
        exit 1
    fi
}

err_print () {
    RED_BOLD='\033[1;31m'
    NC='\033[0m'
    # If stdout is to terminal print colorized error message, otherwise print
    # with no colors
    if [ -t 1 ]; then
        printf "${RED_BOLD}Error:${NC} %s\n" "$1" >&2
    else
        printf "Error: %s\n" "$1" >&2
    fi
}

################################################################################

main "$@"

################################################################################
