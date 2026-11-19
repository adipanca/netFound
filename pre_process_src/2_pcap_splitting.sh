#!/bin/bash

set -e
set +x

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 input_folder output_folder"
    exit 1
fi

input_folder="$1"
output_folder="$2"

# Get the directory where the current script is located (to find sctp_split_helper.py)
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$output_folder"

# sctp_split_helper.py dispatches per file: SCTP traffic is split by its own
# association-aware logic (PcapSplitter has no SctpLayer and would otherwise
# merge many distinct SCTP associations into one output file -- see
# reports/fase8/sctp_small_class_diagnosis.md); every other protocol still
# goes straight to PcapSplitter -m connection, unchanged.
find "$input_folder" -type f | parallel "mkdir -p $output_folder/{/.} && python3 $script_dir/sctp_split_helper.py {} $output_folder/{/.}/"
