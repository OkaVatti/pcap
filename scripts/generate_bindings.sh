#!/usr/bin/env bash
#
# Generate Crystal FFI bindings for libpcap.
# This script uses `crystal-lib` to parse pcap.h and produce a Crystal `lib` block.
# It is intended as a development aid; the generated code may need manual adjustments.
#
# Prerequisites:
#   - crystal-lib installed: `shards install crystal-lib` or `crystal-lib` gem?
#   - libpcap development headers (pcap.h) accessible.
#
# Usage:
#   ./scripts/generate_bindings.sh

set -euo pipefail

# Check if crystal-lib is available
if ! command -v crystal-lib &> /dev/null; then
    echo "Error: crystal-lib not found. Please install it via:"
    echo "  shards install --development"
    echo "or"
    echo "  git clone https://github.com/crystal-lang/crystal-lib.git && cd crystal-lib && make"
    exit 1
fi

# Find pcap.h
PCAP_H=$(find /usr/include -name pcap.h 2>/dev/null | head -1)
if [ -z "$PCAP_H" ]; then
    echo "Error: pcap.h not found in /usr/include. Please install libpcap-dev."
    exit 1
fi

OUTPUT_FILE="src/libpcap/lib/lib_pcap_auto.cr"
echo "Generating bindings from $PCAP_H into $OUTPUT_FILE ..."

crystal-lib generate \
    --header "$PCAP_H" \
    --library pcap \
    --output "$OUTPUT_FILE" \
    --include-dirs /usr/include \
    --exclude-functions "pcap_(?!findalldevs|freealldevs|create|activate|set_snaplen|set_promisc|set_timeout|set_buffer_size|set_immediate_mode|set_rfmon|snapshot|datalink|loop|dispatch|next|next_ex|breakloop|compile|setfilter|freecode|stats|open_offline|open_offline_with_tstamp_precision|open_dead|dump_open|dump|dump_close|dump_ftell|geterr|perror|strerror|lookupnet|datalink_val_to_name|datalink_val_to_description|datalink_name_to_val|close|set_tstamp_precision|get_tstamp_precision|set_tstamp_type|list_tstamp_types|free_tstamp_types|set_protocol|dump_open_append|statustostr|setnonblock|getnonblock|get_selectable_fd|setdirection|list_datalinks|free_datalinks|dump_flush|inject|sendpacket)" \
    --typedefs "u_char=UInt8" "u_short=UInt16" "u_int=UInt32"

echo "Generated $OUTPUT_FILE. Please review and integrate manually if needed."