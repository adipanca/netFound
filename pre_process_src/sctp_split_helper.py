#!/usr/bin/env python3
"""Per-file connection splitter used by 2_pcap_splitting.sh.

PcapPlusPlus's PcapSplitter (-m connection) has no SctpLayer (see
reports/fase8/sctp_s4_s5_notes.md), so for SCTP traffic it falls back to a
coarser grouping that merges MANY distinct SCTP associations in one input
file into a SINGLE output "connection" -- confirmed empirically (e.g. one
402-packet NGAP episode contains 38 real associations but PcapSplitter wrote
exactly 1 file for it).

This script processes every packet in the input file and routes it by its
OWN protocol (not a first-packet-peek classification of the whole file --
some captures, e.g. benign's GTP-U-tunneled taps, mix SCTP packets in among
otherwise TCP/UDP/ICMP traffic, and a whole-file classification would wrongly
drop one side or the other):
  - SCTP packets are grouped by the UNORDERED (ip, port) endpoint pair (NOT
    the verification tag, which is direction-asymmetric -- see below) and
    written directly to per-association pcaps.
  - Every other packet is collected into a temp pcap and handed to the
    original PcapSplitter -m connection, completely unchanged -- so a file
    with no SCTP in it behaves exactly as before (zero regression risk).

Association key rationale: SCTP's verification tag is direction-asymmetric
(each endpoint announces its OWN tag during INIT/INIT-ACK, and packets carry
the tag their PEER expects), so keying on it would split one real
bidirectional association into two one-directional halves, undermining
netFound's forward/backward direction detection (the thing the S4 gate
verifies). Keying on the symmetric endpoint pair groups both directions
together, exactly like how PcapSplitter keys TCP/UDP by the (unordered)
4-tuple.
"""
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from scapy.all import PcapReader, PcapWriter, IP, IPv6

SCTP_PROTO = 132


def get_ip_and_proto(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, pkt[IP].proto, pkt[IP].payload
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh, pkt[IPv6].payload
    return None, None, None, None


def main():
    input_file = sys.argv[1]
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    sctp_assoc_writers = {}
    non_sctp_tmp_path = None
    non_sctp_writer = None

    with PcapReader(str(input_file)) as r:
        for pkt in r:
            src_ip, dst_ip, proto, payload_layer = get_ip_and_proto(pkt)
            if src_ip is None:
                continue

            if proto == SCTP_PROTO:
                payload = bytes(payload_layer)
                if len(payload) < 4:
                    continue
                src_port, dst_port = struct.unpack(">HH", payload[0:4])
                ep1 = (src_ip, src_port)
                ep2 = (dst_ip, dst_port)
                key = tuple(sorted([ep1, ep2]))
                if key not in sctp_assoc_writers:
                    idx = len(sctp_assoc_writers)
                    out_path = output_dir / f"assoc-{idx:04d}.pcap"
                    sctp_assoc_writers[key] = PcapWriter(str(out_path), append=False, sync=False)
                sctp_assoc_writers[key].write(pkt)
            else:
                if non_sctp_writer is None:
                    fd, non_sctp_tmp_path = tempfile.mkstemp(suffix=".pcap")
                    os.close(fd)
                    non_sctp_writer = PcapWriter(non_sctp_tmp_path, append=False, sync=False)
                non_sctp_writer.write(pkt)

    n_assoc = len(sctp_assoc_writers)
    for w in sctp_assoc_writers.values():
        w.close()

    if non_sctp_writer is not None:
        non_sctp_writer.close()
        subprocess.run(
            ["PcapSplitter", "-f", non_sctp_tmp_path, "-o", str(output_dir), "-m", "connection"],
            check=True,
        )
        os.unlink(non_sctp_tmp_path)

    print(
        f"{input_file}: sctp_associations={n_assoc} "
        f"had_non_sctp_traffic={non_sctp_writer is not None} -> {output_dir}"
    )


if __name__ == "__main__":
    main()
