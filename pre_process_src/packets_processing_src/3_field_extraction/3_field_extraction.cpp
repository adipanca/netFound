#include <iostream>
#include <fstream>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <IcmpLayer.h>
#include <filesystem>
#include <vector>

uint8_t getTcpFields(const pcpp::tcphdr *tcpheader) {
    uint8_t flags = 0;
    if (tcpheader->cwrFlag) {
        flags |= 1 << 7;
    }
    if (tcpheader->eceFlag) {
        flags |= 1 << 6;
    }
    if (tcpheader->urgFlag) {
        flags |= 1 << 5;
    }
    if (tcpheader->ackFlag) {
        flags |= 1 << 4;
    }
    if (tcpheader->pshFlag) {
        flags |= 1 << 3;
    }
    if (tcpheader->rstFlag) {
        flags |= 1 << 2;
    }
    if (tcpheader->synFlag) {
        flags |= 1 << 1;
    }
    if (tcpheader->finFlag) {
        flags |= 1;
    }
    return flags;
}

// PcapPlusPlus has no SCTP entry in ProtocolType.h / IPProtocolTypes -- use the raw
// IANA protocol number directly (see also pre_process_src/packets_processing_src/
// 1_filter/1_filter.cpp, which needed the same workaround).
constexpr uint8_t SCTP_PROTOCOL_NUMBER = 132;

int process_file(const std::string input_file, const std::string output_file, bool tcpoptions_flag, bool no_payload_flag) {
    // Open the input pcap file
    auto *reader = pcpp::IFileReaderDevice::getReader(input_file);
    if (reader == nullptr) {
        std::cerr << "Cannot determine reader for file: " << input_file << std::endl;
        return 1;
    }
    if (!reader->open()) {
        std::cerr << "Error opening input pcap file: " << input_file << std::endl;
        return 1;
    }

    std::ofstream outputFileStream;

    pcpp::RawPacket rawPacket;
    uint64_t packetCount = 0;
    uint8_t global_protocol;
    uint32_t absolute_seq_src_ip = 0;
    uint32_t tcp_absolute_seq = 0;
    uint32_t tcp_absolute_ack = 0;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        uint8_t *data;
        size_t data_len;

        uint8_t ipversion = 4;

        // Here you would extract each field as per your requirements and write to outputFile
        // Example for IP and TCP fields:

        pcpp::IPv4Layer *ipLayer = nullptr;
        pcpp::IPv6Layer *ipv6Layer = nullptr;

        ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == nullptr) {
            ipversion = 6;
            ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
            if (ipv6Layer == nullptr) {
                std::cerr << "File " << input_file << " contains packets with unknown network layer protocol: " << std::to_string(ipversion) << std::endl;
                return 1;
            }
        }

        // getting protocol number
        uint8_t protocol;
        if (ipversion == 4) {
            protocol = ipLayer->getIPv4Header()->protocol;
        } else {
            protocol = ipv6Layer->getIPv6Header()->nextHeader;
        }

        if (packetCount == 0) {
            global_protocol = protocol;

            // rename output file to <outputfilename>.<protocol_number>
            std::string outputFilename(output_file);
            if (tcpoptions_flag && protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP) {
                outputFilename += ".tcpoptions";
            }
            outputFilename += "." + std::to_string(protocol);

            // Create and open the output file
            outputFileStream.open(outputFilename, std::ios::binary | std::ios::out);
            if (!outputFileStream.is_open()) {
                std::cerr << "Error opening output file: " << outputFilename << std::endl;
                return 1;
            }

            outputFileStream.write(reinterpret_cast<const char*>(&protocol), sizeof(protocol));
        }

        if (protocol != global_protocol) {
            std::cerr << "File " << input_file << " contains packets with different protocols. " <<
                      "Protocol of the first packet: " << std::to_string(global_protocol) << ", current packet number: " << packetCount <<
                      ", current protocol: " << std::to_string(protocol) << std::endl;
            return 1;
        }

        // we are guaranteed to have ipLayer

        // unixtime with nanoseconds, frame.time_epoch
        uint64_t epoch = rawPacket.getPacketTimeStamp().tv_sec * static_cast<uint64_t>(1000000000L) + rawPacket.getPacketTimeStamp().tv_nsec;

        uint8_t ip_hdr_len;
        if (ipversion == 4) {
            // value * 32bits to find out number of bytes in the header, ip.hdr_len
            constexpr uint8_t IHL_INCREMENTS_BYTES = 4;
            ip_hdr_len = ipLayer->getIPv4Header()->internetHeaderLength * IHL_INCREMENTS_BYTES;
        } else {
            ip_hdr_len = 40;
        }

        uint8_t type_of_service;
        if (ipversion == 4) {
            // ip.dsfield
            type_of_service = ipLayer->getIPv4Header()->typeOfService;
        } else {
            type_of_service = ipv6Layer->getIPv6Header()->trafficClass;
        }

        // total length of the packet, ip.len, big endian -> little endian
        uint16_t total_length;
        if (ipversion == 4) {
            total_length = ipLayer->getIPv4Header()->totalLength;
        } else {
            total_length = ipv6Layer->getIPv6Header()->payloadLength;
        }
        total_length = ((total_length & 0xff00) >> 8) | ((total_length & 0x00ff) << 8);
        if (ipversion == 6) {
            // ipv6 includes only payload length
            total_length += 40;
        }

        // ip.flags
        uint8_t flags;
        if (ipversion == 4) {
            flags = ipLayer->getFragmentFlags();
            //aligning the 3bit flags
            flags = flags >> 5;
        } else {
            flags = 0;
        }

        // ip.ttl
        uint8_t ttl;
        if (ipversion == 4) {
            ttl = ipLayer->getIPv4Header()->timeToLive;
        } else {
            ttl = ipv6Layer->getIPv6Header()->hopLimit;
        }

        // ip.src, big endian -> little endian
        uint32_t src_ip;
        if (ipversion == 4) {
            src_ip = ipLayer->getSrcIPv4Address().toInt();
            src_ip = ((src_ip & 0xff000000) >> 24) | ((src_ip & 0x00ff0000) >> 8) | ((src_ip & 0x0000ff00) << 8) | ((src_ip & 0x000000ff) << 24);
        } else {
            // legacy - only have 32bit for address - let's get first 32bits of ipv6
            uint8_t *src_ip_ptr = ipv6Layer->getIPv6Header()->ipSrc;
            src_ip = src_ip_ptr[0] << 24 | src_ip_ptr[1] << 16 | src_ip_ptr[2] << 8 | src_ip_ptr[3];
        }
        if (packetCount == 0) {
            absolute_seq_src_ip = src_ip;
        }

        // ip.dst, big endian -> little endian
        uint32_t dst_ip;
        if (ipversion == 4) {
            dst_ip = ipLayer->getDstIPv4Address().toInt();
            dst_ip = ((dst_ip & 0xff000000) >> 24) | ((dst_ip & 0x00ff0000) >> 8) | ((dst_ip & 0x0000ff00) << 8) | ((dst_ip & 0x000000ff) << 24);
        } else {
            // legacy - only have 32bit for address - let's get first 32bits of ipv6
            uint8_t *dst_ip_ptr = ipv6Layer->getIPv6Header()->ipDst;
            dst_ip = dst_ip_ptr[0] << 24 | dst_ip_ptr[1] << 16 | dst_ip_ptr[2] << 8 | dst_ip_ptr[3];
        }

        outputFileStream.write(reinterpret_cast<const char*>(&epoch), sizeof(epoch));
        outputFileStream.write(reinterpret_cast<const char*>(&ip_hdr_len), sizeof(ip_hdr_len));
        outputFileStream.write(reinterpret_cast<const char*>(&type_of_service), sizeof(type_of_service));
        outputFileStream.write(reinterpret_cast<const char*>(&total_length), sizeof(total_length));
        outputFileStream.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
        outputFileStream.write(reinterpret_cast<const char*>(&ttl), sizeof(ttl));
        outputFileStream.write(reinterpret_cast<const char*>(&src_ip), sizeof(src_ip));
        outputFileStream.write(reinterpret_cast<const char*>(&dst_ip), sizeof(dst_ip));

        // based on protocol number, we can determine which layer to get
        if (protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_TCP) {
            auto *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer == nullptr) {
                std::cerr << "File " << input_file << " contains packets with unknown transport layer protocol during TCP parsing: " << std::to_string(protocol) << std::endl;
                return 1;
            }

            // tcp.srcport, big endian -> little endian
            uint16_t src_port = tcpLayer->getTcpHeader()->portSrc;
            src_port = ((src_port & 0xff00) >> 8) | ((src_port & 0x00ff) << 8);

            // tcp.dstport, big endian -> little endian
            uint16_t dst_port = tcpLayer->getTcpHeader()->portDst;
            dst_port = ((dst_port & 0xff00) >> 8) | ((dst_port & 0x00ff) << 8);

            // tcp.flags
            uint8_t tcp_flags = getTcpFields(tcpLayer->getTcpHeader());

            // tcp.window_size, big endian -> little endian
            uint16_t tcp_window_size = tcpLayer->getTcpHeader()->windowSize;
            tcp_window_size = ((tcp_window_size & 0xff00) >> 8) | ((tcp_window_size & 0x00ff) << 8);

            // tcp.seq, big endian -> little endian
            uint32_t tcp_seq = tcpLayer->getTcpHeader()->sequenceNumber;
            tcp_seq = ((tcp_seq & 0xff000000) >> 24) | ((tcp_seq & 0x00ff0000) >> 8) | ((tcp_seq & 0x0000ff00) << 8) | ((tcp_seq & 0x000000ff) << 24);

            // tcp.ack, big endian -> little endian
            uint32_t tcp_ack = tcpLayer->getTcpHeader()->ackNumber;
            tcp_ack = ((tcp_ack & 0xff000000) >> 24) | ((tcp_ack & 0x00ff0000) >> 8) | ((tcp_ack & 0x0000ff00) << 8) | ((tcp_ack & 0x000000ff) << 24);

            if (packetCount == 0) {
                tcp_absolute_seq = tcp_seq;
            }
            if (packetCount == 0 && tcp_ack!=0) {
                //this would be the case where the session the capture was started midway
                tcp_absolute_ack = tcp_ack;
            } else if (packetCount == 1 && tcp_absolute_ack == 0) {
                //this should be the ideal case where the 2nd packet is ack and the first packet had 0 as ack, the ack in response is present in the seq number
                tcp_absolute_ack = tcp_seq;
            }

            if (src_ip == absolute_seq_src_ip) {
                tcp_seq -= tcp_absolute_seq;
            } else {
                tcp_seq -= tcp_absolute_ack;
            }

            if (src_ip == absolute_seq_src_ip) {
                if (tcp_absolute_ack == 0){
                    // this will be 0 only when the ack is 0 in the first packet
                    tcp_ack = 0;
                } else {
                    tcp_ack -= tcp_absolute_ack;
                }
            } else {
                tcp_ack -= tcp_absolute_seq;
            }

            // tcp.urgent_pointer, big endian -> little endian
            uint16_t tcp_urgent_pointer = tcpLayer->getTcpHeader()->urgentPointer;
            tcp_urgent_pointer = ((tcp_urgent_pointer & 0xff00) >> 8) | ((tcp_urgent_pointer & 0x00ff) << 8);

            outputFileStream.write(reinterpret_cast<const char*>(&src_port), sizeof(src_port));
            outputFileStream.write(reinterpret_cast<const char*>(&dst_port), sizeof(dst_port));
            outputFileStream.write(reinterpret_cast<const char*>(&tcp_flags), sizeof(tcp_flags));
            outputFileStream.write(reinterpret_cast<const char*>(&tcp_window_size), sizeof(tcp_window_size));
            outputFileStream.write(reinterpret_cast<const char*>(&tcp_seq), sizeof(tcp_seq));
            outputFileStream.write(reinterpret_cast<const char*>(&tcp_ack), sizeof(tcp_ack));
            outputFileStream.write(reinterpret_cast<const char*>(&tcp_urgent_pointer), sizeof(tcp_urgent_pointer));

            if (tcpoptions_flag) {
                uint16_t total_options_len = tcpLayer->getTcpHeader()->dataOffset * 4 - 20;
                // copy data from tcpLayer->getData()[20] (beginning of tcpoptions) to tcpLayer->getData()[20 + total_options_len]
                std::vector<uint8_t> tcp_options(total_options_len);
                for (int i = 0; i < total_options_len; i++) {
                    tcp_options[i] = tcpLayer->getData()[20 + i];
                }

                // pad with zeroes to 40 bytes
                if (tcp_options.size() < 40) {
                    tcp_options.resize(40, 0);
                }
                for (int i = 0; i < 40; i++) {
                    outputFileStream.write(reinterpret_cast<const char*>(&tcp_options[i]), sizeof(tcp_options[i]));
                }
            }

            data = tcpLayer->getLayerPayload();
            data_len = tcpLayer->getLayerPayloadSize();
        } else if (protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP) {
            auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer == nullptr) {
                std::cerr << "File " << input_file << " contains packets with unknown transport layer protocol during UDP parsing: " << std::to_string(protocol) << std::endl;
                return 1;
            }

            // udp.srcport, big endian -> little endian
            uint16_t src_port = udpLayer->getUdpHeader()->portSrc;
            src_port = ((src_port & 0xff00) >> 8) | ((src_port & 0x00ff) << 8);

            // udp.dstport, big endian -> little endian
            uint16_t dst_port = udpLayer->getUdpHeader()->portDst;
            dst_port = ((dst_port & 0xff00) >> 8) | ((dst_port & 0x00ff) << 8);

            // udp.length, big endian -> little endian
            uint16_t udp_length = udpLayer->getUdpHeader()->length;
            udp_length = ((udp_length & 0xff00) >> 8) | ((udp_length & 0x00ff) << 8);

            outputFileStream.write(reinterpret_cast<const char*>(&src_port), sizeof(src_port));
            outputFileStream.write(reinterpret_cast<const char*>(&dst_port), sizeof(dst_port));
            outputFileStream.write(reinterpret_cast<const char*>(&udp_length), sizeof(udp_length));

            data = udpLayer->getLayerPayload();
            data_len = udpLayer->getLayerPayloadSize();
        } else if (protocol == SCTP_PROTOCOL_NUMBER) {
            // PcapPlusPlus has no SctpLayer, so we parse the raw bytes after the IP
            // header manually (RFC 4960): a 12-byte common header followed by one or
            // more chunks. We only extract the FIRST chunk -- enough for a per-packet
            // signal without implementing a full chunk-walker. For a DATA chunk, the
            // "user data" is NGAP (ASN.1 PER) -- we do NOT parse it, it's treated as
            // opaque payload bytes exactly like PFCP/SBI payload elsewhere in this
            // pipeline. Deliberately minimal (per SCTP_SUPPORT.md S2): fewer new
            // fields means a smaller cold-start burden on the pretrained embeddings.
            uint8_t *sctpData = (ipversion == 4) ? ipLayer->getLayerPayload() : ipv6Layer->getLayerPayload();
            size_t sctpLen = (ipversion == 4) ? ipLayer->getLayerPayloadSize() : ipv6Layer->getLayerPayloadSize();

            uint16_t sctp_src_port = 0, sctp_dst_port = 0;
            uint32_t sctp_verification_tag = 0;
            uint8_t chunk_type = 0, chunk_flags = 0;
            uint16_t chunk_length = 0;
            uint32_t data_tsn = 0;
            uint16_t data_stream_id = 0, data_stream_seq = 0;
            uint32_t data_ppid = 0;

            constexpr size_t SCTP_COMMON_HEADER_LEN = 12;
            constexpr uint8_t SCTP_DATA_CHUNK_TYPE = 0;
            constexpr size_t SCTP_DATA_CHUNK_FIXED_LEN = 16; // 4B chunk hdr + TSN(4) + SID(2) + SSN(2) + PPID(4)

            data = nullptr;
            data_len = 0;

            // ngap_malformed intentionally contains truncated/malformed SCTP packets,
            // so every offset is bounds-checked -- missing bytes just stay 0 rather
            // than reading past the buffer.
            if (sctpLen >= SCTP_COMMON_HEADER_LEN) {
                sctp_src_port = (sctpData[0] << 8) | sctpData[1];
                sctp_dst_port = (sctpData[2] << 8) | sctpData[3];
                sctp_verification_tag = (static_cast<uint32_t>(sctpData[4]) << 24) |
                                         (static_cast<uint32_t>(sctpData[5]) << 16) |
                                         (static_cast<uint32_t>(sctpData[6]) << 8) | sctpData[7];
                // bytes [8..11] are the SCTP checksum -- not extracted (not useful post-NAT/-rewrite)

                if (sctpLen >= SCTP_COMMON_HEADER_LEN + 4) {
                    uint8_t *chunk = sctpData + SCTP_COMMON_HEADER_LEN;
                    size_t chunkAvail = sctpLen - SCTP_COMMON_HEADER_LEN;
                    chunk_type = chunk[0];
                    chunk_flags = chunk[1];
                    chunk_length = (chunk[2] << 8) | chunk[3];

                    if (chunk_type == SCTP_DATA_CHUNK_TYPE && chunkAvail >= SCTP_DATA_CHUNK_FIXED_LEN) {
                        data_tsn = (static_cast<uint32_t>(chunk[4]) << 24) | (static_cast<uint32_t>(chunk[5]) << 16) |
                                   (static_cast<uint32_t>(chunk[6]) << 8) | chunk[7];
                        data_stream_id = (chunk[8] << 8) | chunk[9];
                        data_stream_seq = (chunk[10] << 8) | chunk[11];
                        data_ppid = (static_cast<uint32_t>(chunk[12]) << 24) | (static_cast<uint32_t>(chunk[13]) << 16) |
                                    (static_cast<uint32_t>(chunk[14]) << 8) | chunk[15];

                        data = chunk + SCTP_DATA_CHUNK_FIXED_LEN;
                        data_len = (chunkAvail > SCTP_DATA_CHUNK_FIXED_LEN) ? chunkAvail - SCTP_DATA_CHUNK_FIXED_LEN : 0;
                    } else if (chunkAvail > 4) {
                        data = chunk + 4;
                        data_len = chunkAvail - 4;
                    }
                }
            }

            outputFileStream.write(reinterpret_cast<const char*>(&sctp_src_port), sizeof(sctp_src_port));
            outputFileStream.write(reinterpret_cast<const char*>(&sctp_dst_port), sizeof(sctp_dst_port));
            outputFileStream.write(reinterpret_cast<const char*>(&sctp_verification_tag), sizeof(sctp_verification_tag));
            outputFileStream.write(reinterpret_cast<const char*>(&chunk_type), sizeof(chunk_type));
            outputFileStream.write(reinterpret_cast<const char*>(&chunk_flags), sizeof(chunk_flags));
            outputFileStream.write(reinterpret_cast<const char*>(&chunk_length), sizeof(chunk_length));
            outputFileStream.write(reinterpret_cast<const char*>(&data_tsn), sizeof(data_tsn));
            outputFileStream.write(reinterpret_cast<const char*>(&data_stream_id), sizeof(data_stream_id));
            outputFileStream.write(reinterpret_cast<const char*>(&data_stream_seq), sizeof(data_stream_seq));
            outputFileStream.write(reinterpret_cast<const char*>(&data_ppid), sizeof(data_ppid));
        } else if (protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ICMP) {
            auto *icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
            if (icmpLayer == nullptr) {
                std::cerr << "File " << input_file << " contains packets with unknown transport layer protocol during ICMP parsing: " << std::to_string(protocol) << std::endl;
                return 1;
            }
            
            uint8_t icmp_type = icmpLayer->getIcmpHeader()->type;  // icmp.type
            uint8_t icmp_code = icmpLayer->getIcmpHeader()->code;  // icmp.code

            outputFileStream.write(reinterpret_cast<const char*>(&icmp_type), sizeof(icmp_type));
            outputFileStream.write(reinterpret_cast<const char*>(&icmp_code), sizeof(icmp_code));

            if (icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REQUEST)) {
                data = icmpLayer->getEchoRequestData()->data;
                data_len = icmpLayer->getEchoRequestData()->dataLength;
            } else if (icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REPLY)) {
                data = icmpLayer->getEchoReplyData()->data;
                data_len = icmpLayer->getEchoReplyData()->dataLength;
            } else {
                data = icmpLayer->getData();
                data_len = icmpLayer->getDataLen();
            }
        } else {
            std::cerr << "File " << input_file << " contains packets with unknown transport layer protocol: " << std::to_string(protocol) << std::endl;
            return 1;
        }

        // data: get first N bytes of payload unless it's smaller, pad with zeros if data_len < N.
        // SCTP gets a wider cap (40B) because its distinguishing NAS/NGAP bytes sit
        // beyond byte 12 (see reports/fase8/nas_triplet_investigation.md); TCP/UDP/ICMP
        // keep the original 12B cap unchanged so their tokenization is byte-identical
        // to every prior run.
        // if no payload - fill with 0s to maintain data structure
        constexpr size_t PAYLOAD_CAP_BYTES_DEFAULT = 12;
        constexpr size_t PAYLOAD_CAP_BYTES_SCTP = 40;
        const size_t PAYLOAD_CAP_BYTES = (protocol == SCTP_PROTOCOL_NUMBER) ? PAYLOAD_CAP_BYTES_SCTP : PAYLOAD_CAP_BYTES_DEFAULT;
        size_t payload_len = no_payload_flag ? 0 : std::min(data_len, PAYLOAD_CAP_BYTES);
        for (int i = 0; i < payload_len; i++) {
            outputFileStream.write(reinterpret_cast<const char*>(&data[i]), sizeof(data[i]));
        }
        for (size_t i = payload_len; i < PAYLOAD_CAP_BYTES; i++) {
            uint8_t zero = 0;
            outputFileStream.write(reinterpret_cast<const char*>(&zero), sizeof(zero));
        }

        packetCount++;
    }

    outputFileStream.close();
    reader->close();

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 5) {
        std::cout << "Usage: " << argv[0] << " <input folder> <output folder> [tcpoptions_flag] [no_payload_flag]" << std::endl;
        return 1;
    }

    std::string input_folder(argv[1]);
    std::string output_folder(argv[2]);
    bool tcpoptions_flag = false;
    bool no_payload_flag = false;
    if (argc >= 4) {
        tcpoptions_flag = std::stoi(argv[3]);
    }
    if (argc == 5) {
        no_payload_flag = std::stoi(argv[4]);
    }

    // for each file in the input folder, process it and write to the output folder
    for (const auto &entry : std::filesystem::directory_iterator(input_folder)) {
        std::string input_file = entry.path().string();
        std::string output_file = output_folder + "/" + entry.path().filename().string();
        process_file(input_file, output_file, tcpoptions_flag, no_payload_flag);
    }

    return 0;
}