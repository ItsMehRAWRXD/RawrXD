//=============================================================================
// network_protocol_analyzer.c - Network Protocol Analyzer
// Production-ready protocol parsing and analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Protocol Types
//=============================================================================

#define MAX_PACKETS 10000
#define MAX_CONNECTIONS 1000
#define MAX_ENDPOINTS 100

typedef enum {
    PROTO_UNKNOWN,
    PROTO_ETHERNET,
    PROTO_IP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS,
    PROTO_DHCP,
    PROTO_ARP
} ProtocolType;

typedef struct {
    uint8_t bytes[6];
} MacAddress;

typedef struct {
    uint8_t bytes[4];
} IpAddress;

typedef struct {
    MacAddress src_mac;
    MacAddress dst_mac;
    uint16_t ethertype;
} EthernetHeader;

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IpAddress src_ip;
    IpAddress dst_ip;
} IpHeader;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TcpHeader;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} UdpHeader;

typedef struct {
    ProtocolType protocol;
    uint64_t timestamp;
    uint32_t size;
    
    EthernetHeader eth;
    IpHeader ip;
    union {
        TcpHeader tcp;
        UdpHeader udp;
    } transport;
    
    uint8_t payload[1500];
    uint16_t payload_len;
    
    int is_valid;
    char summary[256];
} Packet;

typedef struct {
    IpAddress src_ip;
    uint16_t src_port;
    IpAddress dst_ip;
    uint16_t dst_port;
    ProtocolType protocol;
    
    uint64_t start_time;
    uint64_t end_time;
    uint32_t packet_count;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    int is_active;
} Connection;

typedef struct {
    Packet* packets;
    int packet_count;
    int packet_capacity;
    
    Connection* connections;
    int connection_count;
    int connection_capacity;
    
    uint64_t start_time;
    uint64_t end_time;
    
    uint32_t total_bytes;
    uint32_t total_packets;
    
    int protocol_counts[12];
    int error_count;
} NetworkReport;

//=============================================================================
// Protocol Analysis
//=============================================================================

NetworkReport* network_create_report(void) {
    NetworkReport* report = (NetworkReport*)calloc(1, sizeof(NetworkReport));
    report->packet_capacity = MAX_PACKETS;
    report->packets = (Packet*)calloc(report->packet_capacity, sizeof(Packet));
    report->connection_capacity = MAX_CONNECTIONS;
    report->connections = (Connection*)calloc(report->connection_capacity, sizeof(Connection));
    return report;
}

void network_destroy_report(NetworkReport* report) {
    if (!report) return;
    free(report->packets);
    free(report->connections);
    free(report);
}

const char* protocol_to_string(ProtocolType proto) {
    switch (proto) {
        case PROTO_ETHERNET: return "Ethernet";
        case PROTO_IP: return "IP";
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMP: return "ICMP";
        case PROTO_HTTP: return "HTTP";
        case PROTO_HTTPS: return "HTTPS";
        case PROTO_DNS: return "DNS";
        case PROTO_DHCP: return "DHCP";
        case PROTO_ARP: return "ARP";
        default: return "Unknown";
    }
}

void mac_to_string(const MacAddress* mac, char* str, size_t len) {
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac->bytes[0], mac->bytes[1], mac->bytes[2],
             mac->bytes[3], mac->bytes[4], mac->bytes[5]);
}

void ip_to_string(const IpAddress* ip, char* str, size_t len) {
    snprintf(str, len, "%d.%d.%d.%d",
             ip->bytes[0], ip->bytes[1], ip->bytes[2], ip->bytes[3]);
}

ProtocolType detect_application_protocol(const uint8_t* payload, uint16_t len, uint16_t port) {
    if (len == 0) return PROTO_UNKNOWN;
    
    // Check port numbers
    if (port == 80) return PROTO_HTTP;
    if (port == 443) return PROTO_HTTPS;
    if (port == 53) return PROTO_DNS;
    if (port == 67 || port == 68) return PROTO_DHCP;
    
    // Check payload patterns
    if (len > 4) {
        if (strncmp((char*)payload, "GET ", 4) == 0 ||
            strncmp((char*)payload, "POST", 4) == 0 ||
            strncmp((char*)payload, "HTTP", 4) == 0) {
            return PROTO_HTTP;
        }
    }
    
    return PROTO_UNKNOWN;
}

void parse_packet(NetworkReport* report, const uint8_t* data, uint32_t len) {
    if (report->packet_count >= report->packet_capacity) return;
    
    Packet* pkt = &report->packets[report->packet_count++];
    pkt->timestamp = (uint64_t)time(NULL);
    pkt->size = len;
    pkt->is_valid = 1;
    
    // Parse Ethernet header (14 bytes)
    if (len >= 14) {
        memcpy(pkt->eth.dst_mac.bytes, data, 6);
        memcpy(pkt->eth.src_mac.bytes, data + 6, 6);
        pkt->eth.ethertype = (data[12] << 8) | data[13];
        
        pkt->protocol = PROTO_ETHERNET;
        
        // Parse IP header
        if (pkt->eth.ethertype == 0x0800 && len >= 34) {
            const uint8_t* ip_data = data + 14;
            pkt->ip.version_ihl = ip_data[0];
            pkt->ip.tos = ip_data[1];
            pkt->ip.total_length = (ip_data[2] << 8) | ip_data[3];
            pkt->ip.identification = (ip_data[4] << 8) | ip_data[5];
            pkt->ip.flags_fragment = (ip_data[6] << 8) | ip_data[7];
            pkt->ip.ttl = ip_data[8];
            pkt->ip.protocol = ip_data[9];
            pkt->ip.checksum = (ip_data[10] << 8) | ip_data[11];
            memcpy(pkt->ip.src_ip.bytes, ip_data + 12, 4);
            memcpy(pkt->ip.dst_ip.bytes, ip_data + 16, 4);
            
            pkt->protocol = PROTO_IP;
            
            int ip_header_len = (pkt->ip.version_ihl & 0x0F) * 4;
            const uint8_t* transport_data = ip_data + ip_header_len;
            
            // Parse transport layer
            if (pkt->ip.protocol == 6 && len >= 14 + ip_header_len + 20) {  // TCP
                pkt->transport.tcp.src_port = (transport_data[0] << 8) | transport_data[1];
                pkt->transport.tcp.dst_port = (transport_data[2] << 8) | transport_data[3];
                pkt->transport.tcp.seq_number = ((uint32_t)transport_data[4] << 24) |
                                                ((uint32_t)transport_data[5] << 16) |
                                                ((uint32_t)transport_data[6] << 8) |
                                                transport_data[7];
                pkt->transport.tcp.ack_number = ((uint32_t)transport_data[8] << 24) |
                                                ((uint32_t)transport_data[9] << 16) |
                                                ((uint32_t)transport_data[10] << 8) |
                                                transport_data[11];
                pkt->transport.tcp.data_offset = (transport_data[12] >> 4) * 4;
                pkt->transport.tcp.flags = transport_data[13];
                
                pkt->protocol = PROTO_TCP;
                
                // Detect application protocol
                uint16_t payload_offset = 14 + ip_header_len + pkt->transport.tcp.data_offset;
                if (len > payload_offset) {
                    pkt->payload_len = len - payload_offset;
                    memcpy(pkt->payload, data + payload_offset, 
                           pkt->payload_len > 1500 ? 1500 : pkt->payload_len);
                    
                    ProtocolType app_proto = detect_application_protocol(
                        pkt->payload, pkt->payload_len, pkt->transport.tcp.dst_port);
                    if (app_proto != PROTO_UNKNOWN) {
                        pkt->protocol = app_proto;
                    }
                }
            } else if (pkt->ip.protocol == 17 && len >= 14 + ip_header_len + 8) {  // UDP
                pkt->transport.udp.src_port = (transport_data[0] << 8) | transport_data[1];
                pkt->transport.udp.dst_port = (transport_data[2] << 8) | transport_data[3];
                pkt->transport.udp.length = (transport_data[4] << 8) | transport_data[5];
                
                pkt->protocol = PROTO_UDP;
                
                // Detect application protocol
                uint16_t payload_offset = 14 + ip_header_len + 8;
                if (len > payload_offset) {
                    pkt->payload_len = len - payload_offset;
                    memcpy(pkt->payload, data + payload_offset,
                           pkt->payload_len > 1500 ? 1500 : pkt->payload_len);
                    
                    ProtocolType app_proto = detect_application_protocol(
                        pkt->payload, pkt->payload_len, pkt->transport.udp.dst_port);
                    if (app_proto != PROTO_UNKNOWN) {
                        pkt->protocol = app_proto;
                    }
                }
            } else if (pkt->ip.protocol == 1) {
                pkt->protocol = PROTO_ICMP;
            }
        } else if (pkt->eth.ethertype == 0x0806) {
            pkt->protocol = PROTO_ARP;
        }
    }
    
    // Update protocol counts
    report->protocol_counts[pkt->protocol]++;
    report->total_packets++;
    report->total_bytes += len;
    
    // Create summary
    char src_ip[16], dst_ip[16];
    ip_to_string(&pkt->ip.src_ip, src_ip, sizeof(src_ip));
    ip_to_string(&pkt->ip.dst_ip, dst_ip, sizeof(dst_ip));
    
    if (pkt->protocol == PROTO_TCP || pkt->protocol == PROTO_UDP ||
        pkt->protocol == PROTO_HTTP || pkt->protocol == PROTO_HTTPS) {
        snprintf(pkt->summary, sizeof(pkt->summary),
                 "%s %s:%d -> %s:%d (%d bytes)",
                 protocol_to_string(pkt->protocol),
                 src_ip, pkt->transport.tcp.src_port,
                 dst_ip, pkt->transport.tcp.dst_port,
                 pkt->size);
    } else {
        snprintf(pkt->summary, sizeof(pkt->summary),
                 "%s %s -> %s (%d bytes)",
                 protocol_to_string(pkt->protocol),
                 src_ip, dst_ip, pkt->size);
    }
}

void analyze_connections(NetworkReport* report) {
    // Group packets into connections
    for (int i = 0; i < report->packet_count; i++) {
        Packet* pkt = &report->packets[i];
        
        if (pkt->protocol != PROTO_TCP && pkt->protocol != PROTO_UDP) continue;
        
        // Find or create connection
        Connection* conn = NULL;
        for (int j = 0; j < report->connection_count; j++) {
            Connection* c = &report->connections[j];
            if (c->src_port == pkt->transport.tcp.src_port &&
                c->dst_port == pkt->transport.tcp.dst_port &&
                memcmp(&c->src_ip, &pkt->ip.src_ip, 4) == 0 &&
                memcmp(&c->dst_ip, &pkt->ip.dst_ip, 4) == 0) {
                conn = c;
                break;
            }
        }
        
        if (!conn && report->connection_count < report->connection_capacity) {
            conn = &report->connections[report->connection_count++];
            conn->src_ip = pkt->ip.src_ip;
            conn->dst_ip = pkt->ip.dst_ip;
            conn->src_port = pkt->transport.tcp.src_port;
            conn->dst_port = pkt->transport.tcp.dst_port;
            conn->protocol = pkt->protocol;
            conn->start_time = pkt->timestamp;
            conn->is_active = 1;
        }
        
        if (conn) {
            conn->packet_count++;
            conn->bytes_sent += pkt->size;
            conn->end_time = pkt->timestamp;
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_network_summary(NetworkReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Network Protocol Analysis\n");
    printf("=============================================================================\n");
    printf("  Packets Captured:   %d\n", report->packet_count);
    printf("  Total Bytes:        %u\n", report->total_bytes);
    printf("  Connections:        %d\n", report->connection_count);
    printf("\n");
    printf("  Protocol Distribution:\n");
    for (int i = 0; i < 12; i++) {
        if (report->protocol_counts[i] > 0) {
            printf("    %-12s: %d (%.1f%%)\n",
                   protocol_to_string(i),
                   report->protocol_counts[i],
                   (float)report->protocol_counts[i] / report->packet_count * 100);
        }
    }
    printf("=============================================================================\n");
}

void print_packet_list(NetworkReport* report, int top_n) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Packet List (First %d)\n", top_n);
    printf("=============================================================================\n");
    
    int count = (top_n < report->packet_count) ? top_n : report->packet_count;
    for (int i = 0; i < count; i++) {
        Packet* pkt = &report->packets[i];
        printf("  [%d] %s\n", i + 1, pkt->summary);
    }
    
    printf("=============================================================================\n");
}

void print_connection_list(NetworkReport* report) {
    if (report->connection_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Active Connections\n");
    printf("=============================================================================\n");
    printf("  %-21s %-21s %-8s %8s %10s\n",
           "Source", "Destination", "Protocol", "Packets", "Bytes");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->connection_count && i < 20; i++) {
        Connection* conn = &report->connections[i];
        char src[22], dst[22];
        ip_to_string(&conn->src_ip, src, sizeof(src));
        ip_to_string(&conn->dst_ip, dst, sizeof(dst));
        
        char src_full[32], dst_full[32];
        snprintf(src_full, sizeof(src_full), "%s:%d", src, conn->src_port);
        snprintf(dst_full, sizeof(dst_full), "%s:%d", dst, conn->dst_port);
        
        printf("  %-21s %-21s %-8s %8d %10llu\n",
               src_full, dst_full,
               protocol_to_string(conn->protocol),
               conn->packet_count,
               (unsigned long long)conn->bytes_sent);
    }
    
    printf("=============================================================================\n");
}

void export_network_json(NetworkReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"packets_captured\": %d,\n", report->packet_count);
    fprintf(f, "    \"total_bytes\": %u,\n", report->total_bytes);
    fprintf(f, "    \"connections\": %d\n", report->connection_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"protocols\": {\n");
    
    int first = 1;
    for (int i = 0; i < 12; i++) {
        if (report->protocol_counts[i] > 0) {
            if (!first) fprintf(f, ",");
            first = 0;
            fprintf(f, "    \"%s\": %d", protocol_to_string(i), report->protocol_counts[i]);
        }
    }
    fprintf(f, "\n  },\n");
    
    fprintf(f, "  \"packets\": [\n");
    for (int i = 0; i < report->packet_count && i < 100; i++) {
        Packet* pkt = &report->packets[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"timestamp\": %llu,\n", (unsigned long long)pkt->timestamp);
        fprintf(f, "      \"protocol\": \"%s\",\n", protocol_to_string(pkt->protocol));
        fprintf(f, "      \"size\": %u,\n", pkt->size);
        fprintf(f, "      \"summary\": \"%s\"\n", pkt->summary);
        fprintf(f, "    }%s\n", (i < report->packet_count - 1 && i < 99) ? "," : "");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Network report exported: %s\n", filename);
}

//=============================================================================
// Demo
//=============================================================================

void demo_packet_capture(NetworkReport* report) {
    // Simulate captured packets
    uint8_t packet1[] = {
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // dst MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // src MAC
        0x08, 0x00,                           // IPv4
        // IP header
        0x45, 0x00, 0x00, 0x3C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x01,              // src IP: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02,              // dst IP: 192.168.1.2
        // TCP header
        0x00, 0x50, 0x1F, 0x90,              // ports: 80, 8080
        0x00, 0x00, 0x00, 0x01,              // seq
        0x00, 0x00, 0x00, 0x00,              // ack
        0x50, 0x02, 0x20, 0x00,              // data offset, flags, window
        0x00, 0x00, 0x00, 0x00               // checksum, urgent
    };
    
    uint8_t packet2[] = {
        // Ethernet header
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        // IP header
        0x45, 0x00, 0x00, 0x30, 0x00, 0x02, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x02,
        0xC0, 0xA8, 0x01, 0x01,
        // UDP header
        0x00, 0x35, 0x13, 0x88,              // ports: 53, 5000
        0x00, 0x10, 0x00, 0x00               // length, checksum
    };
    
    parse_packet(report, packet1, sizeof(packet1));
    parse_packet(report, packet2, sizeof(packet2));
    
    // Add more simulated packets
    for (int i = 0; i < 10; i++) {
        parse_packet(report, packet1, sizeof(packet1));
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Network Protocol Analyzer\n");
    printf("=================================\n\n");
    
    NetworkReport* report = network_create_report();
    
    printf("Capturing packets...\n");
    
    // Run demo capture
    demo_packet_capture(report);
    
    // Analyze connections
    analyze_connections(report);
    
    // Generate reports
    print_network_summary(report);
    print_packet_list(report, 10);
    print_connection_list(report);
    export_network_json(report, "network_analysis.json");
    
    printf("\nNetwork analysis complete!\n");
    
    network_destroy_report(report);
    
    return 0;
}
