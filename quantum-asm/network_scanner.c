// Single-file Network Scanner - Compile with MinGW
// i686-w64-mingw32-gcc -O3 -s -static network_scanner.c -o scanner32.exe -lws2_32 -liphlpapi
// x86_64-w64-mingw32-gcc -O3 -s -static network_scanner.c -o scanner64.exe -lws2_32 -liphlpapi

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_THREADS 256
#define TIMEOUT_MS 1000
#define MAX_PORTS 65535

typedef struct {
    char host[256];
    int startPort;
    int endPort;
    HANDLE hSemaphore;
    CRITICAL_SECTION* pCritSec;
    int* openPorts;
    int* portCount;
} ScanContext;

// Port service identification
const char* GetServiceName(int port) {
    switch(port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 135: return "RPC";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        default: return "Unknown";
    }
}

// Banner grabbing
void GrabBanner(const char* host, int port, char* banner, int bannerSize) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return;
    
    // Set timeout
    int timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        // Try to receive banner
        int received = recv(sock, banner, bannerSize - 1, 0);
        if (received > 0) {
            banner[received] = '\0';
            // Clean up banner
            for (int i = 0; i < received; i++) {
                if (banner[i] < 32 || banner[i] > 126) banner[i] = '.';
            }
        } else {
            // Send probe for HTTP
            if (port == 80 || port == 8080 || port == 443 || port == 8443) {
                send(sock, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
                received = recv(sock, banner, bannerSize - 1, 0);
                if (received > 0) {
                    banner[received] = '\0';
                    // Extract server header
                    char* server = strstr(banner, "Server:");
                    if (server) {
                        char* end = strchr(server, '\r');
                        if (end) *end = '\0';
                        strcpy(banner, server);
                    }
                }
            }
        }
    }
    
    closesocket(sock);
}

// TCP port scanner thread
unsigned __stdcall ScanPortThread(void* param) {
    ScanContext* ctx = (ScanContext*)param;
    
    while (1) {
        WaitForSingleObject(ctx->hSemaphore, INFINITE);
        
        EnterCriticalSection(ctx->pCritSec);
        int port = ctx->startPort++;
        if (port > ctx->endPort) {
            LeaveCriticalSection(ctx->pCritSec);
            break;
        }
        LeaveCriticalSection(ctx->pCritSec);
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;
        
        // Set non-blocking mode
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ctx->host, &addr.sin_addr);
        
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        
        struct timeval tv;
        tv.tv_sec = TIMEOUT_MS / 1000;
        tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;
        
        if (select(0, NULL, &fdset, NULL, &tv) > 0) {
            EnterCriticalSection(ctx->pCritSec);
            ctx->openPorts[(*ctx->portCount)++] = port;
            
            printf("[+] Port %d open - %s", port, GetServiceName(port));
            
            // Try banner grabbing
            char banner[512] = {0};
            LeaveCriticalSection(ctx->pCritSec);
            
            GrabBanner(ctx->host, port, banner, sizeof(banner));
            if (strlen(banner) > 0) {
                printf(" - %s", banner);
            }
            printf("\n");
        }
        
        closesocket(sock);
        ReleaseSemaphore(ctx->hSemaphore, 1, NULL);
    }
    
    return 0;
}

// SYN scan (requires raw sockets - admin privileges)
BOOL SynScan(const char* host, int port) {
    // Note: Windows restricts raw sockets
    // This is a simplified version
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;
    
    // Would need to craft TCP SYN packet here
    // Simplified for demonstration
    
    closesocket(sock);
    return FALSE;
}

// UDP port scanner
BOOL ScanUdpPort(const char* host, int port) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return FALSE;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    // Send probe packet
    const char* probe = "\x00";
    sendto(sock, probe, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
    
    // Wait for response or ICMP unreachable
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500ms timeout
    
    BOOL isOpen = FALSE;
    if (select(0, &fdset, NULL, NULL, &tv) > 0) {
        char buffer[1024];
        int received = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (received > 0) isOpen = TRUE;
    }
    
    closesocket(sock);
    return isOpen;
}

// Network enumeration
void EnumerateNetwork() {
    ULONG bufferSize = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
    
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        
        printf("\n=== Network Interfaces ===\n");
        while (pAdapter) {
            printf("\nAdapter: %s\n", pAdapter->Description);
            printf("IP: %s\n", pAdapter->IpAddressList.IpAddress.String);
            printf("Subnet: %s\n", pAdapter->IpAddressList.IpMask.String);
            printf("Gateway: %s\n", pAdapter->GatewayList.IpAddress.String);
            
            // MAC address
            printf("MAC: ");
            for (int i = 0; i < pAdapter->AddressLength; i++) {
                printf("%02X", pAdapter->Address[i]);
                if (i < pAdapter->AddressLength - 1) printf(":");
            }
            printf("\n");
            
            pAdapter = pAdapter->Next;
        }
    }
    
    free(pAdapterInfo);
}

// ARP scan for local network discovery
void ArpScan(const char* subnet) {
    printf("\n=== ARP Scan ===\n");
    
    ULONG bufferSize = 0;
    GetIpNetTable(NULL, &bufferSize, FALSE);
    
    PMIB_IPNETTABLE pIpNetTable = (PMIB_IPNETTABLE)malloc(bufferSize);
    if (GetIpNetTable(pIpNetTable, &bufferSize, FALSE) == NO_ERROR) {
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            MIB_IPNETROW* pRow = &pIpNetTable->table[i];
            
            struct in_addr addr;
            addr.s_addr = pRow->dwAddr;
            
            printf("IP: %-15s MAC: ", inet_ntoa(addr));
            for (DWORD j = 0; j < pRow->dwPhysAddrLen; j++) {
                printf("%02X", pRow->bPhysAddr[j]);
                if (j < pRow->dwPhysAddrLen - 1) printf(":");
            }
            
            printf(" Type: ");
            switch (pRow->dwType) {
                case MIB_IPNET_TYPE_STATIC: printf("Static"); break;
                case MIB_IPNET_TYPE_DYNAMIC: printf("Dynamic"); break;
                default: printf("Other");
            }
            printf("\n");
        }
    }
    
    free(pIpNetTable);
}

int main(int argc, char* argv[]) {
    printf("=== Advanced Network Scanner v1.0 ===\n\n");
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] Failed to initialize Winsock\n");
        return 1;
    }
    
    if (argc < 2) {
        printf("Usage: %s <host> [start_port] [end_port] [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -t <threads>  Number of threads (default: 100)\n");
        printf("  -u            UDP scan\n");
        printf("  -n            Network enumeration\n");
        printf("  -a            ARP scan\n");
        printf("\nExamples:\n");
        printf("  %s 192.168.1.1 1 1000\n", argv[0]);
        printf("  %s 192.168.1.1 -n\n", argv[0]);
        printf("  %s localhost 80 443\n", argv[0]);
        return 1;
    }
    
    // Check for special modes
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0) {
            EnumerateNetwork();
            WSACleanup();
            return 0;
        }
        if (strcmp(argv[i], "-a") == 0) {
            ArpScan(argv[1]);
            WSACleanup();
            return 0;
        }
    }
    
    // Port scanning mode
    char host[256];
    strcpy(host, argv[1]);
    
    int startPort = 1;
    int endPort = 1000;
    int numThreads = 100;
    BOOL udpScan = FALSE;
    
    if (argc >= 3) startPort = atoi(argv[2]);
    if (argc >= 4) endPort = atoi(argv[3]);
    
    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            numThreads = atoi(argv[i + 1]);
            if (numThreads > MAX_THREADS) numThreads = MAX_THREADS;
        }
        if (strcmp(argv[i], "-u") == 0) {
            udpScan = TRUE;
        }
    }
    
    printf("Scanning %s ports %d-%d with %d threads...\n\n", 
           host, startPort, endPort, numThreads);
    
    if (udpScan) {
        printf("=== UDP Scan ===\n");
        for (int port = startPort; port <= endPort; port++) {
            if (ScanUdpPort(host, port)) {
                printf("[+] UDP Port %d open\n", port);
            }
        }
    } else {
        // TCP scan
        int* openPorts = (int*)calloc(MAX_PORTS, sizeof(int));
        int portCount = 0;
        
        CRITICAL_SECTION critSec;
        InitializeCriticalSection(&critSec);
        
        HANDLE hSemaphore = CreateSemaphore(NULL, numThreads, numThreads, NULL);
        
        ScanContext ctx = {0};
        strcpy(ctx.host, host);
        ctx.startPort = startPort;
        ctx.endPort = endPort;
        ctx.hSemaphore = hSemaphore;
        ctx.pCritSec = &critSec;
        ctx.openPorts = openPorts;
        ctx.portCount = &portCount;
        
        // Create threads
        HANDLE* threads = (HANDLE*)malloc(numThreads * sizeof(HANDLE));
        for (int i = 0; i < numThreads; i++) {
            threads[i] = (HANDLE)_beginthreadex(NULL, 0, ScanPortThread, &ctx, 0, NULL);
        }
        
        // Wait for completion
        WaitForMultipleObjects(numThreads, threads, TRUE, INFINITE);
        
        // Cleanup
        for (int i = 0; i < numThreads; i++) {
            CloseHandle(threads[i]);
        }
        free(threads);
        
        CloseHandle(hSemaphore);
        DeleteCriticalSection(&critSec);
        
        printf("\n=== Scan Complete ===\n");
        printf("Found %d open ports\n", portCount);
        
        free(openPorts);
    }
    
    WSACleanup();
    return 0;
}