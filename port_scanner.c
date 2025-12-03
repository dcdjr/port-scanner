/*
 * Multithreaded TCP Port Scanner
 * Author: Daniel DiPietro Jr.
 * Description:
 *     A Windows Winsock2-based multithreaded TCP port scanner with optional
 *     banner grabbing, thread identifiers, timing statistics, and file output.
 *
 * Build:
 *     gcc port_scanner.c -o port_scanner -lws2_32 -lpthread
 */

// Enable newer Winsock features such as inet_pton
#define _WIN32_WINNT 0x0601

// ANSI color codes for console output (Windows 10+ / modern terminals)
#define COLOR_GREEN  "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET  "\x1b[0m"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <string.h>

// Target IP shared by all threads
static const char *TARGET_IP;

// Mutex for synchronized console + file output
pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

// Pre-parsed IPv4 address (set once in main)
struct sockaddr_in tmp = {0};

// Global output file (opened in main, written in worker threads)
FILE *OUTPUT_FILE;

// Scan mode: 1 = banner grab (full), 0 = fast mode (no banner)
int FULL_MODE = 1;

// Global timeout in milliseconds for connect()/recv()
int TIMEOUT_MS = 200;

// Thread-safe job queue of ports to scan
typedef struct {
    int *ports;             // contiguous list of port numbers
    int size;               // total number of ports
    int index;              // next index to hand out
    pthread_mutex_t lock;   // protects index
} JobQueue;

// Per-thread argument container
typedef struct {
    int id;          // thread id (0..num_threads-1)
    JobQueue *queue; // shared job queue
} ThreadArgs;

// Prototypes
const char* service_name(int port);
void *worker(void *arg);
int get_next_port(JobQueue *q);

int main(int argc, char *argv[]) {

    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <ip> [start_port end_port] <num_threads> [--fast|--full] [--timeout ms]\n", argv[0]);
        WSACleanup();
        return 1;
    }

    TARGET_IP = argv[1];

    // Convert string IP to binary and store once
    if (inet_pton(AF_INET, TARGET_IP, &tmp.sin_addr) != 1) {
        printf("Invalid IPv4 address: %s\n", TARGET_IP);
        WSACleanup();
        return 1;
    }
    tmp.sin_family = AF_INET;

    // Defaults
    int start = 1;
    int end = 1023;
    int num_threads = 50;

    // Optional positional arguments: start,end,threads
    if (argc == 4) {
        start = atoi(argv[2]);
        end = atoi(argv[3]);
    } else if (argc >= 5) {
        start = atoi(argv[2]);
        end = atoi(argv[3]);
        num_threads = atoi(argv[4]);
    }

    // Parse flags (can appear anywhere after argv[1])
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fast") == 0) FULL_MODE = 0;
        if (strcmp(argv[i], "--full") == 0) FULL_MODE = 1;

        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            TIMEOUT_MS = atoi(argv[i + 1]);
        }
    }

    // Basic sanity bounds
    if (num_threads < 1) num_threads = 1;
    if (num_threads > 5000) num_threads = 5000;

    if (TIMEOUT_MS < 1) TIMEOUT_MS = 1;

    printf("Scanning %s (ports %d-%d) with %d threads, mode=%s, timeout=%d ms...\n",
           TARGET_IP, start, end, num_threads,
           FULL_MODE ? "full" : "fast", TIMEOUT_MS);

    clock_t start_time = clock();

    // Initialize job queue
    JobQueue q;
    q.size = end - start + 1;
    q.ports = malloc(q.size * sizeof(int));
    q.index = 0;
    pthread_mutex_init(&q.lock, NULL);

    if (q.ports == NULL) {
        printf("Memory allocation failed.\n");
        pthread_mutex_destroy(&q.lock);
        WSACleanup();
        return 1;
    }

    for (int i = 0; i < q.size; i++)
        q.ports[i] = start + i;

    // Open output file
    FILE *out = fopen("scan_results.txt", "w");
    if (!out) {
        printf("Could not open output file.\n");
        free(q.ports);
        pthread_mutex_destroy(&q.lock);
        WSACleanup();
        return 1;
    }
    OUTPUT_FILE = out;

    // Allocate thread handles
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    if (threads == NULL) {
        printf("Failed to allocate thread array.\n");
        fclose(out);
        free(q.ports);
        pthread_mutex_destroy(&q.lock);
        WSACleanup();
        return 1;
    }

    // Spawn worker threads; each gets its own ThreadArgs
    for (int i = 0; i < num_threads; i++) {
        ThreadArgs *t = malloc(sizeof(ThreadArgs));
        if (t == NULL) {
            printf("Failed to allocate thread args.\n");
            // Not cleaning up partially created threads here to keep it simple.
            free(threads);
            fclose(out);
            free(q.ports);
            pthread_mutex_destroy(&q.lock);
            WSACleanup();
            return 1;
        }
        t->id = i;
        t->queue = &q;

        pthread_create(&threads[i], NULL, worker, t);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    printf("Scan complete.\n");

    // Timing stats
    clock_t end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Total scan time: %.2f seconds\n", elapsed);
    printf("Ports per second: %.2f\n", q.size / elapsed);

    // Cleanup
    free(threads);
    fclose(out);
    free(q.ports);
    pthread_mutex_destroy(&q.lock);
    WSACleanup();

    return 0;
}

// Map common ports to human-readable service names
const char* service_name(int port) {
    switch (port) {
        case 20:
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        default:  return "";
    }
}

// Worker thread: pulls ports from queue and attempts TCP connects
void *worker(void *arg) {
    ThreadArgs *info = (ThreadArgs*)arg;
    int thread_id = info->id;
    JobQueue *q = info->queue;
    free(info); // free per-thread argument struct

    while (1) {
        int port = get_next_port(q);
        if (port == -1)
            break;

        struct sockaddr_in target = {0};
        target.sin_family = AF_INET;
        target.sin_addr = *((struct in_addr*)&tmp.sin_addr);
        target.sin_port = htons(port);

        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET)
            return NULL;

        DWORD timeout = TIMEOUT_MS;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        int result = connect(s, (struct sockaddr*)&target, sizeof(target));

        if (result == 0) {
            char banner[512];
            int n = 0;
            if (FULL_MODE)
                n = recv(s, banner, sizeof(banner) - 1, 0);

            const char *svc = service_name(port);

            pthread_mutex_lock(&print_lock);

            if (n > 0) {
                banner[n] = '\0';

                if (svc[0] != '\0')
                    printf(COLOR_GREEN "[Thread %d] Port %d OPEN" COLOR_RESET
                           " - banner: %s (%s)\n", thread_id, port, banner, svc);
                else
                    printf(COLOR_GREEN "[Thread %d] Port %d OPEN" COLOR_RESET
                           " - banner: %s\n", thread_id, port, banner);

                if (svc[0] != '\0')
                    fprintf(OUTPUT_FILE,
                            "[Thread %d] Port %d OPEN - banner: %s (%s)\n",
                            thread_id, port, banner, svc);
                else
                    fprintf(OUTPUT_FILE,
                            "[Thread %d] Port %d OPEN - banner: %s\n",
                            thread_id, port, banner);

            } else {
                if (svc[0] != '\0') {
                    printf(COLOR_GREEN "[Thread %d] Port %d OPEN (%s)" COLOR_RESET "\n",
                           thread_id, port, svc);
                    fprintf(OUTPUT_FILE,
                            "[Thread %d] Port %d OPEN (%s)\n",
                            thread_id, port, svc);
                } else {
                    printf(COLOR_GREEN "[Thread %d] Port %d OPEN" COLOR_RESET "\n",
                           thread_id, port);
                    fprintf(OUTPUT_FILE,
                            "[Thread %d] Port %d OPEN\n",
                            thread_id, port);
                }
            }

            fflush(OUTPUT_FILE);
            pthread_mutex_unlock(&print_lock);
        }

        closesocket(s);
    }

    return NULL;
}

// Get next port from the queue in a thread-safe way
int get_next_port(JobQueue *q) {
    pthread_mutex_lock(&q->lock);

    if (q->index >= q->size) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }

    int port = q->ports[q->index++];
    pthread_mutex_unlock(&q->lock);
    return port;
}
