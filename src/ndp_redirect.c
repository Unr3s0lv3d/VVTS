/*
 * ndp_redirect.c — stuurt ICMPv6 Redirect (type 137) pakketten
 *
 * Gebruik: ndp_redirect <interface> <ap-link-local>
 *
 * Leest commando's van stdin:
 *   client <ipv6>    — voeg client toe om redirects naar te sturen
 *   target <ipv6>    — voeg doelbestemming toe
 *   interval <secs>  — stel verzendinterval in (standaard: 30)
 *   flush            — stuur nu direct redirects naar alle clients
 *   quit             — stop het programma
 *
 * Implementatie:
 *   Gebruikt AF_INET6 SOCK_RAW IPPROTO_ICMPV6.
 *   De kernel berekent de ICMPv6-checksum en handelt MAC-resolutie af.
 *   Geen Scapy of Python vereist.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#define MAX_CLIENTS      64
#define MAX_TARGETS      64
#define DEFAULT_INTERVAL 30

/* -------------------------------------------------------------------------
 * ICMPv6 Redirect pakketstructuur (RFC 4861 §8)
 * De kernel voegt de IPv6-header toe; wij leveren vanaf het ICMPv6-type.
 * ------------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t         type;       /* 137 = ND_REDIRECT                        */
    uint8_t         code;       /* 0                                        */
    uint16_t        cksum;      /* 0 → kernel vult in via IPV6_CHECKSUM     */
    uint32_t        reserved;   /* 0                                        */
    struct in6_addr target;     /* nieuwe next-hop  = AP link-local adres   */
    struct in6_addr dest;       /* bestemming die omgeleid wordt            */
    /* Option: Target Link-Layer Address (RFC 4861 §4.6.1) */
    uint8_t         opt_type;   /* 2                                        */
    uint8_t         opt_len;    /* 1  (= 1 × 8 bytes)                       */
    uint8_t         opt_mac[6]; /* MAC-adres van de AP                      */
} redirect_msg_t;

/* -------------------------------------------------------------------------
 * Globals
 * ------------------------------------------------------------------------- */
static const char    *g_iface;
static struct in6_addr g_ap_lladdr;
static uint8_t        g_ap_mac[6];
static unsigned int   g_ifindex;
static int            g_sock = -1;

static struct in6_addr g_clients[MAX_CLIENTS];
static int             g_num_clients = 0;
static struct in6_addr g_targets[MAX_TARGETS];
static int             g_num_targets = 0;
static int             g_interval    = DEFAULT_INTERVAL;

/* -------------------------------------------------------------------------
 * Stuur één Redirect-pakket naar client voor bestemming target
 * ------------------------------------------------------------------------- */
static void send_redirect(const struct in6_addr *client,
                          const struct in6_addr *target)
{
    redirect_msg_t    msg;
    struct sockaddr_in6 dst;

    memset(&msg, 0, sizeof(msg));
    msg.type     = ND_REDIRECT;
    msg.code     = 0;
    msg.cksum    = 0;               /* kernel berekent checksum             */
    msg.reserved = 0;
    msg.target   = g_ap_lladdr;     /* nieuwe next-hop = wij                */
    msg.dest     = *target;         /* bestemming die omgeleid wordt        */
    msg.opt_type = 2;               /* Target Link-Layer Address optie      */
    msg.opt_len  = 1;
    memcpy(msg.opt_mac, g_ap_mac, 6);

    memset(&dst, 0, sizeof(dst));
    dst.sin6_family   = AF_INET6;
    dst.sin6_addr     = *client;
    dst.sin6_scope_id = g_ifindex;  /* vereist voor link-local adressen     */

    if (sendto(g_sock, &msg, sizeof(msg), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        char szClient[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, client, szClient, sizeof(szClient));
        fprintf(stderr, "redirect error (client %s): %s\n",
                szClient, strerror(errno));
        fflush(stderr);
    }
}

/* Stuur redirects naar alle bekende client/target-combinaties */
static void send_all(void)
{
    int i, j;
    for (i = 0; i < g_num_clients; i++) {
        for (j = 0; j < g_num_targets; j++) {
            send_redirect(&g_clients[i], &g_targets[j]);
        }
    }
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    struct ifreq        ifr;
    struct sockaddr_in6 src;
    struct icmp6_filter filter;
    struct pollfd       pfd;
    char                line[256];
    time_t              last_send = 0;
    int                 hoplimit  = 255;
    int                 ckoff     = 2;   /* checksum offset in ICMPv6 header */

    if (argc < 3) {
        fprintf(stderr, "usage: ndp_redirect <interface> <ap-link-local>\n");
        return 1;
    }
    g_iface = argv[1];

    /* Parseer AP link-local adres */
    if (inet_pton(AF_INET6, argv[2], &g_ap_lladdr) != 1) {
        fprintf(stderr, "invalid link-local address: %s\n", argv[2]);
        return 1;
    }

    /* Interface-index opvragen */
    g_ifindex = if_nametoindex(g_iface);
    if (g_ifindex == 0) {
        fprintf(stderr, "interface not found: %s\n", g_iface);
        return 1;
    }

    /* MAC-adres van de AP-interface ophalen */
    {
        int tmp = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp < 0) {
            fprintf(stderr, "socket (tmp): %s\n", strerror(errno));
            return 1;
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, g_iface, IFNAMSIZ - 1);
        if (ioctl(tmp, SIOCGIFHWADDR, &ifr) < 0) {
            fprintf(stderr, "SIOCGIFHWADDR: %s\n", strerror(errno));
            close(tmp);
            return 1;
        }
        close(tmp);
        memcpy(g_ap_mac, ifr.ifr_hwaddr.sa_data, 6);
    }

    /* Raw ICMPv6-socket aanmaken */
    g_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }

    /* Hop limit op 255 zetten (vereist door RFC 4861) */
    setsockopt(g_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
               &hoplimit, sizeof(hoplimit));

    /* Kernel laten de ICMPv6-checksum berekenen (offset 2) */
    setsockopt(g_sock, IPPROTO_IPV6, IPV6_CHECKSUM, &ckoff, sizeof(ckoff));

    /* Bind aan AP link-local zodat bronAdres correct is */
    memset(&src, 0, sizeof(src));
    src.sin6_family   = AF_INET6;
    src.sin6_addr     = g_ap_lladdr;
    src.sin6_scope_id = g_ifindex;
    if (bind(g_sock, (struct sockaddr *)&src, sizeof(src)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        close(g_sock);
        return 1;
    }

    /* Alle inkomende ICMPv6-pakketten blokkeren — wij alleen zenden */
    ICMP6_FILTER_SETBLOCKALL(&filter);
    setsockopt(g_sock, IPPROTO_ICMPV6, ICMP6_FILTER,
               &filter, sizeof(filter));

    printf("started\n");
    fflush(stdout);

    /* Hoofdlus: stdin-commando's verwerken + periodiek verzenden */
    pfd.fd     = STDIN_FILENO;
    pfd.events = POLLIN;

    for (;;) {
        time_t now        = time(NULL);
        int    timeout_ms = (int)((g_interval - (now - last_send)) * 1000);
        if (timeout_ms < 0) timeout_ms = 0;

        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Periodieke verzending */
        now = time(NULL);
        if (now - last_send >= g_interval) {
            if (g_num_clients > 0 && g_num_targets > 0) {
                send_all();
            }
            last_send = now;
        }

        /* Stdin-commando verwerken */
        if (ret > 0 && (pfd.revents & POLLIN)) {
            if (fgets(line, sizeof(line), stdin) == NULL) break;
            line[strcspn(line, "\r\n")] = 0;

            char *cmd = strtok(line, " \t");
            char *arg = strtok(NULL, " \t");
            if (!cmd) continue;

            if (strcmp(cmd, "client") == 0 && arg) {
                struct in6_addr addr;
                if (inet_pton(AF_INET6, arg, &addr) == 1
                    && g_num_clients < MAX_CLIENTS)
                {
                    /* Alleen link-local adressen (fe80::/10) accepteren als client.
                       Globale unicast zijn niet bereikbaar via een link-local socket. */
                    if (addr.s6_addr[0] != 0xfe || (addr.s6_addr[1] & 0xc0) != 0x80) {
                        printf("warning: skipping non-link-local client: %s\n", arg);
                        fflush(stdout);
                        continue;
                    }
                    int dup = 0, i;
                    for (i = 0; i < g_num_clients; i++) {
                        if (memcmp(&g_clients[i], &addr, 16) == 0) {
                            dup = 1; break;
                        }
                    }
                    if (!dup) {
                        g_clients[g_num_clients++] = addr;
                        printf("client added: %s\n", arg);
                        fflush(stdout);
                        /* direct redirect sturen naar nieuwe client */
                        for (i = 0; i < g_num_targets; i++) {
                            send_redirect(&addr, &g_targets[i]);
                        }
                    }
                }

            } else if (strcmp(cmd, "target") == 0 && arg) {
                struct in6_addr addr;
                if (inet_pton(AF_INET6, arg, &addr) == 1
                    && g_num_targets < MAX_TARGETS)
                {
                    int dup = 0, i;
                    for (i = 0; i < g_num_targets; i++) {
                        if (memcmp(&g_targets[i], &addr, 16) == 0) {
                            dup = 1; break;
                        }
                    }
                    if (!dup) {
                        g_targets[g_num_targets++] = addr;
                        printf("target added: %s\n", arg);
                        fflush(stdout);
                        /* direct redirect sturen naar alle bekende clients */
                        for (i = 0; i < g_num_clients; i++) {
                            send_redirect(&g_clients[i], &addr);
                        }
                    }
                }

            } else if (strcmp(cmd, "interval") == 0 && arg) {
                int iv = atoi(arg);
                if (iv > 0) {
                    g_interval = iv;
                    printf("interval set: %d\n", iv);
                    fflush(stdout);
                }

            } else if (strcmp(cmd, "flush") == 0) {
                send_all();
                printf("flush done\n");
                fflush(stdout);

            } else if (strcmp(cmd, "quit") == 0) {
                break;
            }
        }
    }

    close(g_sock);
    return 0;
}
