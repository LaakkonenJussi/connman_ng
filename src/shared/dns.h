/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2022 Matthias Gerstner of SUSE. All rights reserved.
 *  Copyright (C) 2025 Jolla Mobile Ltd. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <resolv.h>

#include <glib.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#elif __BYTE_ORDER == __BIG_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t ra:1;
	uint8_t z:3;
	uint8_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#else
#error "Unknown byte order"
#endif

struct qtype_qclass {
	uint16_t qtype;
	uint16_t qclass;
} __attribute__ ((packed));

/*
 * The TCP client requires some extra handling as we need to
 * be prepared to receive also partial DNS requests.
 */
struct tcp_partial_client_data {
	int family;
	struct dns_listener_data *ifdata;
	GIOChannel *channel;
	guint watch;
	unsigned char *buf;
	unsigned int buf_end;
	guint timeout;
};

struct domain_question {
	uint16_t type;
	uint16_t class;
} __attribute__ ((packed));

struct domain_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
} __attribute__ ((packed));

#define NUM_ARRAY_ELEMENTS(a) sizeof(a) / sizeof(a[0])

/*
 * Max length of the DNS TCP packet.
 */
#define TCP_MAX_BUF_LEN 4096

enum dns_type {
	/* IPv4 address 32-bit */
	DNS_TYPE_A = ns_t_a,
	/* IPv6 address 128-bit */
	DNS_TYPE_AAAA = ns_t_aaaa,
	/* alias to another name */
	DNS_TYPE_CNAME = ns_t_cname,
	/* start of a zone of authority */
	DNS_TYPE_SOA = ns_t_soa
};

enum dns_class {
	DNS_CLASS_IN = ns_c_in,
	DNS_CLASS_ANY = ns_c_any /* only valid for QCLASS fields */
};

#define DNS_HEADER_SIZE sizeof(struct domain_hdr)
#define DNS_HEADER_TCP_EXTRA_BYTES 2
#define DNS_TCP_HEADER_SIZE DNS_HEADER_SIZE + DNS_HEADER_TCP_EXTRA_BYTES
#define DNS_QUESTION_SIZE sizeof(struct domain_question)
#define DNS_RR_SIZE sizeof(struct domain_rr)
#define DNS_QTYPE_QCLASS_SIZE sizeof(struct qtype_qclass)

struct dns_listener_data {
	int index;
	/* Allow listener for loopback without resolvfile getting altered.
	 * Needed for systemd-resolved.
	 */
	bool lo_exclude;

	GIOChannel *udp4_listener_channel;
	GIOChannel *tcp4_listener_channel;
	guint udp4_listener_watch;
	guint tcp4_listener_watch;

	GIOChannel *udp6_listener_channel;
	GIOChannel *tcp6_listener_channel;
	guint udp6_listener_watch;
	guint tcp6_listener_watch;
};

struct dns_request_data {
	union {
		struct sockaddr_in6 __sin6; /* Only for the length */
		struct sockaddr sa;
	};
	socklen_t sa_len;
	int client_sk;
	int protocol;
	int family;
	guint16 srcid;
	guint16 dstid;
	guint16 altid;
	guint timeout;
	guint watch;
	guint numserv;
	guint numresp;
	gpointer request;
	gsize request_len;
	gpointer name;
	gpointer resp;
	gsize resplen;
	struct dns_listener_data *ifdata;
	bool append_domain;
};

struct dns_partial_reply {
	uint16_t len;
	uint16_t received;
	unsigned char buf[];
};

struct dns_server_data {
	int index;
	GList *domains;
	char *server;
	struct sockaddr *server_addr;
	socklen_t server_addr_len;
	int protocol;
	GIOChannel *channel;
	guint watch;
	guint timeout;
	bool enabled;
	bool connected;
	struct dns_partial_reply *incoming_reply;
};

struct dns_callbacks {
	void (*create_cache) (void);
	int (*cache_update) (struct dns_server_data *srv,
				const unsigned char *msg, size_t msg_len);
	void (*cache_remove_timer) (void);
	int (*resolv_from_cache) (struct dns_request_data *req,
				gpointer request, const char *lookup);
	int (*send_from_cache) (struct dns_request_data *req,
				unsigned char *buf, uint16_t qtype,
				int socket, int protocol);
};

enum dns_ipproto {
	DNS_IPPROTO_ALL = 0,
	DNS_IPPROTO_UDP = IPPROTO_UDP,
	DNS_IPPROTO_TCP = IPPROTO_TCP
};

int dns_add_listener(int index, enum dns_ipproto ipproto, bool lo_exclude);
void dns_remove_listener(int index);
int dns_create_server(int index, const char *domain, const char *server,
				int protocol);
void dns_remove_server(int index, const char *server, int protocol);
int dns_enable_server(int index, const char *server, int protocol, bool enable);
void dns_destroy_server(struct dns_server_data *server);
struct dns_server_data *dns_find_server(int index, const char *server,
								int protocol);
void dns_set_listen_port(unsigned int port);
void dns_enable_fallback(bool enable);
int dns_get_req_udp_socket(struct dns_request_data *req);
int dns_ns_resolv(struct dns_server_data *server,
				struct dns_request_data *req,
				gpointer request, gpointer name);
void dns_destroy_request_data(struct dns_request_data *req);
gboolean dns_request_timeout(gpointer user_data);
size_t dns_protocol_offset(int protocol);

int dns_init(struct dns_callbacks *cbs);
void dns_cleanup(void);
