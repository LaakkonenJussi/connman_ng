/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2022 Matthias Gerstner of SUSE. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>
#include <gweb/gresolv.h>

#include <glib.h>

#include "shared/dns.h"
#include "connman.h"

#ifdef DNSPROXY_DEBUG
#	define debug(fmt...) do { fprintf(stderr, fmt); fprintf(stderr, "\n"); } while (0)
#else
#	define debug(fmt...) do { } while (0)
#endif

struct cache_data {
	time_t inserted;
	time_t valid_until;
	time_t cache_until;
	int timeout;
	uint16_t type;
	uint16_t answers;
	unsigned int data_len;
	unsigned char *data; /* contains DNS header + body */
};

struct cache_entry {
	char *key;
	bool want_refresh;
	size_t hits;
	struct cache_data *ipv4;
	struct cache_data *ipv6;
};

struct cache_timeout {
	time_t current_time;
	time_t max_timeout;
	bool try_harder;
};

/*
 * We limit how long the cached DNS entry stays in the cache.
 * By default the TTL (time-to-live) of the DNS response is used
 * when setting the cache entry life time. The value is in seconds.
 */
#define MAX_CACHE_TTL (60 * 30)
/*
 * Also limit the other end, cache at least for 30 seconds.
 */
#define MIN_CACHE_TTL (30)

/*
 * We limit the cache size to some sane value so that cached data does
 * not occupy too much memory. Each cached entry occupies on average
 * about 100 bytes memory (depending on DNS name length).
 * Example: caching www.connman.net uses 97 bytes memory.
 * The value is the max amount of cached DNS responses (count).
 */
#define MAX_CACHE_SIZE 256

static int cache_size;
static GHashTable *cache;
static int cache_refcount;
static GSList *server_list;
static GSList *request_list;
static GHashTable *listener_table;
static time_t next_refresh;
static GHashTable *partial_tcp_req_table;
static guint cache_timer;
/* we can keep using the same resolve's */
static GResolv *ipv4_resolve;
static GResolv *ipv6_resolve;

/*
 * There is a power and efficiency benefit to have entries
 * in our cache expire at the same time. To this extend,
 * we round down the cache valid time to common boundaries.
 */
static time_t round_down_ttl(time_t end_time, int ttl)
{
	if (ttl < 15)
		return end_time;

	/* Less than 5 minutes, round to 10 second boundary */
	if (ttl < 300) {
		end_time = end_time / 10;
		end_time = end_time * 10;
	} else { /* 5 or more minutes, round to 30 seconds */
		end_time = end_time / 30;
		end_time = end_time * 30;
	}
	return end_time;
}

static void dummy_resolve_func(GResolvResultStatus status,
					char **results, gpointer user_data)
{
}

/*
 * Refresh a DNS entry, but also age the hit count a bit */
static void refresh_dns_entry(struct cache_entry *entry, char *name)
{
	unsigned int age = 1;

	if (!ipv4_resolve) {
		ipv4_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv4_resolve, AF_INET);
		g_resolv_add_nameserver(ipv4_resolve, "127.0.0.1", 53, 0);
	}

	if (!ipv6_resolve) {
		ipv6_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv6_resolve, AF_INET6);
		g_resolv_add_nameserver(ipv6_resolve, "::1", 53, 0);
	}

	if (!entry->ipv4) {
		debug("Refreshing A record for %s", name);
		g_resolv_lookup_hostname(ipv4_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	if (!entry->ipv6) {
		debug("Refreshing AAAA record for %s", name);
		g_resolv_lookup_hostname(ipv6_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	if (entry->hits > age)
		entry->hits -= age;
	else
		entry->hits = 0;
}

static size_t dns_name_length(const unsigned char *buf)
{
	if ((buf[0] & NS_CMPRSFLGS) == NS_CMPRSFLGS) /* compressed name */
		return 2;
	return strlen((const char *)buf) + 1;
}

static void update_cached_ttl(unsigned char *ptr, size_t len, int new_ttl)
{
	size_t name_len;
	const uint32_t raw_ttl = ntohl((uint32_t)new_ttl);

	if (new_ttl < 0 || len < DNS_HEADER_SIZE + DNS_QUESTION_SIZE + 1)
		return;

	/* skip the header */
	ptr += DNS_HEADER_SIZE;
	len -= DNS_HEADER_SIZE;

	/* skip the query, which is a name and a struct domain_question */
	name_len = dns_name_length(ptr);

	if (len < name_len + DNS_QUESTION_SIZE)
		return;

	ptr += name_len + DNS_QUESTION_SIZE;
	len -= name_len + DNS_QUESTION_SIZE;

	/* now we get the answer records */

	while (len > 0) {
		struct domain_rr *rr = NULL;
		size_t rr_len;

		/* first a name */
		name_len = dns_name_length(ptr);
		if (len < name_len)
			break;

		ptr += name_len;
		len -= name_len;

		rr = (void*)ptr;
		if (len < sizeof(*rr))
			/* incomplete record */
			break;

		/* update the TTL field */
		memcpy(&rr->ttl, &raw_ttl, sizeof(raw_ttl));

		/* skip to the next record */
		rr_len = sizeof(*rr) + ntohs(rr->rdlen);
		if (len < rr_len)
			break;

		ptr += rr_len;
		len -= rr_len;
	}
}

static void send_cached_response(int sk, const unsigned char *ptr, size_t len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol, int id, uint16_t answers, int ttl)
{
	struct domain_hdr *hdr = NULL;
	int err;
	size_t bytes_sent;
	const size_t offset = dns_protocol_offset(protocol);
	/*
	 * The cached packet contains always the TCP offset (two bytes)
	 * so skip them for UDP.
	 */
	const size_t skip_bytes = offset ? 0 : DNS_HEADER_TCP_EXTRA_BYTES;
	size_t dns_len;

	ptr += skip_bytes;
	len -= skip_bytes;
	dns_len = protocol == IPPROTO_UDP ? len : ntohs(*((uint16_t*)ptr));


	if (len < DNS_HEADER_SIZE)
		return;

	hdr = (void *) (ptr + offset);

	hdr->id = id;
	hdr->qr = 1;
	hdr->rcode = ns_r_noerror;
	hdr->ancount = htons(answers);
	hdr->nscount = 0;
	hdr->arcount = 0;

	/* if this is a negative reply, we are authoritative */
	if (answers == 0)
		hdr->aa = 1;
	else
		update_cached_ttl((unsigned char *)hdr, dns_len, ttl);

	debug("sk %d id 0x%04x answers %d ptr %p length %zd dns %zd",
		sk, hdr->id, answers, ptr, len, dns_len);

	err = sendto(sk, ptr, len, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Cannot send cached DNS response: %s",
				strerror(errno));
	}

	bytes_sent = err;
	if (bytes_sent != len || dns_len != (len - offset))
		debug("Packet length mismatch, sent %d wanted %zd dns %zd",
			err, len, dns_len);
}

static bool cache_check_is_valid(struct cache_data *data, time_t current_time)
{
	if (!data)
		return false;
	else if (data->cache_until < current_time)
		return false;

	return true;
}

static void cache_free_ipv4(struct cache_entry *entry)
{
	if (!entry->ipv4)
		return;

	g_free(entry->ipv4->data);
	g_free(entry->ipv4);
	entry->ipv4 = NULL;
}

static void cache_free_ipv6(struct cache_entry *entry)
{
	if (!entry->ipv6)
		return;

	g_free(entry->ipv6->data);
	g_free(entry->ipv6);
	entry->ipv6 = NULL;
}

/*
 * remove stale cached entries so that they can be refreshed
 */
static void cache_enforce_validity(struct cache_entry *entry)
{
	time_t current_time = time(NULL);

	if (entry->ipv4 && !cache_check_is_valid(entry->ipv4, current_time)) {
		debug("cache timeout \"%s\" type A", entry->key);
		cache_free_ipv4(entry);
	}

	if (entry->ipv6 && !cache_check_is_valid(entry->ipv6, current_time)) {
		debug("cache timeout \"%s\" type AAAA", entry->key);
		cache_free_ipv6(entry);
	}
}

static bool cache_check_validity(const char *question, uint16_t type,
				struct cache_entry *entry)
{
	struct cache_data *cached_ip = NULL, *other_ip = NULL;
	const time_t current_time = time(NULL);
	bool want_refresh;

	cache_enforce_validity(entry);

	switch (type) {
	case DNS_TYPE_A: /* IPv4 */
		cached_ip = entry->ipv4;
		other_ip = entry->ipv6;
		break;

	case DNS_TYPE_AAAA: /* IPv6 */
		cached_ip = entry->ipv6;
		other_ip = entry->ipv4;
		break;
	default:
		return false;
	}

	/*
	 * if we have a popular entry, we want a refresh instead of
	 * total destruction of the entry.
	 */
	want_refresh = entry->hits > 2 ? true : false;

	if (!cache_check_is_valid(cached_ip, current_time)) {
		debug("cache %s \"%s\" type %s",
				cached_ip ?  "timeout" : "entry missing",
				question,
				cached_ip == entry->ipv4 ? "A" : "AAAA");

		if (want_refresh)
			entry->want_refresh = true;
		/*
		 * We do not remove cache entry if there is still a
		 * valid entry for another IP version found in the cache.
		 */
		else if (!cache_check_is_valid(other_ip, current_time)) {
			g_hash_table_remove(cache, question);
			return false;
		}
	}

	return true;
}

static void cache_element_destroy(gpointer value)
{
	struct cache_entry *entry = value;

	if (!entry)
		return;

	cache_free_ipv4(entry);
	cache_free_ipv6(entry);

	g_free(entry->key);
	g_free(entry);

	/* TODO: this would be a worrying condition. Does this ever happen? */
	if (--cache_size < 0)
		cache_size = 0;
}

static gboolean try_remove_cache(gpointer user_data)
{
	cache_timer = 0;

	if (__sync_fetch_and_sub(&cache_refcount, 1) == 1) {
		debug("No cache users, removing it.");

		g_hash_table_destroy(cache);
		cache = NULL;
		cache_size = 0;
	}

	return FALSE;
}

static void create_cache(void)
{
	if (__sync_fetch_and_add(&cache_refcount, 1) == 0) {
		cache = g_hash_table_new_full(g_str_hash,
					g_str_equal,
					NULL,
					cache_element_destroy);
		cache_size = 0;
	}
}

static struct cache_entry *cache_check(gpointer request, uint16_t *qtype, int proto)
{
	const char *question;
	size_t offset;
	const struct domain_question *q;
	uint16_t type;
	struct cache_entry *entry;

	if (!request)
		return NULL;

	question = request + dns_protocol_offset(proto) + DNS_HEADER_SIZE;
	offset = strlen(question) + 1;
	q = (void *) (question + offset);
	type = ntohs(q->type);

	/* We only cache either A (1) or AAAA (28) requests */
	if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA)
		return NULL;

	if (!cache) {
		create_cache();
		return NULL;
	}

	entry = g_hash_table_lookup(cache, question);
	if (!entry)
		return NULL;

	if (!cache_check_validity(question, type, entry))
		return NULL;

	*qtype = type;
	return entry;
}

static int send_from_cache(struct dns_request_data *req,
				unsigned char *buf, uint16_t qtype,
				int socket, int protocol)
{
	struct cache_entry *entry;

	entry = cache_check(buf, &qtype, protocol);
	if (entry) {
		struct cache_data *data;

		data = qtype == DNS_TYPE_A ? entry->ipv4 : entry->ipv6;
		if (data) {
			int ttl_left = data->valid_until - time(NULL);
			entry->hits++;

			send_cached_response(socket, data->data,
					data->data_len, NULL, 0, protocol,
					req->srcid, data->answers, ttl_left);

			g_free(req);
			return 1;
		}
	}

	return 0;
}

/*
 * Get a label/name from DNS resource record. The function decompresses the
 * label if necessary. The function does not convert the name to presentation
 * form. This means that the result string will contain label lengths instead
 * of dots between labels. We intentionally do not want to convert to dotted
 * format so that we can cache the wire format string directly.
 */
static int get_name(int counter,
		const unsigned char *pkt, const unsigned char *start, const unsigned char *max,
		unsigned char *output, int output_max, int *output_len,
		const unsigned char **end, char *name, size_t max_name, int *name_len)
{
	const unsigned char *p = start;

	/* Limit recursion to 10 (this means up to 10 labels in domain name) */
	if (counter > 10)
		return -EINVAL;

	while (*p) {
		if ((*p & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			const uint16_t offset = (*p & 0x3F) * 256 + *(p + 1);

			if (offset >= max - pkt)
				return -ENOBUFS;

			if (!*end)
				*end = p + 2;

			return get_name(counter + 1, pkt, pkt + offset, max,
					output, output_max, output_len, end,
					name, max_name, name_len);
		} else {
			unsigned label_len = *p;

			if (pkt + label_len > max)
				return -ENOBUFS;
			else if (*output_len > output_max)
				return -ENOBUFS;
			else if ((*name_len + 1 + label_len + 1) > max_name)
				return -ENOBUFS;

			/*
			 * We need the original name in order to check
			 * if this answer is the correct one.
			 */
			name[(*name_len)++] = label_len;
			memcpy(name + *name_len, p + 1,	label_len + 1);
			*name_len += label_len;

			/* We compress the result */
			output[0] = NS_CMPRSFLGS;
			output[1] = 0x0C;
			*output_len = 2;

			p += label_len + 1;

			if (!*end)
				*end = p;

			if (p >= max)
				return -ENOBUFS;
		}
	}

	return 0;
}

static int parse_rr(const unsigned char *buf, const unsigned char *start,
			const unsigned char *max,
			unsigned char *response, size_t *response_size,
			uint16_t *type, uint16_t *class, int *ttl, uint16_t *rdlen,
			const unsigned char **end,
			char *name, size_t max_name)
{
	struct domain_rr *rr;
	size_t offset;
	int name_len = 0, output_len = 0, max_rsp = *response_size;
	int err = get_name(0, buf, start, max, response, max_rsp,
		&output_len, end, name, max_name, &name_len);

	if (err < 0)
		return err;

	offset = output_len;

	if (offset > *response_size)
		return -ENOBUFS;

	rr = (void *) (*end);

	if (!rr)
		return -EINVAL;

	*type = ntohs(rr->type);
	*class = ntohs(rr->class);
	*ttl = ntohl(rr->ttl);
	*rdlen = ntohs(rr->rdlen);

	if (*ttl < 0)
		return -EINVAL;

	memcpy(response + offset, *end, DNS_RR_SIZE);

	offset += DNS_RR_SIZE;
	*end += DNS_RR_SIZE;

	if ((offset + *rdlen) > *response_size)
		return -ENOBUFS;

	if ((*end + *rdlen) > max)
		return -EINVAL;

	memcpy(response + offset, *end, *rdlen);

	*end += *rdlen;
	*response_size = offset + *rdlen;

	return 0;
}

static bool check_alias(GSList *aliases, const char *name)
{
	if (aliases) {
		for (GSList *list = aliases; list; list = list->next) {
			const char *cmpname = (const char*)list->data;
			if (strncmp(cmpname, name, NS_MAXDNAME) == 0)
				return true;
		}
	}

	return false;
}

/*
 * Parses the DNS response packet found in 'buf' consisting of 'buflen' bytes.
 *
 * The parsed question label, response type and class, ttl and number of
 * answer sections are output parameters. The response output buffer will
 * receive all matching resource records to be cached.
 *
 * Return value is < 0 on error (negative errno) or zero on success.
 */
static int parse_response(const unsigned char *buf, size_t buflen,
			char *question, size_t qlen,
			uint16_t *type, uint16_t *class, int *ttl,
			unsigned char *response, size_t *response_len,
			uint16_t *answers)
{
	struct domain_hdr *hdr = (void *) buf;
	struct domain_question *q;
	uint16_t qtype;
	int err = -ENOMSG;
	uint16_t ancount, qclass;
	GSList *aliases = NULL;
	const size_t maxlen = *response_len;
	uint16_t qdcount;
	const unsigned char *ptr;
	const unsigned char *eptr;

	*response_len = 0;
	*answers = 0;

	if (buflen < DNS_HEADER_SIZE)
		return -EINVAL;

	qdcount = ntohs(hdr->qdcount);
	ptr = buf + DNS_HEADER_SIZE;
	eptr = buf + buflen;

	debug("qr %d qdcount %d", hdr->qr, qdcount);

	/* We currently only cache responses where question count is 1 */
	if (hdr->qr != 1 || qdcount != 1)
		return -EINVAL;

	/*
	 * NOTE: currently the *caller* ensures that the `question' buffer is
	 * always zero terminated.
	 */
	strncpy(question, (const char *) ptr, MIN(qlen, buflen - DNS_HEADER_SIZE));
	qlen = strlen(question);
	ptr += qlen + 1; /* skip \0 */

	if (ptr + DNS_QUESTION_SIZE >= eptr)
		return -EINVAL;

	q = (void *) ptr;
	qtype = ntohs(q->type);

	/* We cache only A and AAAA records */
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA)
		return -ENOMSG;

	ptr += DNS_QUESTION_SIZE; /* advance to answers section */

	ancount = ntohs(hdr->ancount);
	qclass = ntohs(q->class);

	/*
	 * We have a bunch of answers (like A, AAAA, CNAME etc) to
	 * A or AAAA question. We traverse the answers and parse the
	 * resource records. Only A and AAAA records are cached, all
	 * the other records in answers are skipped.
	 */
	for (uint16_t i = 0; i < ancount; i++) {
		char name[NS_MAXDNAME + 1] = {0};
		/*
		 * Get one address at a time to this buffer.
		 * The max size of the answer is
		 *   2 (pointer) + 2 (type) + 2 (class) +
		 *   4 (ttl) + 2 (rdlen) + addr (16 or 4) = 28
		 * for A or AAAA record.
		 * For CNAME the size can be bigger.
		 * TODO: why are we using the MAXCDNAME constant as buffer
		 * size then?
		 */
		unsigned char rsp[NS_MAXCDNAME] = {0};
		size_t rsp_len = sizeof(rsp) - 1;
		const unsigned char *next = NULL;
		uint16_t rdlen;

		int ret = parse_rr(buf, ptr, buf + buflen, rsp, &rsp_len,
			type, class, ttl, &rdlen, &next, name,
			sizeof(name) - 1);
		if (ret != 0) {
			err = ret;
			break;
		}

		/* set pointer to the next RR for the next iteration */
		ptr = next;

		/*
		 * Now rsp contains a compressed or an uncompressed resource
		 * record. Next we check if this record answers the question.
		 * The name var contains the uncompressed label.
		 * One tricky bit is the CNAME records as they alias
		 * the name we might be interested in.
		 */

		/*
		 * Go to next answer if the class is not the one we are
		 * looking for.
		 */
		if (*class != qclass) {
			continue;
		}

		/*
		 * Try to resolve aliases also, type is CNAME(5).
		 * This is important as otherwise the aliased names would not
		 * be cached at all as the cache would not contain the aliased
		 * question.
		 *
		 * If any CNAME is found in DNS packet, then we cache the alias
		 * IP address instead of the question (as the server
		 * said that question has only an alias).
		 * This means in practice that if e.g., ipv6.google.com is
		 * queried, DNS server returns CNAME of that name which is
		 * ipv6.l.google.com. We then cache the address of the CNAME
		 * but return the question name to client. So the alias
		 * status of the name is not saved in cache and thus not
		 * returned to the client. We do not return DNS packets from
		 * cache to client saying that ipv6.google.com is an alias to
		 * ipv6.l.google.com but we return instead a DNS packet that
		 * says ipv6.google.com has address xxx which is in fact the
		 * address of ipv6.l.google.com. For caching purposes this
		 * should not cause any issues.
		 */
		if (*type == DNS_TYPE_CNAME && strncmp(question, name, qlen) == 0) {
			/*
			 * So now the alias answered the question. This is
			 * not very useful from caching point of view as
			 * the following A or AAAA records will not match the
			 * question. We need to find the real A/AAAA record
			 * of the alias and cache that.
			 */
			const unsigned char *end = NULL;
			int name_len = 0, output_len = 0;

			memset(rsp, 0, sizeof(rsp));
			rsp_len = sizeof(rsp) - 1;

			/*
			 * Alias is in rdata part of the message,
			 * and next-rdlen points to it. So we need to get
			 * the real name of the alias.
			 */
			ret = get_name(0, buf, next - rdlen, buf + buflen,
					rsp, rsp_len, &output_len, &end,
					name, sizeof(name) - 1, &name_len);
			if (ret != 0) {
				/* just ignore the error at this point */
				continue;
			}

			/*
			 * We should now have the alias of the entry we might
			 * want to cache. Just remember it for a while.
			 * We check the alias list when we have parsed the
			 * A or AAAA record.
			 */
			aliases = g_slist_prepend(aliases, g_strdup(name));

			continue;
		} else if (*type == qtype) {
			/*
			 * We found correct type (A or AAAA)
			 */
			if (check_alias(aliases, name) ||
				(!aliases && strncmp(question, name,
							qlen) == 0)) {
				/*
				 * We found an alias or the name of the rr
				 * matches the question. If so, we append
				 * the compressed label to the cache.
				 * The end result is a response buffer that
				 * will contain one or more cached and
				 * compressed resource records.
				 */
				if (*response_len + rsp_len > maxlen) {
					err = -ENOBUFS;
					break;
				}
				memcpy(response + *response_len, rsp, rsp_len);
				*response_len += rsp_len;
				(*answers)++;
				err = 0;
			}
		}
	}

	for (GSList *list = aliases; list; list = list->next)
		g_free(list->data);
	g_slist_free(aliases);

	return err;
}

static gboolean cache_check_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_timeout *data = user_data;
	struct cache_entry *entry = value;
	time_t max_timeout;

	/* Scale the number of hits by half as part of cache aging */

	entry->hits /= 2;

	/*
	 * If either IPv4 or IPv6 cached entry has expired, we
	 * remove both from the cache.
	 */

	if (entry->ipv4 && entry->ipv4->timeout > 0) {
		max_timeout = entry->ipv4->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv4->cache_until < data->current_time)
			return TRUE;
	}

	if (entry->ipv6 && entry->ipv6->timeout > 0) {
		max_timeout = entry->ipv6->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv6->cache_until < data->current_time)
			return TRUE;
	}

	/*
	 * if we're asked to try harder, also remove entries that have
	 * few hits
	 */
	if (data->try_harder && entry->hits < 4)
		return TRUE;

	return FALSE;
}

static void cache_cleanup(void)
{
	static time_t max_timeout;
	struct cache_timeout data = {
		.current_time = time(NULL),
		.max_timeout = 0,
		.try_harder = false
	};
	int count = 0;

	/*
	 * In the first pass, we only remove entries that have timed out.
	 * We use a cache of the first time to expire to do this only
	 * when it makes sense.
	 */
	if (max_timeout <= data.current_time) {
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);
	}
	debug("removed %d in the first pass", count);

	/*
	 * In the second pass, if the first pass turned up blank,
	 * we also expire entries with a low hit count,
	 * while aging the hit count at the same time.
	 */
	data.try_harder = true;
	if (count == 0)
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);

	if (count == 0)
		/*
		 * If we could not remove anything, then remember
		 * what is the max timeout and do nothing if we
		 * have not yet reached it. This will prevent
		 * constant traversal of the cache if it is full.
		 */
		max_timeout = data.max_timeout;
	else
		max_timeout = 0;
}

static gboolean cache_invalidate_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	/* first, delete any expired elements */
	cache_enforce_validity(entry);

	/* if anything is not expired, mark the entry for refresh */
	if (entry->hits > 0 && (entry->ipv4 || entry->ipv6))
		entry->want_refresh = true;

	/* delete the cached data */
	cache_free_ipv4(entry);
	cache_free_ipv6(entry);

	/* keep the entry if we want it refreshed, delete it otherwise */
	return entry->want_refresh ? FALSE : TRUE;
}

/*
 * cache_invalidate is called from places where the DNS landscape
 * has changed, say because connections are added or we entered a VPN.
 * The logic is to wipe all cache data, but mark all non-expired
 * parts of the cache for refresh rather than deleting the whole cache.
 */
static void cache_invalidate(void)
{
	debug("Invalidating the DNS cache %p", cache);

	if (!cache)
		return;

	g_hash_table_foreach_remove(cache, cache_invalidate_entry, NULL);
}

static void cache_refresh_entry(struct cache_entry *entry)
{
	cache_enforce_validity(entry);

	if (entry->hits > 2 && (!entry->ipv4 || !entry->ipv6))
		entry->want_refresh = true;

	if (entry->want_refresh) {
		char dns_name[NS_MAXDNAME + 1];
		char *c;

		entry->want_refresh = false;

		/* turn a DNS name into a hostname with dots */
		strncpy(dns_name, entry->key, NS_MAXDNAME);
		c = dns_name;
		while (*c) {
			/* fetch the size of the current component and replace
			   it by a dot */
			int jump = *c;
			*c = '.';
			c += jump + 1;
		}
		debug("Refreshing %s\n", dns_name);
		/* then refresh the hostname */
		refresh_dns_entry(entry, &dns_name[1]);
	}
}

static void cache_refresh_iterator(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	cache_refresh_entry(entry);
}

static void cache_refresh(void)
{
	if (!cache)
		return;

	g_hash_table_foreach(cache, cache_refresh_iterator, NULL);
}

static int reply_query_type(const unsigned char *msg, int len)
{
	/* skip the header */
	const unsigned char *c = msg + DNS_HEADER_SIZE;
	int type;
	len -= DNS_HEADER_SIZE;

	if (len < 0)
		return 0;

	/* now the query, which is a name and 2 16 bit words for type and class */
	c += dns_name_length(c);

	type = c[0] << 8 | c[1];

	return type;
}

/*
 * update the cache with the DNS reply found in msg
 */
static int cache_update(struct dns_server_data *srv, const unsigned char *msg, size_t msg_len)
{
	const size_t offset = dns_protocol_offset(srv->protocol);
	int err, ttl = 0;
	uint16_t *lenhdr;
	size_t qlen;
	bool is_new_entry = false;
	uint16_t answers = 0, type = 0, class = 0;
	struct domain_hdr *hdr = (void *)(msg + offset);
	struct domain_question *q = NULL;
	struct cache_entry *entry;
	struct cache_data *data;
	char question[NS_MAXDNAME + 1];
	unsigned char response[NS_MAXDNAME + 1];
	unsigned char *ptr = NULL;
	size_t rsplen = sizeof(response) - 1;
	const time_t current_time = time(NULL);

	if (cache_size >= MAX_CACHE_SIZE) {
		cache_cleanup();
		if (cache_size >= MAX_CACHE_SIZE)
			return 0;
	}

	/* don't do a cache refresh more than twice a minute */
	if (next_refresh < current_time) {
		cache_refresh();
		next_refresh = current_time + 30;
	}

	debug("offset %zd hdr %p msg %p rcode %d", offset, hdr, msg, hdr->rcode);

	/* Continue only if response code is 0 (=ok) */
	if (hdr->rcode != ns_r_noerror)
		return 0;

	if (!cache)
		create_cache();

	question[sizeof(question) - 1] = '\0';
	err = parse_response(msg + offset, msg_len - offset,
				question, sizeof(question) - 1,
				&type, &class, &ttl,
				response, &rsplen, &answers);

	/*
	 * special case: if we do a ipv6 lookup and get no result
	 * for a record that's already in our ipv4 cache.. we want
	 * to cache the negative response.
	 */
	if ((err == -ENOMSG || err == -ENOBUFS) &&
			reply_query_type(msg + offset,
					msg_len - offset) == DNS_TYPE_AAAA) {
		entry = g_hash_table_lookup(cache, question);
		if (entry && entry->ipv4 && !entry->ipv6) {
			struct cache_data *data = g_try_new(struct cache_data, 1);

			if (!data)
				return -ENOMEM;
			data->inserted = entry->ipv4->inserted;
			data->type = type;
			data->answers = ntohs(hdr->ancount);
			data->timeout = entry->ipv4->timeout;
			data->data_len = msg_len +
				(offset ? 0 : DNS_HEADER_TCP_EXTRA_BYTES);
			data->data = g_malloc(data->data_len);
			ptr = data->data;
			if (srv->protocol == IPPROTO_UDP) {
				/* add the two bytes length header also for
				 * UDP responses */
				lenhdr = (void*)ptr;
				*lenhdr = htons(data->data_len -
						DNS_HEADER_TCP_EXTRA_BYTES);
				ptr += DNS_HEADER_TCP_EXTRA_BYTES;
			}
			data->valid_until = entry->ipv4->valid_until;
			data->cache_until = entry->ipv4->cache_until;
			memcpy(ptr, msg, msg_len);
			entry->ipv6 = data;
			/*
			 * we will get a "hit" when we serve the response
			 * out of the cache
			 */
			entry->hits = entry->hits ? entry->hits - 1 : 0;
			return 0;
		}
	}

	if (err < 0 || ttl == 0)
		return 0;

	/*
	 * If the cache contains already data, check if the
	 * type of the cached data is the same and do not add
	 * to cache if data is already there.
	 * This is needed so that we can cache both A and AAAA
	 * records for the same name.
	 */

	entry = g_hash_table_lookup(cache, question);
	data = NULL;
	is_new_entry = !entry;

	if (!entry) {
		entry = g_try_new(struct cache_entry, 1);
		if (!entry)
			return -ENOMEM;

		data = g_try_new(struct cache_data, 1);
		if (!data) {
			g_free(entry);
			return -ENOMEM;
		}

		entry->key = g_strdup(question);
		entry->ipv4 = entry->ipv6 = NULL;
		entry->want_refresh = false;
		entry->hits = 0;

	} else {
		if (type == DNS_TYPE_A && entry->ipv4)
			return 0;
		else if (type == DNS_TYPE_AAAA && entry->ipv6)
			return 0;

		data = g_try_new(struct cache_data, 1);
		if (!data)
			return -ENOMEM;

		/*
		 * compensate for the hit we'll get for serving
		 * the response out of the cache
		 */
		entry->hits = entry->hits ? entry->hits - 1 : 0;
	}

	if (type == DNS_TYPE_A)
		entry->ipv4 = data;
	else
		entry->ipv6 = data;

	if (ttl < MIN_CACHE_TTL)
		ttl = MIN_CACHE_TTL;

	data->inserted = current_time;
	data->type = type;
	data->answers = answers;
	data->timeout = ttl;
	data->valid_until = current_time + ttl;

	qlen = strlen(question);
	/*
	 * We allocate the extra TCP header bytes here even for UDP packet
	 * because it simplifies the sending of cached packet.
	 */
	data->data_len =  DNS_TCP_HEADER_SIZE + qlen + 1 + 2 + 2 + rsplen;
	data->data = g_malloc(data->data_len);
	if (!data->data) {
		g_free(entry->key);
		g_free(data);
		g_free(entry);
		return -ENOMEM;
	}

	/*
	 * Restrict the cached DNS record TTL to some sane value
	 * in order to prevent data staying in the cache too long.
	 */
	if (ttl > MAX_CACHE_TTL)
		ttl = MAX_CACHE_TTL;

	data->cache_until = round_down_ttl(current_time + ttl, ttl);

	ptr = data->data;

	/*
	 * We cache the two extra bytes at the start of the message
	 * in a TCP packet. When sending UDP packet, we pad the first
	 * two bytes. This way we do not need to know the format
	 * (UDP/TCP) of the cached message.
	 */
	lenhdr = (void*)ptr;
	*lenhdr = htons(data->data_len - DNS_HEADER_TCP_EXTRA_BYTES);
	ptr += DNS_HEADER_TCP_EXTRA_BYTES;

	memcpy(ptr, hdr, DNS_HEADER_SIZE);
	ptr += DNS_HEADER_SIZE;

	memcpy(ptr, question, qlen + 1); /* copy also the \0 */
	ptr += qlen + 1;

	q = (void *)ptr;
	q->type = htons(type);
	q->class = htons(class);
	ptr += DNS_QUESTION_SIZE;

	memcpy(ptr, response, rsplen);

	if (is_new_entry) {
		g_hash_table_replace(cache, entry->key, entry);
		cache_size++;
	}

	debug("cache %d %squestion \"%s\" type %d ttl %d size %zd packet %u "
								"dns len %u",
		cache_size, is_new_entry ? "new " : "old ",
		question, type, ttl,
		sizeof(*entry) + sizeof(*data) + data->data_len + qlen,
		data->data_len,
		srv->protocol == IPPROTO_TCP ?
			(unsigned int)(data->data[0] * 256 + data->data[1]) :
			data->data_len);

	return 0;
}

/*
 * attempts to answer the given request from cached replies.
 *
 * returns:
 * > 0 on cache hit (answer is already sent out to client)
 * == 0 on cache miss
 * < 0 on error condition (errno)
 */
static int ns_try_resolv_from_cache(
		struct dns_request_data *req, gpointer request, const char *lookup)
{
	uint16_t type = 0;
	int ttl_left;
	struct cache_data *data;
	struct cache_entry *entry = cache_check(request, &type, req->protocol);
	if (!entry)
		return 0;

	debug("cache hit %s type %s", lookup, type == 1 ? "A" : "AAAA");

	data = type == DNS_TYPE_A ? entry->ipv4 : entry->ipv6;

	if (!data)
		return 0;

	ttl_left = data->valid_until - time(NULL);
	entry->hits++;

	switch(req->protocol) {
		case IPPROTO_TCP:
			send_cached_response(req->client_sk, data->data,
					data->data_len, NULL, 0, IPPROTO_TCP,
					req->srcid, data->answers, ttl_left);
			return 1;
		case IPPROTO_UDP: {
			int udp_sk = dns_get_req_udp_socket(req);

			if (udp_sk < 0)
				return -EIO;

			send_cached_response(udp_sk, data->data,
				data->data_len, &req->sa, req->sa_len,
				IPPROTO_UDP, req->srcid, data->answers,
				ttl_left);
			return 1;
		}
	}

	return -EINVAL;
}

static void update_domain(int index, const char *domain, bool append)
{
	DBG("index %d domain %s", index, domain);

	if (!domain)
		return;

	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;
		char *dom = NULL;
		bool dom_found = false;

		if (data->index < 0)
			continue;
		else if (data->index != index)
			continue;

		for (GList *dom_list = data->domains; dom_list;
				dom_list = dom_list->next) {
			dom = dom_list->data;

			if (g_str_equal(dom, domain)) {
				dom_found = true;
				break;
			}
		}

		if (!dom_found && append) {
			data->domains =
				g_list_append(data->domains, g_strdup(domain));
		} else if (dom_found && !append) {
			data->domains =
				g_list_remove(data->domains, dom);
			g_free(dom);
		}
	}
}

static void append_domain(int index, const char *domain)
{
	update_domain(index, domain, true);
}

static void remove_domain(int index, const char *domain)
{
	update_domain(index, domain, false);
}

static void flush_requests(struct dns_server_data *server)
{
	GSList *list = request_list;
	while (list) {
		struct dns_request_data *req = list->data;

		list = list->next;

		if (dns_ns_resolv(server, req, req->request, req->name)) {
			/*
			 * A cached result was sent,
			 * so the request can be released
			 */
			request_list =
				g_slist_remove(request_list, req);
			dns_destroy_request_data(req);
			continue;
		}

		if (req->timeout > 0)
			g_source_remove(req->timeout);

		req->timeout = g_timeout_add_seconds(5, dns_request_timeout,
									req);
	}
}

int __connman_dnsproxy_append(int index, const char *domain,
							const char *server)
{
	struct dns_server_data *data;
	DBG("index %d server %s", index, server);

	if (!server) {
		if (!domain) {
			return -EINVAL;
		} else {
			append_domain(index, domain);
			return 0;
		}
	}

	if (g_str_equal(server, "127.0.0.1"))
		return -ENODEV;
	else if (g_str_equal(server, "::1"))
		return -ENODEV;

	data = dns_find_server(index, server, IPPROTO_UDP);
	if (data) {
		append_domain(index, domain);
		return 0;
	}

	if (dns_create_server(index, domain, server, IPPROTO_UDP))
		return -EIO;

	data = dns_find_server(index, server, IPPROTO_UDP);
	if (data)
		flush_requests(data);

	return 0;
}

static void cache_remove_timer(void)
{
	if (cache && !cache_timer)
		cache_timer = g_timeout_add_seconds(3, try_remove_cache, NULL);
}

int __connman_dnsproxy_remove(int index, const char *domain,
							const char *server)
{
	DBG("index %d server %s", index, server);

	if (!server) {
		if (!domain) {
			return -EINVAL;
		} else {
			remove_domain(index, domain);
			return 0;
		}
	}

	if (g_str_equal(server, "127.0.0.1"))
		return -ENODEV;
	else if (g_str_equal(server, "::1"))
		return -ENODEV;

	dns_remove_server(index, server, IPPROTO_UDP);
	dns_remove_server(index, server, IPPROTO_TCP);

	return 0;
}

static void dnsproxy_offline_mode(bool enabled)
{
	DBG("enabled %d", enabled);

	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (!enabled) {
			DBG("Enabling DNS server %s", data->server);
			data->enabled = true;
			cache_invalidate();
			cache_refresh();
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = false;
			cache_invalidate();
		}
	}
}

static void dnsproxy_default_changed(struct connman_service *service)
{
	bool any_server_enabled = false;
	int index, vpn_index;

	DBG("service %p", service);

	/* DNS has changed, invalidate the cache */
	cache_invalidate();

	if (!service) {
		/* When no services are active, then disable DNS proxying */
		dnsproxy_offline_mode(true);
		return;
	}

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	/*
	 * In case non-split-routed VPN is set as split routed the DNS servers
	 * the VPN must be enabled as well, when the transport becomes the
	 * default service.
	 */
	vpn_index = __connman_gateway_get_vpn_index(index);

	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (data->index == index) {
			DBG("Enabling DNS server %s", data->server);
			data->enabled = true;
			any_server_enabled = true;
		} else if (data->index == vpn_index) {
			DBG("Enabling DNS server of VPN %s", data->server);
			data->enabled = true;
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = false;
		}
	}

	if (!any_server_enabled)
		dns_enable_fallback(true);

	cache_refresh();
}

static void dnsproxy_service_state_changed(struct connman_service *service,
			enum connman_service_state state)
{
	GSList *list;
	int index;

	switch (state) {
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_IDLE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_ONLINE:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		return;
	}

	index = __connman_service_get_index(service);
	list = server_list;

	while (list) {
		struct dns_server_data *data = list->data;

		/* Get next before the list is changed by dns_destroy_server() */
		list = list->next;

		if (data->index == index) {
			DBG("removing server data of index %d", index);
			dns_destroy_server(data);
		}
	}
}

static const struct connman_notifier dnsproxy_notifier = {
	.name			= "dnsproxy",
	.default_changed	= dnsproxy_default_changed,
	.offline_mode		= dnsproxy_offline_mode,
	.service_state_changed	= dnsproxy_service_state_changed,
};

int __connman_dnsproxy_add_listener(int index)
{
	int err;

	DBG("index %d", index);

	err = dns_add_listener(index, DNS_IPPROTO_UDP, true);
	if (err)
		return err;

	return 0;
}

void __connman_dnsproxy_remove_listener(int index)
{
	DBG("index %d", index);

	dns_remove_listener(index);
}

static struct dns_callbacks cbs = {
	.create_cache		= create_cache,
	.cache_update		= cache_update,
	.cache_remove_timer	= cache_remove_timer,
	.resolv_from_cache	= ns_try_resolv_from_cache,
	.send_from_cache	= send_from_cache
};

int __connman_dnsproxy_init(void)
{
	int err, index;

	DBG("");

	err = dns_init(&cbs);
	if (err) {
		connman_error("cannot initialize dnsproxy");
		return err;
	}

	index = connman_inet_ifindex("lo");
	err = __connman_dnsproxy_add_listener(index);
	if (err < 0)
		return err;

	err = connman_notifier_register(&dnsproxy_notifier);
	if (err < 0) {
		__connman_dnsproxy_remove_listener(index);
		g_hash_table_destroy(listener_table);
		g_hash_table_destroy(partial_tcp_req_table);

		return err;
	}

	return 0;
}

int __connman_dnsproxy_set_mdns(int index, bool enabled)
{
	return -ENOTSUP;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	if (cache_timer) {
		g_source_remove(cache_timer);
		cache_timer = 0;
	}

	if (cache) {
		g_hash_table_destroy(cache);
		cache = NULL;
	}

	connman_notifier_unregister(&dnsproxy_notifier);

	dns_cleanup();

	if (ipv4_resolve)
		g_resolv_unref(ipv4_resolve);
	if (ipv6_resolve)
		g_resolv_unref(ipv6_resolve);
}

void __connman_dnsproxy_set_listen_port(unsigned int port)
{
	dns_set_listen_port(port);
}
