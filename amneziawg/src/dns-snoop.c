/* Passive DNS-response watcher.
 * libpcap on the "any" device only copies frames, so DNS keeps working if
 * this process stops. Learned addresses are mirrored to /data so a restart
 * can put them back into the nft set before the next lookup.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#define MAX_DOMAINS 128
#define MAX_ENTRIES 4096
#define MAX_CHAIN 8
#define MAX_CNAMES 16
#define MAX_ADDRS 16
#define NAME_LEN 256

struct entry {
	char ip[64];
	char name[NAME_LEN];
	int af;
	int64_t exp;
	int used;
};

static char domains[MAX_DOMAINS][NAME_LEN];
static int ndomains;
static struct entry entries[MAX_ENTRIES];
static unsigned timeout_sec = 86400;
static int do_warmup;
static char state_path[512];
static char count_path[512];
static uint64_t matches;
static int dirty;
static time_t dirty_at;
static volatile sig_atomic_t stop_flag;

static void on_signal(int sig) {
	(void)sig;
	stop_flag = 1;
}

static void lower_copy(char *s) {
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

static int load_domains(const char *path) {
	FILE *f = fopen(path, "r");
	char line[NAME_LEN];
	if (!f) {
		fprintf(stderr, "[snoop] cannot read %s: %s\n", path, strerror(errno));
		return -1;
	}
	while (ndomains < MAX_DOMAINS && fgets(line, sizeof line, f)) {
		size_t n = strcspn(line, "\r\n");
		line[n] = 0;
		if (!line[0] || line[0] == '#')
			continue;
		lower_copy(line);
		snprintf(domains[ndomains], NAME_LEN, "%s", line);
		ndomains++;
	}
	fclose(f);
	return 0;
}

static int name_listed(const char *name) {
	size_t nl, dl, i;
	if (!name || !name[0])
		return 0;
	nl = strlen(name);
	for (i = 0; i < (size_t)ndomains; i++) {
		dl = strlen(domains[i]);
		if (nl == dl && strcmp(name, domains[i]) == 0)
			return 1;
		if (nl > dl + 1 && name[nl - dl - 1] == '.' &&
		    strcmp(name + (nl - dl), domains[i]) == 0)
			return 1;
	}
	return 0;
}

static int parse_name(const uint8_t *msg, size_t len, size_t *off, char *out, size_t out_len) {
	size_t o = *off, end = *off, w = 0;
	int jumps = 0, jumped = 0;
	if (o >= len)
		return -1;
	while (jumps < 16 && o < len) {
		uint8_t lab = msg[o];
		if (lab == 0) {
			if (!jumped)
				end = o + 1;
			out[w] = 0;
			*off = end;
			return 0;
		}
		if ((lab & 0xc0) == 0xc0) {
			size_t ptr;
			if (o + 1 >= len)
				return -1;
			ptr = ((size_t)(lab & 0x3f) << 8) | msg[o + 1];
			if (ptr >= len)
				return -1;
			if (!jumped)
				end = o + 2;
			jumped = 1;
			o = ptr;
			jumps++;
			continue;
		}
		if (lab & 0xc0)
			return -1;
		if (o + 1 + lab > len)
			return -1;
		if (w && w + 1 < out_len)
			out[w++] = '.';
		if (w + lab >= out_len)
			return -1;
		memcpy(out + w, msg + o + 1, lab);
		w += lab;
		o += 1 + lab;
	}
	return -1;
}

static void remember(int af, const char *ip, const char *name, int64_t exp) {
	int i, free_slot = -1, soonest = -1;
	int64_t soonest_exp = 0;
	time_t now = time(NULL);
	if (exp <= (int64_t)now)
		return;
	for (i = 0; i < MAX_ENTRIES; i++) {
		if (!entries[i].used) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (entries[i].exp <= (int64_t)now) {
			entries[i].used = 0;
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (entries[i].af == af && strcmp(entries[i].ip, ip) == 0) {
			snprintf(entries[i].name, NAME_LEN, "%s", name);
			entries[i].exp = exp;
			dirty = 1;
			if (!dirty_at)
				dirty_at = now;
			return;
		}
		if (soonest < 0 || entries[i].exp < soonest_exp) {
			soonest = i;
			soonest_exp = entries[i].exp;
		}
	}
	if (free_slot < 0)
		free_slot = soonest;
	if (free_slot < 0)
		return;
	entries[free_slot].used = 1;
	entries[free_slot].af = af;
	entries[free_slot].exp = exp;
	snprintf(entries[free_slot].ip, sizeof entries[free_slot].ip, "%s", ip);
	snprintf(entries[free_slot].name, NAME_LEN, "%s", name);
	dirty = 1;
	if (!dirty_at)
		dirty_at = now;
}

static int nft_add(int af, const char *ip, unsigned seconds) {
	char elem[128];
	pid_t pid;
	int status;
	const char *set = af == 6 ? "routed_v6" : "routed_v4";
	if (seconds == 0)
		seconds = 1;
	snprintf(elem, sizeof elem, "{ %s timeout %us }", ip, seconds);
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		execlp("nft", "nft", "add", "element", "inet", "awg_pbr", set, elem, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return status == 0 ? 0 : -1;
}

static void install_entry(const struct entry *e, time_t now, unsigned force_timeout) {
	unsigned seconds = force_timeout;
	if (!seconds) {
		if (e->exp <= (int64_t)now)
			return;
		seconds = (unsigned)(e->exp - (int64_t)now);
	}
	if (nft_add(e->af, e->ip, seconds) != 0)
		fprintf(stderr, "[snoop] nft add %s failed\n", e->ip);
}

static void touch(int af, const char *ip, const char *name, int count_it) {
	time_t now = time(NULL);
	struct entry scratch;
	remember(af, ip, name, (int64_t)now + (int64_t)timeout_sec);
	scratch.af = af;
	scratch.exp = (int64_t)now + (int64_t)timeout_sec;
	snprintf(scratch.ip, sizeof scratch.ip, "%s", ip);
	snprintf(scratch.name, NAME_LEN, "%s", name);
	install_entry(&scratch, now, timeout_sec);
	if (!count_it)
		return;
	matches++;
	if (count_path[0]) {
		FILE *f = fopen(count_path, "w");
		if (f) {
			fprintf(f, "%llu\n", (unsigned long long)matches);
			fclose(f);
		}
	}
}

static int save_state(void) {
	char tmp[540];
	FILE *f;
	int i, first = 1;
	time_t now;
	if (!state_path[0])
		return 0;
	snprintf(tmp, sizeof tmp, "%s.tmp", state_path);
	f = fopen(tmp, "w");
	if (!f) {
		fprintf(stderr, "[snoop] cannot write %s: %s\n", tmp, strerror(errno));
		return -1;
	}
	now = time(NULL);
	fputs("{\"entries\":[", f);
	for (i = 0; i < MAX_ENTRIES; i++) {
		if (!entries[i].used || entries[i].exp <= (int64_t)now)
			continue;
		fprintf(f, "%s{\"ip\":\"%s\",\"name\":\"%s\",\"af\":%d,\"exp\":%lld}",
			first ? "" : ",", entries[i].ip, entries[i].name, entries[i].af,
			(long long)entries[i].exp);
		first = 0;
	}
	fputs("]}\n", f);
	if (fclose(f) != 0) {
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, state_path) != 0) {
		unlink(tmp);
		return -1;
	}
	dirty = 0;
	dirty_at = 0;
	return 0;
}

static void load_state(void) {
	FILE *f;
	char *buf;
	long sz;
	const char *p;
	time_t now = time(NULL);
	if (!state_path[0])
		return;
	f = fopen(state_path, "r");
	if (!f)
		return;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return;
	}
	sz = ftell(f);
	if (sz < 0 || sz > 2 * 1024 * 1024) {
		fclose(f);
		return;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return;
	}
	buf[sz] = 0;
	fclose(f);
	p = buf;
	while ((p = strstr(p, "{\"ip\":\"")) != NULL) {
		char ip[64], name[NAME_LEN];
		int af = 0;
		long long exp = 0;
		if (sscanf(p, "{\"ip\":\"%63[^\"]\",\"name\":\"%255[^\"]\",\"af\":%d,\"exp\":%lld",
			   ip, name, &af, &exp) == 4 &&
		    exp > (long long)now && (af == 4 || af == 6)) {
			int slot;
			remember(af, ip, name, (int64_t)exp);
			for (slot = 0; slot < MAX_ENTRIES; slot++) {
				if (entries[slot].used && entries[slot].af == af &&
				    strcmp(entries[slot].ip, ip) == 0) {
					install_entry(&entries[slot], now, 0);
					break;
				}
			}
		}
		p += 6;
	}
	free(buf);
	/* restore must not look like a fresh sighting */
	dirty = 0;
	dirty_at = 0;
	fprintf(stderr, "[snoop] restored cache from %s\n", state_path);
}

static void warmup(void) {
	int i;
	for (i = 0; i < ndomains && !stop_flag; i++) {
		struct addrinfo hints, *res = NULL, *ai;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = 0;
		if (getaddrinfo(domains[i], NULL, &hints, &res) != 0)
			continue;
		for (ai = res; ai; ai = ai->ai_next) {
			char ip[64];
			if (ai->ai_family == AF_INET) {
				inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof ip);
				touch(4, ip, domains[i], 0);
			} else if (ai->ai_family == AF_INET6) {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, ip, sizeof ip);
				touch(6, ip, domains[i], 0);
			}
		}
		freeaddrinfo(res);
		fprintf(stderr, "[snoop] warmup %s\n", domains[i]);
	}
}

struct cname_pair {
	char from[NAME_LEN];
	char to[NAME_LEN];
};
struct addr_rec {
	char owner[NAME_LEN];
	char ip[64];
	int af;
};

static int in_list(char list[][NAME_LEN], int n, const char *name) {
	int i;
	for (i = 0; i < n; i++)
		if (strcmp(list[i], name) == 0)
			return 1;
	return 0;
}

static void consider(const uint8_t *dns, size_t len) {
	size_t off = 12;
	uint16_t qd, an, ns, ar, i;
	char qname[NAME_LEN];
	char chain[MAX_CHAIN][NAME_LEN];
	int cn = 0, cc = 0, na = 0, interesting = 0, depth;
	struct cname_pair cnames[MAX_CNAMES];
	struct addr_rec addrs[MAX_ADDRS];
	if (len < 12)
		return;
	if ((dns[2] & 0x80) == 0)
		return;
	qd = (uint16_t)((dns[4] << 8) | dns[5]);
	an = (uint16_t)((dns[6] << 8) | dns[7]);
	ns = (uint16_t)((dns[8] << 8) | dns[9]);
	ar = (uint16_t)((dns[10] << 8) | dns[11]);
	if (qd < 1)
		return;
	if (parse_name(dns, len, &off, qname, sizeof qname) != 0)
		return;
	lower_copy(qname);
	off += 4;
	if (off > len)
		return;
	for (i = 1; i < qd; i++) {
		char skip[NAME_LEN];
		if (parse_name(dns, len, &off, skip, sizeof skip) != 0)
			return;
		off += 4;
		if (off > len)
			return;
	}
	for (i = 0; i < (uint32_t)an + ns + ar; i++) {
		char owner[NAME_LEN];
		uint16_t typ, class, rdlen;
		uint32_t ttl;
		size_t rdata;
		if (parse_name(dns, len, &off, owner, sizeof owner) != 0)
			return;
		if (off + 10 > len)
			return;
		typ = (uint16_t)((dns[off] << 8) | dns[off + 1]);
		class = (uint16_t)((dns[off + 2] << 8) | dns[off + 3]);
		ttl = ((uint32_t)dns[off + 4] << 24) | ((uint32_t)dns[off + 5] << 16) |
		      ((uint32_t)dns[off + 6] << 8) | dns[off + 7];
		rdlen = (uint16_t)((dns[off + 8] << 8) | dns[off + 9]);
		(void)class;
		(void)ttl;
		off += 10;
		if (off + rdlen > len)
			return;
		rdata = off;
		lower_copy(owner);
		if (i < an && typ == 5 && cc < MAX_CNAMES) {
			size_t noff = rdata;
			if (parse_name(dns, len, &noff, cnames[cc].to, NAME_LEN) == 0) {
				lower_copy(cnames[cc].to);
				snprintf(cnames[cc].from, NAME_LEN, "%s", owner);
				cc++;
			}
		} else if (i < an && typ == 1 && rdlen == 4 && na < MAX_ADDRS) {
			inet_ntop(AF_INET, dns + rdata, addrs[na].ip, sizeof addrs[na].ip);
			snprintf(addrs[na].owner, NAME_LEN, "%s", owner);
			addrs[na].af = 4;
			na++;
		} else if (i < an && typ == 28 && rdlen == 16 && na < MAX_ADDRS) {
			inet_ntop(AF_INET6, dns + rdata, addrs[na].ip, sizeof addrs[na].ip);
			snprintf(addrs[na].owner, NAME_LEN, "%s", owner);
			addrs[na].af = 6;
			na++;
		}
		off += rdlen;
	}
	snprintf(chain[0], NAME_LEN, "%s", qname);
	cn = 1;
	for (depth = 0; depth < MAX_CHAIN - 1; depth++) {
		int c;
		for (c = 0; c < cc; c++) {
			if (strcmp(cnames[c].from, chain[cn - 1]) == 0 &&
			    !in_list(chain, cn, cnames[c].to)) {
				snprintf(chain[cn], NAME_LEN, "%s", cnames[c].to);
				cn++;
				break;
			}
		}
	}
	for (i = 0; i < (uint16_t)cn; i++) {
		if (name_listed(chain[i])) {
			interesting = 1;
			break;
		}
	}
	if (!interesting)
		return;
	for (i = 0; i < (uint16_t)na; i++) {
		if (!in_list(chain, cn, addrs[i].owner))
			continue;
		touch(addrs[i].af, addrs[i].ip, addrs[i].owner, 1);
		fprintf(stderr, "[snoop] %s -> %s\n", addrs[i].owner, addrs[i].ip);
	}
}

static void parse_l4(const uint8_t *p, size_t len, int proto) {
	if (proto == IPPROTO_UDP) {
		if (len < 8)
			return;
		if (((p[0] << 8) | p[1]) != 53)
			return;
		consider(p + 8, len - 8);
	} else if (proto == IPPROTO_TCP) {
		size_t hlen, off;
		if (len < 20)
			return;
		if (((p[0] << 8) | p[1]) != 53)
			return;
		hlen = (size_t)((p[12] >> 4) * 4);
		if (hlen < 20 || hlen > len)
			return;
		off = hlen;
		while (off + 2 <= len) {
			size_t mlen = (size_t)((p[off] << 8) | p[off + 1]);
			if (mlen < 12 || off + 2 + mlen > len)
				break;
			consider(p + off + 2, mlen);
			off += 2 + mlen;
		}
	}
}

static void parse_packet(const uint8_t *p, size_t len, int family) {
	if (family == AF_INET) {
		size_t hlen;
		if (len < 20 || (p[0] >> 4) != 4)
			return;
		hlen = (size_t)((p[0] & 0x0f) * 4);
		if (hlen < 20 || hlen > len)
			return;
		if ((p[6] & 0x1f) || p[7])
			return;
		parse_l4(p + hlen, len - hlen, p[9]);
	} else if (family == AF_INET6) {
		size_t off = 40;
		int nh;
		if (len < 40 || (p[0] >> 4) != 6)
			return;
		nh = p[6];
		while (nh == 0 || nh == 43 || nh == 60 || nh == 51) {
			size_t ext;
			if (off + 2 > len)
				return;
			ext = (size_t)(p[off + 1] + 1) * 8;
			if (nh == 51)
				ext = 8;
			nh = p[off];
			off += ext;
			if (off > len)
				return;
		}
		if (nh == 44)
			return;
		parse_l4(p + off, len - off, nh);
	}
}

static void on_frame(const uint8_t *bytes, size_t len, int dlt) {
	size_t off = 0;
	if (dlt == DLT_LINUX_SLL)
		off = 16;
	else if (dlt == DLT_LINUX_SLL2)
		off = 20;
	else if (dlt == DLT_EN10MB)
		off = 14;
	else if (dlt == DLT_RAW || dlt == DLT_IPV4 || dlt == DLT_IPV6)
		off = 0;
	else
		return;
	if (off >= len)
		return;
	if ((bytes[off] >> 4) == 4)
		parse_packet(bytes + off, len - off, AF_INET);
	else if ((bytes[off] >> 4) == 6)
		parse_packet(bytes + off, len - off, AF_INET6);
}

static void maybe_save(int force) {
	time_t now = time(NULL);
	if (!dirty)
		return;
	if (!force && dirty_at && now - dirty_at < 1)
		return;
	save_state();
}

static int usage(void) {
	fprintf(stderr,
		"usage: dns-snoop --domains FILE --state FILE --count FILE [--timeout SEC] [--warmup]\n");
	return 2;
}

int main(int argc, char **argv) {
	const char *domains_path = NULL;
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	struct bpf_program fp;
	int dlt, fd;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--domains") == 0 && i + 1 < argc)
			domains_path = argv[++i];
		else if (strcmp(argv[i], "--state") == 0 && i + 1 < argc)
			snprintf(state_path, sizeof state_path, "%s", argv[++i]);
		else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc)
			snprintf(count_path, sizeof count_path, "%s", argv[++i]);
		else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
			timeout_sec = (unsigned)atoi(argv[++i]);
		else if (strcmp(argv[i], "--warmup") == 0)
			do_warmup = 1;
		else
			return usage();
	}
	if (!domains_path || !state_path[0] || timeout_sec == 0)
		return usage();
	if (load_domains(domains_path) != 0)
		return 1;
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	load_state();
	if (do_warmup)
		warmup();
	maybe_save(1);
	pcap = pcap_create("any", errbuf);
	if (!pcap) {
		fprintf(stderr, "[snoop] pcap_create: %s\n", errbuf);
		return 1;
	}
	pcap_set_snaplen(pcap, 2048);
	pcap_set_promisc(pcap, 0);
	pcap_set_timeout(pcap, 500);
	pcap_set_immediate_mode(pcap, 1);
	if (pcap_activate(pcap) != 0) {
		fprintf(stderr, "[snoop] pcap_activate: %s\n", pcap_geterr(pcap));
		return 1;
	}
	if (pcap_compile(pcap, &fp, "udp src port 53 or tcp src port 53", 1, PCAP_NETMASK_UNKNOWN) != 0 ||
	    pcap_setfilter(pcap, &fp) != 0) {
		fprintf(stderr, "[snoop] pcap filter: %s\n", pcap_geterr(pcap));
		return 1;
	}
	pcap_freecode(&fp);
	dlt = pcap_datalink(pcap);
	fd = pcap_get_selectable_fd(pcap);
	fprintf(stderr, "[snoop] watching DNS responses, %d names\n", ndomains);
	while (!stop_flag) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		struct pcap_pkthdr *hdr = NULL;
		const u_char *bytes = NULL;
		int pr = fd >= 0 ? poll(&pfd, 1, 500) : 0;
		if (pr > 0 || fd < 0) {
			int n = pcap_next_ex(pcap, &hdr, &bytes);
			if (n == 1 && hdr && bytes)
				on_frame(bytes, hdr->caplen, dlt);
		}
		maybe_save(0);
	}
	save_state();
	pcap_close(pcap);
	fprintf(stderr, "[snoop] stopped, cache saved\n");
	return stop_flag ? 143 : 0;
}
