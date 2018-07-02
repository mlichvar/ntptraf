/*
 * Copyright (C) 2016  Miroslav Lichvar <mlichvar0@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <pcap.h>

#define TRAF_SIZE 64
#define TRAF_WINDOWS 2

struct traf_bin {
	uint16_t server;
	uint16_t client;
	uint16_t ip6_client;
	uint16_t sntp_client;
	uint16_t v4_client;
	uint16_t hash;
};

struct traf {
	struct traf_bin bins[TRAF_SIZE * TRAF_WINDOWS];
	unsigned int interval;
	time_t last_ts;
	struct bpf_program filter;
	int offline;
	int datalink;
};

void process_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	uint32_t i, idx, len, hash;
	const u_char *addr;
	struct traf *traf = (struct traf *)user;
	struct timeval tv;
	int ipv6;

	tv.tv_sec = hdr->ts.tv_sec / traf->interval;
	tv.tv_usec = ((hdr->ts.tv_sec - tv.tv_sec * traf->interval) * 1000000
			+ hdr->ts.tv_usec) / traf->interval;

	traf->last_ts = tv.tv_sec;

	if (traf->offline && !pcap_offline_filter(&traf->filter, hdr, pkt))
		return;

	assert(1000000U % TRAF_SIZE == 0);
	idx = (tv.tv_sec % TRAF_WINDOWS * TRAF_SIZE) +
		tv.tv_usec / (1000000U / TRAF_SIZE);
	assert(idx < TRAF_WINDOWS * TRAF_SIZE);

	len = hdr->caplen;

#if 0
	printf("%9ld.%06ld: [%d] caplen: %d len: %d\n", hdr->ts.tv_sec,
			hdr->ts.tv_usec, idx, hdr->caplen, hdr->len);
#endif

	switch (traf->datalink) {
		case DLT_EN10MB:
			/* Check ethertype for IPv4 or IPv6 */
			if (!(pkt[12] == 0x08 && pkt[13] == 0x00) &&
					!(pkt[12] == 0x86 && pkt[13] == 0xdd))
				return;

			/* Skip ethernet header */
			if (len < 14)
				return;
			pkt += 14, len -= 14;

			break;
		case DLT_RAW:
			break;
		default:
			fprintf(stderr, "Unsupported datalink %s\n",
					pcap_datalink_val_to_name(traf->datalink));
			exit(4);
	}

	/* Check IP header */

	if (len < 20)
		return;

	switch (pkt[0] >> 4) {
		case 4:
			/* IPv4 */
			ipv6 = 0;
			addr = &pkt[12];

			/* Check if contains UDP */
			if (pkt[9] != 17)
				return;

			/* Skip IP header */
			i = (pkt[0] & 0xf) * 4;
			if (len < i)
				return;
			pkt += i, len -= i;

			break;

		case 6:
			/* IPv6 */
			ipv6 = 1;
			addr = &pkt[8];

			/* Check if contains UDP */
			if (pkt[6] != 17)
				return;

			/* Skip IP header */
			if (len < 40)
				return;
			pkt += 40, len -= 40;

			break;

		default:
			return;
	}

	/* Check UDP port */
	if (len < 8 || !((pkt[0] == 0 && pkt[1] == 123) || (pkt[2] == 0 && pkt[3] == 123)))
		return;

	/* Skip UDP header */
	pkt += 8, len -= 8;

	/* Check NTP header */

	if (len < 48)
		return;

	switch (pkt[0] & 0x7) {
		case 0:
			if ((pkt[0] & 0x3f) != 0x8)
				return;
			/* Fall through */
		case 3:
			traf->bins[idx].client++;
			break;
		case 4:
			traf->bins[idx].server++;
			return;
		default:
			return;
	}

	if (ipv6)
		traf->bins[idx].ip6_client++;

	if (((uint64_t *)pkt)[4] == 0)
		traf->bins[idx].sntp_client++;

	if (((pkt[0] >> 3) & 0x7) == 4)
		traf->bins[idx].v4_client++;

	if (traf->bins[idx].client == 1) {
		for (i = hash = 0; i < (ipv6 ? 16 : 4); i++)
			hash = hash * 83 + addr[i];
		traf->bins[idx].hash = hash;
	}
}

void reset_color(void) {
	/* op */
	printf("%s", "\033\133\063\071\073\064\071\155");
}

void set_color_intensity(int i) {
	const char af[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	const char ab[10] = {0, 4, 5, 1, 9, 2, 3, 11, 7, 7};

	if (i < 0)
		i = 0;
	else if (i > 9)
		i = 9;

	/* setaf */
	printf("%s%d%s", "\033\133\063\070\073\065\073", af[i], "\155");
	/* setab */
	printf("%s%d%s", "\033\133\064\070\073\065\073", ab[i], "\155");
}

void print_traf(struct traf *traf, time_t ts) {
	uint32_t i, j, idx, x;
        int xlog;
	struct traf_bin sum;

	memset(&sum, 0, sizeof sum);
	j = ts % TRAF_WINDOWS * TRAF_SIZE;

	printf("\r");

	for (i = 0; i < TRAF_SIZE; i++) {
		idx = i + j;
		assert(idx < TRAF_WINDOWS * TRAF_SIZE);

		sum.server += traf->bins[idx].server;
		sum.client += traf->bins[idx].client;
		sum.ip6_client += traf->bins[idx].ip6_client;
		sum.sntp_client += traf->bins[idx].sntp_client;
		sum.v4_client += traf->bins[idx].v4_client;

		x = traf->bins[idx].client;
		for (xlog = -1; x; xlog++)
			x >>= 1;
		set_color_intensity(xlog + 1);

		if (xlog > 9)
			xlog = 9;
		if (xlog < 0)
			putchar(' ');
		else if (xlog == 0)
			putchar((traf->bins[idx].sntp_client ? 'a' : 'A') +
					traf->bins[idx].hash % 26);
		else
			putchar('0' + xlog);
	}

	reset_color();

	printf("|  %6.1f req/s\n", (double)sum.client / traf->interval);

	if (!sum.client)
		sum.client++;
	printf("IPv6: %3.0f%%   SNTP: %3.0f%%   v4: %3.0f%%   Response: %3.0f%%     Scale:%5.1f * 2^x req/s",
			100.0 * (double)sum.ip6_client / sum.client,
			100.0 * (double)sum.sntp_client / sum.client,
			100.0 * (double)sum.v4_client / sum.client,
			100.0 * (double)sum.server / sum.client,
			(double)TRAF_SIZE / traf->interval);

	fflush(stdout);
}

void print_help(void) {
	fprintf(stderr, "Usage: ntptraf [-b <bufsize>] [-i <iface>] [-f <filter>] [-t <interval>]\n");
}

int main(int argc, char **argv) {
	char ebuf[PCAP_ERRBUF_SIZE], *iface = "eth0", *filter = "port 123";
	struct traf traf;
	time_t ts, last_ts = 0;
	pcap_t *p;
	int s, opt, bufsize = 256;

	memset(&traf, 0, sizeof traf);
	traf.interval = 1;

	while ((opt = getopt(argc, argv, "b:i:f:t:")) != -1) {
		switch (opt) {
			case 'b':
				bufsize = atoi(optarg);
				break;
			case 'i':
				iface = optarg;
				break;
			case 'f':
				filter = optarg;
				break;
			case 't':
				traf.interval = atoi(optarg);
				break;
			default:
				print_help();
				return 1;
		}
	}

	if (optind < argc || traf.interval <= 0) {
		print_help();
		return 1;
	}

	traf.offline = !strcmp(iface, "-");

	if (!traf.offline) {
		if (!(p = pcap_create(iface, ebuf))) {
			fprintf(stderr, "%s\n", ebuf);
			return 2;
		}

		if (
				pcap_set_promisc(p, 1) ||
				pcap_set_timeout(p, 100) ||
				pcap_set_buffer_size(p, bufsize * 1024) ||
				pcap_set_snaplen(p, 128) ||
				pcap_activate(p) ||
				pcap_compile(p, &traf.filter, filter, 1, PCAP_NETMASK_UNKNOWN) ||
				pcap_setfilter(p, &traf.filter)) {
			pcap_perror(p, "");
			return 3;
		}
	} else {
		if (!(p = pcap_open_offline("-", ebuf))) {
			fprintf(stderr, "%s\n", ebuf);
			return 2;
		}

		if (pcap_compile(p, &traf.filter, filter, 1, PCAP_NETMASK_UNKNOWN)) {
			pcap_perror(p, "");
			return 3;
		}
	}

	traf.datalink = pcap_datalink(p);

	while (1) {
		s = pcap_dispatch(p, 1, process_packet, (u_char *)&traf);
		if (s == -1 || (!s && traf.offline))
			break;

		if (!traf.offline)
			ts = time(NULL) / traf.interval;
		else
			ts = traf.last_ts;

		if (!last_ts || last_ts >= ts) {
			last_ts = ts;
			continue;
		}

		print_traf(&traf, last_ts);
		memset(traf.bins + last_ts % TRAF_WINDOWS * TRAF_SIZE, 0,
				TRAF_SIZE * sizeof (struct traf_bin));
		last_ts++;

		while (last_ts < ts) {
			last_ts++;
			printf("\r%*s|%*s\n", TRAF_SIZE, "", 15, "");
		}
	}

	printf("\n");

	pcap_freecode(&traf.filter);
	pcap_close(p);

	return 0;
}
