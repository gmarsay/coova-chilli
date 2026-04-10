/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Petit utilitaire : liste les interfaces IPv4 (ioctl SIOCGIFCONF, Linux).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

static void
die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

static void
die_perror(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

/* Linux renvoie typiquement une entrée par sizeof(struct ifreq) ; les sockaddr
 * à taille variable ne sont pas gérées ici (comportement inchangé vs l’original). */
#define IFSCAN_IFCONF_BYTES(n) ((size_t)(n) * sizeof(struct ifreq))

static int
open_ioctl_socket(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (fd < 0) {
		die("Cannot open socket.");
	}
	return fd;
}

/*
 * Alloue / agrandit le tampon ifconf jusqu’à ce que la réponse tienne
 * (ifc_len < taille tampon).
 */
static void
ifconf_grow_until_fit(int sockfd, struct ifconf *ifc, int *slot_count)
{
	for (;;) {
		struct ifreq *newbuf;
		size_t bytes;

		(*slot_count)++;
		bytes = IFSCAN_IFCONF_BYTES(*slot_count);
		newbuf = realloc(ifc->ifc_req, bytes);
		if (newbuf == NULL) {
			free(ifc->ifc_req);
			ifc->ifc_req = NULL;
			die("Out of memory.");
		}
		ifc->ifc_req = newbuf;
		ifc->ifc_len = (int)bytes;

		if (ioctl(sockfd, SIOCGIFCONF, ifc) != 0) {
			free(ifc->ifc_req);
			ifc->ifc_req = NULL;
			die_perror("ioctl SIOCGIFCONF");
		}

		if (ifc->ifc_len < (int)bytes) {
			break;
		}
	}
}

static void
format_sockaddr(const struct sockaddr *sa, char *s, size_t maxlen)
{
	if (maxlen == 0) {
		return;
	}

	switch (sa->sa_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr,
			      s, maxlen) == NULL) {
			snprintf(s, maxlen, "(inet_ntop AF_INET)");
		}
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr,
			      s, maxlen) == NULL) {
			snprintf(s, maxlen, "(inet_ntop AF_INET6)");
		}
		break;
	default:
		snprintf(s, maxlen, "AF %u", (unsigned)sa->sa_family);
		break;
	}
}

static void
format_ipv4(const struct in_addr *addr, char *s, size_t maxlen)
{
	if (inet_ntop(AF_INET, addr, s, maxlen) == NULL) {
		snprintf(s, maxlen, "(inet_ntop)");
	}
}

static int
ipv4_from_sockaddr(const struct sockaddr *sa, struct in_addr *out)
{
	if (sa->sa_family != AF_INET) {
		return -1;
	}
	memcpy(out, &((const struct sockaddr_in *)sa)->sin_addr, sizeof(*out));
	return 0;
}

static int
ipv4_from_ifr_addr(const struct ifreq *ifr, struct in_addr *out)
{
	return ipv4_from_sockaddr(&ifr->ifr_addr, out);
}

static void
print_hwaddr(const struct ifreq *ifr)
{
	const unsigned char *u = (const unsigned char *)ifr->ifr_hwaddr.sa_data;
	unsigned i;
	unsigned sum = 0;

	switch (ifr->ifr_hwaddr.sa_family) {
	case ARPHRD_NETROM:
	case ARPHRD_ETHER:
	case ARPHRD_PPP:
	case ARPHRD_EETHER:
	case ARPHRD_IEEE802:
		break;
	default:
		return;
	}

	for (i = 0; i < 6; i++) {
		sum += u[i];
	}
	if (sum == 0) {
		return;
	}

	printf("HW Address: %02X-%02X-%02X-%02X-%02X-%02X\n",
	       u[0], u[1], u[2], u[3], u[4], u[5]);
}

static void
print_iface(int sockfd, struct ifreq *ifr)
{
	char ip[INET6_ADDRSTRLEN];
	char addrbuf[INET_ADDRSTRLEN];
	struct in_addr in;
	struct sockaddr sa_copy;

	/* L’union ifreq est réutilisée par les ioctl ; on fige l’adresse de SIOCGIFCONF. */
	memcpy(&sa_copy, &ifr->ifr_addr, sizeof(sa_copy));

	if (ioctl(sockfd, SIOCGIFFLAGS, ifr) != 0) {
		return;
	}

	printf("Interface:  %s\n", ifr->ifr_name);
	format_sockaddr(&sa_copy, ip, sizeof ip);
	printf("IP Address: %s\n", ip);

	if (ipv4_from_sockaddr(&sa_copy, &in) == 0) {
		format_ipv4(&in, addrbuf, sizeof addrbuf);
		printf("IP Address: %s\n", addrbuf);
	}

	if (ioctl(sockfd, SIOCGIFHWADDR, ifr) == 0) {
		print_hwaddr(ifr);
	}

	if (ioctl(sockfd, SIOCGIFNETMASK, ifr) == 0 &&
	    ipv4_from_ifr_addr(ifr, &in) == 0) {
		struct in_addr allones;

		allones.s_addr = htonl(0xffffffffu);
		if (in.s_addr != allones.s_addr) {
			format_ipv4(&in, addrbuf, sizeof addrbuf);
			printf("Netmask:    %s\n", addrbuf);
		}
	}

	if (ifr->ifr_flags & IFF_BROADCAST) {
		if (ioctl(sockfd, SIOCGIFBRDADDR, ifr) == 0 &&
		    ipv4_from_ifr_addr(ifr, &in) == 0 &&
		    in.s_addr != htonl(0)) {
			format_ipv4(&in, addrbuf, sizeof addrbuf);
			printf("Broadcast:  %s\n", addrbuf);
		}
	}

	if (ioctl(sockfd, SIOCGIFMTU, ifr) == 0) {
		printf("MTU:        %u\n", (unsigned)ifr->ifr_mtu);
	}

	if (ioctl(sockfd, SIOCGIFMETRIC, ifr) == 0) {
		printf("Metric:     %u\n", (unsigned)ifr->ifr_metric);
	}

	printf("\n");
}

int
main(void)
{
	int sockfd;
	struct ifconf ifc;
	int nslots = 1;
	struct ifreq *ifr;
	char *end;

	memset(&ifc, 0, sizeof(ifc));
	sockfd = open_ioctl_socket();

	ifc.ifc_len = 0;
	ifc.ifc_req = NULL;
	ifconf_grow_until_fit(sockfd, &ifc, &nslots);

	end = (char *)ifc.ifc_req + ifc.ifc_len;
	for (ifr = ifc.ifc_req; (char *)ifr < end; ++ifr) {
		/* Même test que l’original ; (ifr+1) n’est lu que s’il reste au moins une entrée. */
		if ((char *)(ifr + 1) < end &&
		    ifr->ifr_addr.sa_data == (ifr + 1)->ifr_addr.sa_data) {
			continue;
		}
		print_iface(sockfd, ifr);
	}

	free(ifc.ifc_req);
	close(sockfd);
	return EXIT_SUCCESS;
}
