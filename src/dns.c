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
 */

#include "chilli.h"

#define antidnstunnel _options.dnsparanoia

extern struct dhcp_t *dhcp;

enum {
	DNS_MAX_COMPRESSION_DEPTH = 15,
	DNS_ANTI_TUNNEL_MAX_NAME  = 128,
};

/* RFC 1035 RR types referenced in this file */
enum dns_rr_type {
	DNS_RR_A      = 1,
	DNS_RR_NS     = 2,
	DNS_RR_CNAME  = 5,
	DNS_RR_SOA    = 6,
	DNS_RR_PTR    = 12,
	DNS_RR_MX     = 15,
	DNS_RR_TXT    = 16,
	DNS_RR_AAAA   = 28,
	DNS_RR_LOC    = 29,
	DNS_RR_SRV    = 33,
	DNS_RR_OPT    = 41,
	DNS_RR_NSEC   = 47,
	DNS_RR_HTTPS  = 65,
};

#define DNS_COMPRESS_MASK 0xC0U

static void
dns_debug_parse_fail(const char *fn, int line)
{
	if (_options.debug)
		syslog(LOG_DEBUG, "%s(%d): failed parsing DNS packet", fn, line);
}

static int
dns_pull_u16(uint8_t **pp, size_t *lenp, uint16_t *out_host)
{
	uint8_t *p = *pp;
	size_t len = *lenp;
	uint16_t be;

	if (len < 2) {
		return -1;
	}
	memcpy(&be, p, sizeof(be));
	*out_host = ntohs(be);
	*pp = p + 2;
	*lenp = len - 2;
	return 0;
}

static int
dns_pull_u32(uint8_t **pp, size_t *lenp, uint32_t *out_host)
{
	uint8_t *p = *pp;
	size_t len = *lenp;
	uint32_t be;

	if (len < 4) {
		return -1;
	}
	memcpy(&be, p, sizeof(be));
	*out_host = ntohl(be);
	*pp = p + 4;
	*lenp = len - 4;
	return 0;
}

ssize_t
dns_fullname(char *data, size_t dlen,
	     uint8_t *res, size_t reslen,
	     const uint8_t *opkt, size_t olen,
	     int lvl)
{
	int ret = 0;
	char *d = data;
	unsigned char lab;

	if (lvl >= DNS_MAX_COMPRESSION_DEPTH) {
		return -1;
	}

#if(_debug_ > 1)
	if (_options.debug)
		syslog(LOG_DEBUG, "%s(%d): %s dlen=%zu reslen=%zu olen=%zu lvl=%d", __func__, __LINE__,
		       __func__, dlen, reslen, olen, lvl);
#endif

	/* Only capture the first name in query */
	if (d && d[0]) {
		d = NULL;
	}

	while (reslen > 0) {
		reslen--;
		ret++;
		lab = *res++;
		if (lab == 0) {
			break;
		}

		if ((lab & DNS_COMPRESS_MASK) == DNS_COMPRESS_MASK) {
			unsigned offset;

			if (reslen == 0) {
				return -1;
			}
			offset = (unsigned)((lab & ~DNS_COMPRESS_MASK) << 8) + (unsigned)*res;
			ret++;

			if (offset >= olen) {
				if (_options.debug)
					syslog(LOG_DEBUG, "%s(%d): bad value", __func__, __LINE__);
				return -1;
			}

#if(_debug_ > 1)
			if (_options.debug)
				syslog(LOG_DEBUG, "%s(%d): skip[%u] olen=%zu", __func__, __LINE__, offset, olen);
#endif

			if (dns_fullname(d, dlen,
					 (uint8_t *)opkt + offset,
					 olen - offset,
					 opkt, olen, lvl + 1) < 0) {
				return -1;
			}
			break;
		}

		if (lab >= dlen || lab >= olen) {
			if (_options.debug)
				syslog(LOG_DEBUG, "%s(%d): bad value %u/%zu/%zu", __func__, __LINE__,
				       (unsigned)lab, dlen, olen);
			return -1;
		}

#if(_debug_ > 1)
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): part[%.*s] reslen=%zu l=%u dlen=%zu", __func__, __LINE__,
			       (int)lab, (const char *)res, reslen, (unsigned)lab, dlen);
#endif

		if (d) {
			memcpy(d, res, lab);
			d += lab;
			dlen -= lab;
		}
		res += lab;
		reslen -= lab;
		ret += (int)lab;

		if (d) {
			*d = '.';
			d += 1;
			dlen -= 1;
		}
	}

	if (lvl == 0 && d && data) {
		size_t slen = strlen(data);

		if (slen > 0 && slen == (size_t)(d - data) && data[slen - 1] == '.') {
			data[slen - 1] = '\0';
		}
	}

	return ret;
}

int
dns_getname(uint8_t **pktp, size_t *left,
	    const uint8_t *dns0, size_t dnslen,
	    char *name, size_t namesz,
	    size_t *namelen_out)
{
	uint8_t *cur;
	size_t rem;
	ssize_t consumed;

	if (!pktp || !*pktp || !left || !name || namesz == 0 || !namelen_out || !dns0) {
		return -1;
	}

	cur = *pktp;
	rem = *left;
	if (cur < dns0 || cur >= dns0 + dnslen) {
		return -1;
	}

	consumed = dns_fullname(name, namesz - 1U, cur, rem, dns0, dnslen, 0);
	if (consumed < 0) {
		return -1;
	}
	if ((size_t)consumed > rem) {
		return -1;
	}

	name[namesz - 1U] = '\0';
	*pktp = cur + (size_t)consumed;
	*left = rem - (size_t)consumed;
	*namelen_out = (size_t)consumed;
	return 0;
}

static void
add_A_to_garden(uint8_t *p)
{
	struct in_addr reqaddr;
	pass_through pt;

	memcpy(&reqaddr.s_addr, p, 4);
	memset(&pt, 0, sizeof(pass_through));
	pt.mask.s_addr = 0xffffffff;
	pt.host = reqaddr;
	if (pass_through_add(dhcp->pass_throughs,
			     MAX_PASS_THROUGHS,
			     &dhcp->num_pass_throughs,
			     &pt, 1
#ifdef HAVE_PATRICIA
			     , dhcp->ptree_dyn
#endif
			     )) {
		/* ignore */
	}
}

static int
dns_uamdomain_matches(const uint8_t *question)
{
	int id;

	for (id = 0; id < MAX_UAM_DOMAINS && _options.uamdomains[id]; id++) {
		size_t qst_len = strlen((char *)question);
		size_t dom_len = strlen(_options.uamdomains[id]);

#if(_debug_)
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): checking %s [%s]", __func__, __LINE__,
			       _options.uamdomains[id], question);
#endif

		if (qst_len == 0 || dom_len == 0) {
			continue;
		}
		if (qst_len == dom_len && strcmp(_options.uamdomains[id], (char *)question) == 0) {
#if(_debug_)
			if (_options.debug)
				syslog(LOG_DEBUG, "%s(%d): matched %s [%s]", __func__, __LINE__,
				       _options.uamdomains[id], question);
#endif
			return 1;
		}
		if (qst_len > dom_len &&
		    (_options.uamdomains[id][0] == '.' ||
		     question[qst_len - dom_len - 1] == '.') &&
		    strcmp(_options.uamdomains[id], (char *)question + qst_len - dom_len) == 0) {
#if(_debug_)
			if (_options.debug)
				syslog(LOG_DEBUG, "%s(%d): matched %s [%s]", __func__, __LINE__,
				       _options.uamdomains[id], question);
#endif
			return 1;
		}
	}
	return 0;
}

int
dns_copy_res(struct dhcp_conn_t *conn, int q,
	     uint8_t **pktp, size_t *left,
	     uint8_t *opkt, size_t olen,
	     uint8_t *question, size_t qsize,
	     int isReq, int *qmatch, int *modified, int mode)
{
	uint8_t *p_pkt = *pktp;
	size_t len = *left;
	uint8_t name[PKT_IP_PLEN];
	ssize_t namelen;
	int required = 0;
	uint16_t type;
#if(_debug_)
	uint16_t class;
#endif
	uint32_t ttl;
	uint16_t rdlen;
#ifdef ENABLE_IPV6
	uint8_t *pkt_type = NULL;
#endif
	uint8_t *pkt_ttl = NULL;
	uint32_t ul;
	uint16_t us;

	(void)conn;
	(void)mode;

#if(_debug_ > 1)
	if (_options.debug)
		syslog(LOG_DEBUG, "%s(%d): left=%zu olen=%zu qsize=%zu",
		       __func__, __LINE__, *left, olen, qsize);
#endif

	memset(name, 0, sizeof(name));
	namelen = dns_fullname((char *)name, sizeof(name) - 1U,
			       p_pkt, len, opkt, olen, 0);

	if (namelen < 0 || (size_t)namelen > len) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

	p_pkt += (size_t)namelen;
	len -= (size_t)namelen;

	if (antidnstunnel && namelen > DNS_ANTI_TUNNEL_MAX_NAME) {
		syslog(LOG_WARNING, "dropping dns for anti-dnstunnel (namelen: %zd)", namelen);
		return -1;
	}

	if (len < 4) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

#ifdef ENABLE_IPV6
	pkt_type = p_pkt;
#endif
	memcpy(&us, p_pkt, sizeof(us));
	type = ntohs(us);
	p_pkt += 2;
	len -= 2;

	memcpy(&us, p_pkt, sizeof(us));
#if(_debug_)
	class = ntohs(us);
#endif
	p_pkt += 2;
	len -= 2;

#if(_debug_)
	if (_options.debug)
		syslog(LOG_DEBUG, "%s(%d): It was a dns record type: %d class: %d", __func__, __LINE__,
		       (int)type, (int)class);
#endif

	if (q) {
		if (dns_fullname((char *)question, qsize, *pktp, *left, opkt, olen, 0) < 0) {
			dns_debug_parse_fail(__func__, __LINE__);
			return -1;
		}

		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): DNS: %s", __func__, __LINE__, question);

		*pktp = p_pkt;
		*left = len;

		if (!isReq && *qmatch == -1 && _options.uamdomains[0]) {
			if (dns_uamdomain_matches(question)) {
				*qmatch = 1;
			}
		}

#ifdef ENABLE_IPV6
		if (_options.ipv6) {
			if (isReq && type == DNS_RR_AAAA) {
				if (_options.debug)
					syslog(LOG_DEBUG, "%s(%d): changing AAAA to A request", __func__, __LINE__);
				us = htons((uint16_t)DNS_RR_A);
				memcpy(pkt_type, &us, sizeof(us));
				*modified = 1;
			} else if (!isReq && type == DNS_RR_A) {
				if (_options.debug)
					syslog(LOG_DEBUG, "%s(%d): changing A to AAAA response", __func__, __LINE__);
				us = htons((uint16_t)DNS_RR_AAAA);
				memcpy(pkt_type, &us, sizeof(us));
				*modified = 1;
			}
		}
#endif

		return 0;
	}

	if (len < 6) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

	pkt_ttl = p_pkt;
	if (dns_pull_u32(&p_pkt, &len, &ttl) != 0) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

	if (dns_pull_u16(&p_pkt, &len, &rdlen) != 0) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

#if(_debug_ > 1)
	if (_options.debug)
		syslog(LOG_DEBUG, "%s(%d): -> w ttl: %u rdlength: %u/%zu", __func__, __LINE__,
		       ttl, (unsigned)rdlen, len);
#endif

	if (*qmatch == 1 && ttl > (uint32_t)_options.uamdomain_ttl) {
#if(_debug_)
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): Rewriting DNS ttl from %u to %d", __func__, __LINE__,
			       ttl, _options.uamdomain_ttl);
#endif
		ul = htonl((uint32_t)_options.uamdomain_ttl);
		memcpy(pkt_ttl, &ul, sizeof(ul));
		*modified = 1;
	}

	if (len < rdlen) {
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;
	}

	switch ((enum dns_rr_type)type) {
	default:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): Record type %d", __func__, __LINE__, (int)type);
		dns_debug_parse_fail(__func__, __LINE__);
		return -1;

	case DNS_RR_A:
#if(_debug_ > 1)
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): A record", __func__, __LINE__);
#endif
		required = 1;

#ifdef ENABLE_MDNS
		if (mode == DNS_MDNS_MODE) {
			size_t offset;

			for (offset = 0; offset < rdlen; offset += 4) {
				struct in_addr reqaddr;

				memcpy(&reqaddr.s_addr, p_pkt + offset, 4);
#if(_debug_)
				if (_options.debug)
					syslog(LOG_DEBUG, "%s(%d): mDNS %s = %s", __func__, __LINE__,
					       name, inet_ntoa(reqaddr));
#endif
			}
			break;
		}
#endif

		if (*qmatch == 1) {
			size_t offset;

			for (offset = 0; offset < rdlen; offset += 4) {
				add_A_to_garden(p_pkt + offset);
			}
		}
		break;

	case DNS_RR_NS:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): NS record", __func__, __LINE__);
		required = 1;
		break;

	case DNS_RR_CNAME:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): CNAME record %s", __func__, __LINE__, name);
		required = 1;
		break;

	case DNS_RR_SOA:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): SOA record", __func__, __LINE__);
		break;

	case DNS_RR_PTR:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): PTR record", __func__, __LINE__);
		break;

	case DNS_RR_MX:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): MX record", __func__, __LINE__);
		required = 1;
		break;

	case DNS_RR_TXT:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): TXT record %u", __func__, __LINE__, (unsigned)rdlen);
		if (_options.debug) {
			char *txt = (char *)p_pkt;
			int txtlen = (int)rdlen;

			while (txtlen > 0) {
				uint8_t chunk = (uint8_t)*txt++;

				txtlen--;
				if (chunk == 0) {
					break;
				}
				if (_options.debug)
					syslog(LOG_DEBUG, "%s(%d): Text: %.*s", __func__, __LINE__,
					       (int)chunk, txt);
				txt += chunk;
				txtlen -= (int)chunk;
			}
		}
		break;

	case DNS_RR_AAAA:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): AAAA record", __func__, __LINE__);
		required = 1;
		break;

	case DNS_RR_LOC:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): LOC record", __func__, __LINE__);
		break;

	case DNS_RR_SRV:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): SRV record", __func__, __LINE__);
		break;

	case DNS_RR_OPT:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): EDNS OPT pseudorecord", __func__, __LINE__);
		break;

	case DNS_RR_NSEC:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): NSEC record", __func__, __LINE__);
		break;

	case DNS_RR_HTTPS:
		if (_options.debug)
			syslog(LOG_DEBUG, "%s(%d): HTTPS (SVCB) record", __func__, __LINE__);
		break;
	}

	if (antidnstunnel && !required) {
		syslog(LOG_WARNING, "dropping dns for anti-dnstunnel (type %d: length %d)",
		       (int)type, (int)rdlen);
		return -1;
	}

	p_pkt += rdlen;
	len -= rdlen;

	*pktp = p_pkt;
	*left = len;

	return 0;
}
