/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *      The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2007-2008,2010
 *      Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * Copyright (c) 2010-2011 Juniper Networks, Inc.
 * Copyright (c) 2019 Richard Scheffenegger <srichard@netapp.com>
 * All rights reserved.
 *
 * Portions of this software were developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart,
 * James Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Portions of this software were developed by Robert N. M. Watson under
 * contract to Juniper Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tcp_ecn.c 8.12 (Berkeley) 5/24/95
 */

/*
 * Utility functions to deal with Explicit Congestion Notification in TCP
 * implementing the essential parts of the Accurate ECN extension
 * https://tools.ietf.org/html/draft-ietf-tcpm-accurate-ecn-09
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_tcpdebug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <machine/cpu.h>

#include <vm/uma.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet6/tcp6_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_ecn.h>

/*
 * Process a <SYN> packets ECN information, and provide the
 * syncache with the relevant information.
 */
int
tcp_ecn_syncache_add(struct tcphdr *th, int tos)
{
	int xflags, scflags = 0;

	xflags = ((th->th_x2 << 8) | th->th_flags) & (TH_AE|TH_CWR|TH_ECE);
	switch (xflags) {
	/* no ECN */
	case (0|0|0):
		break;
	/* legacy ECN */
	case (0|TH_CWR|TH_ECE):
		scflags = SCF_ECN;
		break;
	/* Accurate ECN */
	case (TH_AE|TH_CWR|TH_ECE):
		if ((V_tcp_do_ecn == 3) ||
		    (V_tcp_do_ecn == 4)) {
			switch (tos & IPTOS_ECN_MASK) {
			case IPTOS_ECN_CE:
				scflags = SCF_ACE_CE;
				break;
			case IPTOS_ECN_ECT0:
				scflags = SCF_ACE_0;
				break;
			case IPTOS_ECN_ECT1:
				scflags = SCF_ACE_1;
				break;
			case IPTOS_ECN_NOTECT:
				scflags = SCF_ACE_N;
				break;
			}
		} else
			scflags |= SCF_ECN;
		break;
	/* Default Case (section 3.1.2) */
	default:
		if ((V_tcp_do_ecn == 3) ||
		    (V_tcp_do_ecn == 4)) {
			switch (tos & IPTOS_ECN_MASK) {
			case IPTOS_ECN_CE:
				scflags = SCF_ACE_CE;
				break;
			case IPTOS_ECN_ECT0:
				scflags = SCF_ACE_0;
				break;
			case IPTOS_ECN_ECT1:
				scflags = SCF_ACE_1;
				break;
			case IPTOS_ECN_NOTECT:
				scflags = SCF_ACE_N;
				break;
			}
		}
		break;
	}
	return scflags;
}

/*
 * Set up the ECN information for the <SYN,ACK> from
 * syncache information.
 */
void
tcp_ecn_syncache_respond(struct tcphdr *th, struct syncache *sc, int flags)
{
	if ((flags & TH_SYN) && 
	    (sc->sc_flags & SCF_ECN_MASK)) {
		switch (sc->sc_flags & SCF_ECN_MASK) {
		case SCF_ECN:
			th->th_flags |= TH_ECE;
			TCPSTAT_INC(tcps_ecn_shs);
			break;
		case SCF_ACE_N:
			th->th_flags |= TH_CWR;
			TCPSTAT_INC(tcps_ecn_shs);
			TCPSTAT_INC(tcps_ace_nect);
			break;
		case SCF_ACE_0:
			th->th_x2    |= (TH_AE >> 8);
			TCPSTAT_INC(tcps_ecn_shs);
			TCPSTAT_INC(tcps_ace_ect0);
			break;
		case SCF_ACE_1:
			th->th_flags |= (TH_ECE | TH_CWR);
			TCPSTAT_INC(tcps_ecn_shs);
			TCPSTAT_INC(tcps_ace_ect1);
			break;
		case SCF_ACE_CE:
			th->th_flags |= TH_CWR;
			th->th_x2    |= (TH_AE >> 8);
			TCPSTAT_INC(tcps_ecn_shs);
			TCPSTAT_INC(tcps_ace_ce);
			break;
		/* undefined SCF codepoint */
		default:
			break;
		}
	}
}

int
tcp_ecn_get_ace(struct tcphdr *th)
{
	int ace = 0;

	if (th->th_flags & TH_ECE)
		ace += 1;
	if (th->th_flags & TH_CWR)
		ace += 2;
	if (th->th_x2 & (TH_AE >> 8))
		ace += 4;
	return ace;
}
