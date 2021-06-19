/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)gauges.h	8.6 (Berkeley) 2/19/95
 * $FreeBSD$
 */

#ifndef _SYS_GAUGES_H_
#define	_SYS_GAUGES_H_

/* Machine type dependent parameters. */
#include <machine/atomic.h>

#if __BSD_VISIBLE

typedef	uint8_t		gauge8_t;
typedef	uint16_t	gauge16_t;
typedef	uint32_t	gauge32_t;
typedef	uint64_t	gauge64_t;

#endif

/*
 * The following are all things that  provide miscellaneous doodads.
 */

#if __BSD_VISIBLE
/*
 * Programmatically determine the maximum value of
 * a signed or unsigned type, without integer overflow.
 * Determining if the type of a variable is signed
 * or not in a portable way without typeof() is quite
 * involved but the resuting code is still optimal.
 */
#define UTYPE_MAX(x) \
    ((((1 << (sizeof((x)) * 8 - 1)) - 1) * 2) + 1)
#define TYPE_MAX(x) \
    ((((1 << (sizeof((x)) * 8 - 2)) - 1) * 2) + 1)

/*
 * Macro to Post-increment gauges that should NOT
 * overflow, as a drop-in replacement for 'x++'.
 */
#define atomic_ceil_u32(x) \
    do {
      ((x) < UINT32_MAX) ? atomic_cmpset(&(x), (x), (x)++);
    } while (0)
    ((x) < UTYPE_MAX(x)) ? (x)++ : (x)

/*
 * Macro to Pre-increment gauges that should NOT
 * overflow, as a drop-in replacement for '++x'.
 */
#define INCCEIL(x) \
    ((x) < UTYPE_MAX(x)) ? ++(x) : (x)

/*
 * Macro to Post-decrement gauges that should NOT
 * underflow, as a drop-in replacement for 'x--'.
 */
#define FLOORDEC(x) \
    ((x) > 0) ? (x)-- : (x)

/*
 * Macro to Pre-decrement gauges that should NOT
 * underflow, as a drop-in replacement for '--x'.
 */
#define DECFLOOR(x) \
    ((x) > 0) ? --(x) : (x)

/*
 * Macro to increment gauges that should NOT
 * overflow, as a drop-in replacement for 'x+var'.
 */
#define ADDCEIL(x,v) \
    ((x) <= (UTYPE_MAX(x)-(v)) ? (x)+(v) : UTYPE_MAX(x)

/*
 * Macro to decrement gauges that should NOT
 * underflow, as a drop-in replacement for 'x-var'.
 */
#define SUBFLOOR(x,v) \
    ((x) >= (v)) ? (x)-(v) : 0

static inline int
atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
        int c = atomic_read(v);

        for (;;) {
                if (unlikely(c == u))
                        break;
                if (likely(atomic_fcmpset_int(&v->counter, &c, c + a)))
                        break;
        }
        return (c);
}


#endif /* __BSD_VISIBLE */

#endif /* !_SYS_GAUGES_H_ */
