#ifndef __KSU_UTIL_H
#define __KSU_UTIL_H

#include <linux/types.h>

#ifndef preempt_enable_no_resched_notrace
#define preempt_enable_no_resched_notrace()                                    \
    do {                                                                       \
        barrier();                                                             \
        __preempt_count_dec();                                                 \
    } while (0)
#endif

#ifndef preempt_disable_notrace
#define preempt_disable_notrace()                                              \
    do {                                                                       \
        __preempt_count_inc();                                                 \
        barrier();                                                             \
    } while (0)
#endif

bool try_set_access_flag(unsigned long addr);

/* Centralized kallsyms resolution (kprobe trick) */
unsigned long ksu_lookup_name(const char *name);
bool ksu_ensure_kallsyms_lookup(void);

/* Common path helper — check if `path` ends with `/tail` or equals `tail` */
#include <linux/string.h>
static inline bool path_tail_eq(const char *path, const char *tail)
{
	size_t plen, tlen;
	const char *p;

	if (!path || !tail)
		return false;
	plen = strlen(path);
	tlen = strlen(tail);
	if (plen < tlen)
		return false;
	p = path + (plen - tlen);
	if (strcmp(p, tail) != 0)
		return false;
	return p == path || *(p - 1) == '/';
}

#endif
