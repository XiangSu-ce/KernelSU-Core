/*
 * boot_sanitize.c - Kernel ring buffer scrubbing for KernelSU
 *
 * Erases KSU-related messages from the printk ring buffer after module
 * initialization completes. This eliminates the timing window where
 * module loading messages are visible in dmesg before klog_sanitize
 * can filter them at read time.
 *
 * Supports two ring buffer architectures:
 * - Legacy (kernel < 5.10): linear log_buf with struct printk_log records
 * - Modern (kernel >= 5.10): struct printk_ringbuffer (prb)
 *
 * Also called after stealth-loading third-party modules to scrub their
 * loading traces.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "klog.h" // IWYU pragma: keep

/* ---- Symbol resolution (same two-step kprobe trick) ---- */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static kallsyms_lookup_name_t kln_func;

static bool resolve_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (kln_func)
		return true; /* Already resolved */

	if (register_kprobe(&kp) < 0)
		return false;
	kln_func = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return kln_func != NULL;
}

static unsigned long lookup_name(const char *name)
{
	return kln_func ? kln_func(name) : 0;
}

/* ---- Keywords to scrub ---- */

static const char *scrub_keywords[] = {
	/* KSU core identifiers */
	"KernelSU",
	"kernelsu",
	"ksu_",
	"ksu:",
	"[ksu",
	"ksud",
	"KERNEL_SU",
	/* Feature module logs */
	"prop_spoof",
	"proc_hide",
	"debug_disable",
	"symbol_hide",
	"mount_sanitize",
	"klog_sanitize",
	"boot_sanitize",
	"stealth_mod",
	"stealth_exec",
	"stealth_fileio",
	"stealth_ipc",
	/* Hook-related logs */
	"hook_manager",
	"throne_tracker",
	"su_compat",
	"sucompat",
	/* Module loading traces */
	"insmod",
	"init_module",
	"finit_module",
	/* kprobe registration traces */
	"kprobe",
	"kretprobe",
	/* Specific hook target symbols (may appear in failed registration msgs) */
	"__arm64_sys_read",
	"__arm64_sys_reboot",
	"__arm64_sys_getdents64",
	"__x64_sys_read",
	"__x64_sys_reboot",
	"__x64_sys_getdents64",
	"wake_up_new_task",
	"fsnotify",
	NULL
};

static bool line_contains_keyword(const char *text, size_t len)
{
	const char **kw;

	for (kw = scrub_keywords; *kw; kw++) {
		if (strnstr(text, *kw, len))
			return true;
	}
	return false;
}

/* ---- Additional dynamic keywords from stealth module registry ---- */

#include "stealth.h"

static bool line_contains_stealth_keyword(const char *text, size_t len)
{
	const char **prefixes = ksu_get_stealth_symbol_prefixes();
	const char **p;

	if (!prefixes)
		return false;

	for (p = prefixes; *p; p++) {
		if (strnstr(text, *p, len))
			return true;
	}
	return false;
}

static bool should_scrub_line(const char *text, size_t len)
{
	if (!text || len == 0)
		return false;
	return line_contains_keyword(text, len) ||
	       line_contains_stealth_keyword(text, len);
}

/* ---- Legacy ring buffer scrubbing (kernel < 5.10) ---- */

/*
 * struct printk_log (kernel < 5.10):
 * The ring buffer is a linear array of variable-length records.
 * Each record has: u64 ts_nsec, u16 len, u16 text_len, u16 dict_len, u8 facility, u8 flags
 * followed by text[] and dict[].
 *
 * We can't include the internal header, so we define the struct ourselves.
 */
struct legacy_printk_log {
	u64 ts_nsec;
	u16 len;		/* total record length (including padding) */
	u16 text_len;		/* text body length */
	u16 dict_len;		/* dictionary length */
	u8 facility;
	u8 flags:5;
	u8 level:3;
};

static void scrub_legacy_ringbuf(void)
{
	char **p_log_buf;
	u32 *p_log_buf_len;
	u32 *p_log_first_idx, *p_log_next_idx;
	char *log_buf;
	u32 log_buf_len, idx, next_idx;
	unsigned long addr;

	addr = lookup_name("log_buf");
	if (!addr)
		return;
	p_log_buf = (char **)addr;
	log_buf = *p_log_buf;
	if (!log_buf)
		return;

	addr = lookup_name("log_buf_len");
	if (!addr)
		return;
	p_log_buf_len = (u32 *)addr;
	log_buf_len = *p_log_buf_len;

	addr = lookup_name("log_first_idx");
	if (!addr)
		return;
	p_log_first_idx = (u32 *)addr;

	addr = lookup_name("log_next_idx");
	if (!addr)
		return;
	p_log_next_idx = (u32 *)addr;

	idx = *p_log_first_idx;
	next_idx = *p_log_next_idx;

	/*
	 * Walk through records from first to next.
	 * For each record, check if the text body matches any keyword.
	 * If so, overwrite the text body with spaces.
	 */
	while (idx != next_idx) {
		struct legacy_printk_log *msg;
		char *text;
		u16 text_len;

		if (idx + sizeof(*msg) > log_buf_len)
			break;

		msg = (struct legacy_printk_log *)(log_buf + idx);

		/* Zero-length record means wrap to beginning */
		if (msg->len == 0) {
			idx = 0;
			continue;
		}

		text = (char *)(msg + 1);
		text_len = msg->text_len;

		/* Bounds check */
		if (idx + sizeof(*msg) + text_len > log_buf_len)
			break;

		if (should_scrub_line(text, text_len))
			memset(text, ' ', text_len);

		idx += msg->len;
		if (idx >= log_buf_len)
			idx = 0;
	}
}

/* ---- Modern ring buffer scrubbing (kernel >= 5.10) ---- */

/*
 * kernel >= 5.10 uses struct printk_ringbuffer with descriptor rings.
 * We access it through the exported 'prb' pointer (printk_ringbuffer *).
 *
 * The internal structures are complex, so we use a simpler approach:
 * resolve the 'printk_rb_static' or 'prb' symbol and walk the data
 * ring buffer directly, looking for text content to scrub.
 *
 * Since the data ring is a contiguous character buffer, we can scan
 * it linearly for keyword matches and overwrite them.
 */

static void scrub_modern_ringbuf(void)
{
	unsigned long addr;
	void *prb_ptr;
	char *text_data;
	unsigned long text_data_ring_size;
	size_t i, len;

	/*
	 * Try to resolve the printk ring buffer.
	 * In kernel >= 5.10, the global is 'prb' (pointer to printk_ringbuffer).
	 * The text data ring is at prb->text_data_ring.data with size
	 * prb->text_data_ring.size_bits (actual size = 1 << size_bits).
	 *
	 * Since we can't include the internal header, we use a direct
	 * memory scan approach on the text data buffer.
	 */
	addr = lookup_name("prb");
	if (!addr)
		return;
	prb_ptr = *(void **)addr;
	if (!prb_ptr)
		return;

	/*
	 * The printk_ringbuffer struct layout (kernel 5.10+):
	 *   struct printk_ringbuffer {
	 *       struct prb_desc_ring desc_ring;    // descriptor ring
	 *       struct prb_data_ring text_data_ring; // text data ring
	 *       ...
	 *   };
	 *
	 * struct prb_data_ring {
	 *       unsigned int size_bits;
	 *       char *data;
	 *       atomic_long_t head_lpos;
	 *       atomic_long_t tail_lpos;
	 * };
	 *
	 * We resolve the text data buffer address and size by looking up
	 * a known helper or by offsetting from prb.
	 *
	 * Alternative approach: just scan the log_buf memory directly,
	 * which is the backing store for the text data ring in most
	 * kernel configurations.
	 */
	addr = lookup_name("log_buf");
	if (!addr)
		return;
	text_data = *(char **)addr;
	if (!text_data)
		return;

	addr = lookup_name("log_buf_len");
	if (!addr)
		return;
	text_data_ring_size = *(u32 *)addr;

	/*
	 * Scan the text data buffer for keyword matches.
	 * The text data ring contains null-terminated strings packed
	 * sequentially. We scan for lines (null or newline delimited)
	 * and scrub matches.
	 */
	i = 0;
	while (i < text_data_ring_size) {
		char *start = text_data + i;
		char *end;

		/* Find end of this text block (null-terminated) */
		end = memchr(start, '\0', text_data_ring_size - i);
		if (!end) {
			len = text_data_ring_size - i;
			if (should_scrub_line(start, len))
				memset(start, ' ', len);
			break;
		}

		len = end - start;
		if (len > 0 && should_scrub_line(start, len))
			memset(start, ' ', len);

		i += len + 1;
	}
}

/* ---- Public API ---- */

/**
 * ksu_boot_sanitize_scrub() - Scrub KSU-related messages from ring buffer.
 *
 * Should be called:
 * 1. At the end of kernelsu_init() after symbol_hide_init()
 * 2. After stealth-loading any third-party module
 *
 * Safe to call multiple times.
 */
void ksu_boot_sanitize_scrub(void)
{
	/* Ensure symbol resolution is available (self-resolving) */
	if (!resolve_kln())
		return; /* Cannot scrub without kallsyms — silent fail */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	scrub_modern_ringbuf();
#else
	scrub_legacy_ringbuf();
#endif
}

void ksu_boot_sanitize_init(void)
{
	/* Pre-resolve kln for later scrub calls.
	 * No logging here — we're about to scrub the ring buffer. */
	resolve_kln();
}

void ksu_boot_sanitize_exit(void)
{
	/* Nothing to clean up */
}
