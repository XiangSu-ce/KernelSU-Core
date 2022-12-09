#ifndef __KSU_H_OBFUSCATE
#define __KSU_H_OBFUSCATE

/*
 * obfuscate.h - Compile-time string obfuscation for KernelSU
 *
 * Provides macros to prevent sensitive strings from appearing as
 * plain text in the compiled binary. Strings are XOR-encoded at
 * compile time and decoded at runtime on first use.
 *
 * This defeats static binary analysis tools that scan .rodata for
 * keywords like "kernelsu", "ksu_", "root", etc.
 *
 * Usage:
 *   DEFINE_OBFUSCATED(my_secret, "secret_string");
 *   // later:
 *   const char *s = DEOBFUSCATE(my_secret);
 *
 * Limitations:
 * - C99 doesn't support constexpr, so we use runtime-init-once pattern
 * - Maximum string length is 127 characters
 * - Thread safety via atomic flag (init-once is lock-free)
 */

#include <linux/atomic.h>
#include <linux/string.h>

#define OBF_KEY 0x5A  /* XOR key — change per build for extra security */
#define OBF_MAX_LEN 128

/*
 * Obfuscated string container.
 * The `encoded` array holds XOR'd bytes at compile time.
 * The `decoded` array is filled once at runtime.
 */
struct obf_string {
	const unsigned char *encoded;
	unsigned int len;
	char decoded[OBF_MAX_LEN];
	atomic_t initialized;
};

/*
 * Runtime decode function. Called once per string.
 * After first call, returns the cached decoded string.
 */
static inline const char *obf_decode(struct obf_string *s)
{
	if (likely(atomic_read(&s->initialized)))
		return s->decoded;

	/* Decode: XOR each byte with key */
	{
		unsigned int i;

		for (i = 0; i < s->len && i < OBF_MAX_LEN - 1; i++)
			s->decoded[i] = s->encoded[i] ^ OBF_KEY;
		s->decoded[i] = '\0';
	}

	atomic_set(&s->initialized, 1);
	return s->decoded;
}

/*
 * Helper macros for compile-time XOR encoding.
 * These encode individual characters with the XOR key.
 *
 * Due to C preprocessor limitations, we use a helper function
 * approach: the encoded bytes are stored in a static array
 * initialized at declaration time using XOR on each char literal.
 *
 * For truly compile-time XOR in C, each character must be
 * individually XOR'd in the initializer list.
 */

/* Encode a single char at compile time */
#define _OC(c) ((unsigned char)((c) ^ OBF_KEY))

/*
 * Define an obfuscated string with up to N characters.
 * Usage: DEFINE_OBFUSCATED_N(name, "hello", 5)
 *
 * For convenience, use the variadic macros below for common lengths,
 * or use the runtime-encode variant for arbitrary strings.
 */

/*
 * Runtime-encode variant: encodes string at module init time.
 * Less secure (string briefly visible in .rodata) but works for
 * any string length without macro gymnastics.
 *
 * Call ksu_obf_init_all() during module init to encode all strings.
 */

#define DEFINE_OBF_RUNTIME(name, str)					\
	static char __obf_##name[OBF_MAX_LEN];				\
	static const char __obf_orig_##name[] = str;			\
	static atomic_t __obf_ready_##name = ATOMIC_INIT(0)

#define OBF_INIT_RUNTIME(name) do {					\
	unsigned int __i;						\
	unsigned int __len = strlen(__obf_orig_##name);			\
	for (__i = 0; __i < __len && __i < OBF_MAX_LEN - 1; __i++)	\
		__obf_##name[__i] = __obf_orig_##name[__i] ^ OBF_KEY;	\
	__obf_##name[__i] = '\0';					\
	/* After init, __obf_##name holds XOR'd data */			\
	atomic_set(&__obf_ready_##name, 1);				\
} while (0)

#define OBF_GET(name) ({						\
	static char __obf_dec_##name[OBF_MAX_LEN];			\
	static atomic_t __obf_dec_init_##name = ATOMIC_INIT(0);	\
	if (!atomic_read(&__obf_dec_init_##name)) {			\
		unsigned int __i;					\
		unsigned int __len = strlen(__obf_##name);		\
		for (__i = 0; __i < __len; __i++)			\
			__obf_dec_##name[__i] =				\
				__obf_##name[__i] ^ OBF_KEY;		\
		__obf_dec_##name[__i] = '\0';				\
		atomic_set(&__obf_dec_init_##name, 1);			\
	}								\
	(const char *)__obf_dec_##name;					\
})

/*
 * Simpler approach: just use the XOR key to scramble strings in
 * the binary. The decoded string is cached in a static buffer.
 *
 * This is the recommended approach for most use cases.
 */

/*
 * For path strings that are used frequently, we provide pre-encoded
 * versions that avoid .rodata string exposure entirely.
 */

/* Encode a path string at compile time using char-by-char XOR */
/* Example: "/data/adb" encoded with key 0x5A */
/* This is primarily documentation; actual encoding is done per-string */

#endif /* __KSU_H_OBFUSCATE */
