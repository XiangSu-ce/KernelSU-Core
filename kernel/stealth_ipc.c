/*
 * stealth_ipc.c - Stealth IPC routing framework for KernelSU
 *
 * Provides infrastructure for invisible inter-process communication
 * between stealth-loaded kernel modules and their userspace counterparts:
 *
 * 1. IPC Handler Registry: stealth modules register command handlers
 *    identified by module_id. Userspace sends commands through KSU's
 *    existing ioctl interface, which routes to the correct handler.
 *
 * 2. Stealth supercall routing: new IOCTL commands for stealth operations
 *    (mark PID, register module, stealth exec, forward IPC).
 *
 * 3. /dev device node hiding: filters stealth device entries from
 *    /dev directory listings.
 *
 * This module bridges the gap between stealth kernel modules that cannot
 * create their own visible /dev nodes or ioctl endpoints, and userspace
 * programs that need to communicate with them.
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/wait.h>

#include "klog.h" // IWYU pragma: keep
#include "stealth.h"

/* ---- IPC Handler Registry ---- */

#define MAX_IPC_HANDLERS 32
#define MAX_MODULE_ID_LEN 64
#define MAX_IPC_DATA_LEN (1024 * 1024)

/**
 * struct stealth_ipc_handler - Registered IPC handler for a stealth module.
 * @module_id: unique string identifier for the module
 * @handler: callback function that handles IPC requests
 * @private_data: opaque pointer passed to handler
 * @active: whether this slot is in use
 *
 * Handler prototype:
 *   int handler(u32 subcmd, void __user *data, size_t len, void *priv)
 *   Returns 0 on success, negative errno on failure.
 *
 * stealth_ipc_handler_fn typedef is in stealth.h
 */
struct stealth_ipc_handler {
	char module_id[MAX_MODULE_ID_LEN];
	stealth_ipc_handler_fn handler;
	void *private_data;
	bool active;
};

static struct stealth_ipc_handler ipc_handlers[MAX_IPC_HANDLERS];
static atomic_t ipc_inflight[MAX_IPC_HANDLERS];
static DEFINE_SPINLOCK(ipc_lock);
static DECLARE_WAIT_QUEUE_HEAD(ipc_waitq);

/**
 * ksu_stealth_ipc_register() - Register an IPC handler for a stealth module.
 * @module_id: unique identifier string
 * @handler: callback function
 * @priv: opaque private data
 *
 * Returns 0 on success, -ENOSPC if registry full, -EEXIST if id already used.
 */
int ksu_stealth_ipc_register(const char *module_id,
			     stealth_ipc_handler_fn handler, void *priv)
{
	unsigned long flags;
	int i, slot = -1;

	if (!module_id || !handler)
		return -EINVAL;
	if (!*module_id)
		return -EINVAL;
	if (strnlen(module_id, MAX_MODULE_ID_LEN) >= MAX_MODULE_ID_LEN)
		return -ENAMETOOLONG;

	spin_lock_irqsave(&ipc_lock, flags);

	/* Check for duplicate and find free slot */
	for (i = 0; i < MAX_IPC_HANDLERS; i++) {
		if (ipc_handlers[i].active) {
			if (strncmp(ipc_handlers[i].module_id, module_id,
				    MAX_MODULE_ID_LEN) == 0) {
				spin_unlock_irqrestore(&ipc_lock, flags);
				return -EEXIST;
			}
		} else if (slot < 0 && atomic_read(&ipc_inflight[i]) == 0) {
			slot = i;
		}
	}

	if (slot < 0) {
		spin_unlock_irqrestore(&ipc_lock, flags);
		return -ENOSPC;
	}

	strscpy(ipc_handlers[slot].module_id, module_id, MAX_MODULE_ID_LEN);
	ipc_handlers[slot].handler = handler;
	ipc_handlers[slot].private_data = priv;
	ipc_handlers[slot].active = true;

	spin_unlock_irqrestore(&ipc_lock, flags);
	return 0;
}

/**
 * ksu_stealth_ipc_unregister() - Remove an IPC handler.
 */
int ksu_stealth_ipc_unregister(const char *module_id)
{
	unsigned long flags;
	int i;

	if (!module_id)
		return -EINVAL;
	if (!*module_id)
		return -EINVAL;
	if (strnlen(module_id, MAX_MODULE_ID_LEN) >= MAX_MODULE_ID_LEN)
		return -ENAMETOOLONG;

	spin_lock_irqsave(&ipc_lock, flags);
	for (i = 0; i < MAX_IPC_HANDLERS; i++) {
		if (ipc_handlers[i].active &&
		    strncmp(ipc_handlers[i].module_id, module_id,
			    MAX_MODULE_ID_LEN) == 0) {
			ipc_handlers[i].active = false;
			ipc_handlers[i].handler = NULL;
			ipc_handlers[i].private_data = NULL;
			memset(ipc_handlers[i].module_id, 0,
			       sizeof(ipc_handlers[i].module_id));
			spin_unlock_irqrestore(&ipc_lock, flags);
			wait_event(ipc_waitq, atomic_read(&ipc_inflight[i]) == 0);
			return 0;
		}
	}
	spin_unlock_irqrestore(&ipc_lock, flags);
	return -ENOENT;
}

/**
 * ksu_stealth_ipc_dispatch() - Route an IPC call to the registered handler.
 * @module_id: target module identifier
 * @subcmd: sub-command for the module
 * @data: userspace data pointer
 * @len: data length
 *
 * Returns handler result, or -ENOENT if module not found.
 */
static int stealth_ipc_dispatch(const char *module_id, u32 subcmd,
				void __user *data, size_t len)
{
	unsigned long flags;
	stealth_ipc_handler_fn handler = NULL;
	void *priv = NULL;
	int i, slot = -1;

	spin_lock_irqsave(&ipc_lock, flags);
	for (i = 0; i < MAX_IPC_HANDLERS; i++) {
		if (ipc_handlers[i].active &&
		    strncmp(ipc_handlers[i].module_id, module_id,
			    MAX_MODULE_ID_LEN) == 0) {
			handler = ipc_handlers[i].handler;
			priv = ipc_handlers[i].private_data;
			if (handler) {
				atomic_inc(&ipc_inflight[i]);
				slot = i;
			}
			break;
		}
	}
	spin_unlock_irqrestore(&ipc_lock, flags);

	if (!handler)
		return -ENOENT;

	i = handler(subcmd, data, len, priv);
	if (slot >= 0) {
		atomic_dec(&ipc_inflight[slot]);
		wake_up_all(&ipc_waitq);
	}
	return i;
}

/* ---- Stealth IOCTL Handlers ---- */

/*
 * These are IOCTL handlers registered with the KSU supercall framework.
 * They provide userspace access to stealth operations.
 */

/**
 * Stealth IPC forwarding command structure.
 * Userspace fills this, sends via KSU_IOCTL_STEALTH_IPC.
 */
struct ksu_stealth_ipc_cmd {
	char module_id[MAX_MODULE_ID_LEN]; /* Target module */
	__u32 subcmd;			   /* Sub-command for module */
	__aligned_u64 data;		   /* Userspace data pointer */
	__u32 data_len;			   /* Data length */
};

/**
 * do_stealth_ipc() - Handle KSU_IOCTL_STEALTH_IPC.
 *
 * Routes IPC from userspace to a stealth-loaded kernel module's handler.
 */
int ksu_do_stealth_ipc(void __user *arg)
{
	struct ksu_stealth_ipc_cmd cmd;

	if (!arg)
		return -EINVAL;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	cmd.module_id[MAX_MODULE_ID_LEN - 1] = '\0';
	if (!cmd.module_id[0])
		return -EINVAL;
	if (cmd.data_len > MAX_IPC_DATA_LEN)
		return -E2BIG;

	return stealth_ipc_dispatch(cmd.module_id, cmd.subcmd,
				    (void __user *)(unsigned long)cmd.data,
				    cmd.data_len);
}

/**
 * Stealth PID management command structure.
 */
struct ksu_stealth_pid_cmd {
	__u32 operation;     /* 0=mark, 1=unmark, 2=mark_self */
	__s32 pid;           /* Target PID (ignored for mark_self) */
	char fake_comm[128]; /* Optional: fake process name */
	char fake_exe[128];  /* Optional: fake executable path */
};

#define STEALTH_PID_MARK       0
#define STEALTH_PID_UNMARK     1
#define STEALTH_PID_MARK_SELF  2
#define STEALTH_PID_DISGUISE   3

int ksu_do_stealth_pid(void __user *arg)
{
	struct ksu_stealth_pid_cmd cmd;

	if (!arg)
		return -EINVAL;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	switch (cmd.operation) {
	case STEALTH_PID_MARK:
		return ksu_stealth_mark_pid(cmd.pid);
	case STEALTH_PID_UNMARK:
		return ksu_stealth_unmark_pid(cmd.pid);
	case STEALTH_PID_MARK_SELF:
		return ksu_stealth_mark_self();
	case STEALTH_PID_DISGUISE:
		cmd.fake_comm[sizeof(cmd.fake_comm) - 1] = '\0';
		cmd.fake_exe[sizeof(cmd.fake_exe) - 1] = '\0';
		return ksu_stealth_set_disguise(
			cmd.pid,
			cmd.fake_comm[0] ? cmd.fake_comm : NULL,
			cmd.fake_exe[0] ? cmd.fake_exe : NULL);
	default:
		return -EINVAL;
	}
}

/**
 * Stealth module registration command.
 */
struct ksu_stealth_register_mod_cmd {
	char name[64]; /* Module name to register as stealth */
};

int ksu_do_stealth_register_mod(void __user *arg)
{
	struct ksu_stealth_register_mod_cmd cmd;

	if (!arg)
		return -EINVAL;
	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	cmd.name[sizeof(cmd.name) - 1] = '\0';
	return ksu_stealth_register_module(cmd.name, NULL);
}

/**
 * Stealth exec command — marks current process as stealth before exec.
 */
int ksu_do_stealth_exec(void __user *arg)
{
	return ksu_stealth_mark_self();
}

/* ---- /dev Device Node Hiding ---- */

/*
 * Device nodes created by stealth modules need to be hidden.
 * We maintain a list of device names to hide from /dev/ listings.
 * This is checked by the getdents hook in proc_hide.c (extended).
 */

#define MAX_HIDDEN_DEVS 16
#define MAX_DEV_NAME_LEN 64

static char hidden_devs[MAX_HIDDEN_DEVS][MAX_DEV_NAME_LEN];
static int hidden_dev_count;
static DEFINE_SPINLOCK(hidden_dev_lock);

/**
 * ksu_stealth_hide_dev() - Register a /dev name to be hidden.
 * @name: device node name (without /dev/ prefix)
 */
int ksu_stealth_hide_dev(const char *name)
{
	unsigned long flags;
	int i;

	if (!name || !*name)
		return -EINVAL;
	if (strnlen(name, MAX_DEV_NAME_LEN) >= MAX_DEV_NAME_LEN)
		return -ENAMETOOLONG;

	spin_lock_irqsave(&hidden_dev_lock, flags);

	if (hidden_dev_count >= MAX_HIDDEN_DEVS) {
		spin_unlock_irqrestore(&hidden_dev_lock, flags);
		return -ENOSPC;
	}

	/* Check for duplicate */
	for (i = 0; i < hidden_dev_count; i++) {
		if (strncmp(hidden_devs[i], name, MAX_DEV_NAME_LEN) == 0) {
			spin_unlock_irqrestore(&hidden_dev_lock, flags);
			return -EEXIST;
		}
	}

	strscpy(hidden_devs[hidden_dev_count], name, MAX_DEV_NAME_LEN);
	hidden_dev_count++;

	spin_unlock_irqrestore(&hidden_dev_lock, flags);
	return 0;
}

/**
 * ksu_stealth_unhide_dev() - Remove a device from hidden list.
 */
int ksu_stealth_unhide_dev(const char *name)
{
	unsigned long flags;
	int i;

	if (!name)
		return -EINVAL;
	if (!*name)
		return -EINVAL;
	if (strnlen(name, MAX_DEV_NAME_LEN) >= MAX_DEV_NAME_LEN)
		return -ENAMETOOLONG;

	spin_lock_irqsave(&hidden_dev_lock, flags);
	for (i = 0; i < hidden_dev_count; i++) {
		if (strncmp(hidden_devs[i], name, MAX_DEV_NAME_LEN) == 0) {
			/* Shift remaining entries */
			if (i < hidden_dev_count - 1)
				memmove(&hidden_devs[i], &hidden_devs[i + 1],
					(hidden_dev_count - i - 1) *
						MAX_DEV_NAME_LEN);
			hidden_dev_count--;
			spin_unlock_irqrestore(&hidden_dev_lock, flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&hidden_dev_lock, flags);
	return -ENOENT;
}

/**
 * ksu_is_hidden_dev() - Check if a device name should be hidden.
 * @name: device node name
 *
 * Returns true if the device should be hidden from /dev/ listings.
 */
bool ksu_is_hidden_dev(const char *name)
{
	unsigned long flags;
	int i;

	if (!name || !*name)
		return false;

	spin_lock_irqsave(&hidden_dev_lock, flags);
	if (hidden_dev_count == 0) {
		spin_unlock_irqrestore(&hidden_dev_lock, flags);
		return false;
	}
	for (i = 0; i < hidden_dev_count; i++) {
		if (strncmp(hidden_devs[i], name, MAX_DEV_NAME_LEN) == 0) {
			spin_unlock_irqrestore(&hidden_dev_lock, flags);
			return true;
		}
	}
	spin_unlock_irqrestore(&hidden_dev_lock, flags);
	return false;
}

/**
 * ksu_filter_proc_devices() - Filter hidden devices from /proc/devices output.
 */
ssize_t ksu_filter_proc_devices(char __user *ubuf, ssize_t count)
{
	char *kbuf, *src, *dst, *line_end;
	ssize_t new_len = 0;

	if (!ksu_should_hide_proc_general())
		return count;
	if (count <= 0 || hidden_dev_count == 0)
		return count;

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return count;

	if (copy_from_user(kbuf, ubuf, count)) {
		kfree(kbuf);
		return count;
	}
	kbuf[count] = '\0';

	src = kbuf;
	dst = kbuf;
	while (src < kbuf + count) {
		line_end = memchr(src, '\n', (kbuf + count) - src);
		if (!line_end)
			line_end = kbuf + count;
		else
			line_end++;

		/* device name is last token on the line */
		{
			char *end = line_end;
			char name_buf[MAX_DEV_NAME_LEN];
			size_t name_len;
			while (end > src && *(end - 1) == '\n')
				--end;
			while (end > src && *(end - 1) == ' ')
				--end;
			{
				char *p = end;
				while (p > src && *(p - 1) != ' ' &&
				       *(p - 1) != '\t')
					--p;
				name_len = (end > p) ? (size_t)(end - p) : 0;
				if (name_len >= MAX_DEV_NAME_LEN)
					name_len = MAX_DEV_NAME_LEN - 1;
				memcpy(name_buf, p, name_len);
				name_buf[name_len] = '\0';
			}
			if (!ksu_is_hidden_dev(name_buf)) {
				size_t len = line_end - src;
				if (dst != src)
					memmove(dst, src, len);
				dst += len;
				new_len += len;
			}
		}
		src = line_end;
	}

	if (new_len != count) {
		if (copy_to_user(ubuf, kbuf, new_len)) {
			kfree(kbuf);
			return count;
		}
	}
	kfree(kbuf);
	return new_len;
}

/* ---- Init/Exit ---- */

void ksu_stealth_ipc_init(void)
{
	int i;

	memset(ipc_handlers, 0, sizeof(ipc_handlers));
	for (i = 0; i < MAX_IPC_HANDLERS; i++)
		atomic_set(&ipc_inflight[i], 0);
	memset(hidden_devs, 0, sizeof(hidden_devs));
	hidden_dev_count = 0;
}

void ksu_stealth_ipc_exit(void)
{
	unsigned long flags;
	int i;

	/*
	 * Deactivate all handlers first, then wait for any inflight
	 * handler calls to complete before clearing the slots.
	 * This prevents use-after-free if a handler is executing on
	 * another CPU when we clear its function pointer.
	 */
	spin_lock_irqsave(&ipc_lock, flags);
	for (i = 0; i < MAX_IPC_HANDLERS; i++) {
		ipc_handlers[i].active = false;
		ipc_handlers[i].handler = NULL;
	}
	spin_unlock_irqrestore(&ipc_lock, flags);

	/* Wait for all inflight handler calls to finish */
	for (i = 0; i < MAX_IPC_HANDLERS; i++) {
		if (atomic_read(&ipc_inflight[i]) > 0)
			wait_event(ipc_waitq,
				   atomic_read(&ipc_inflight[i]) == 0);
	}

	/* Now safe to clear all data */
	spin_lock_irqsave(&ipc_lock, flags);
	memset(ipc_handlers, 0, sizeof(ipc_handlers));
	spin_unlock_irqrestore(&ipc_lock, flags);

	spin_lock_irqsave(&hidden_dev_lock, flags);
	hidden_dev_count = 0;
	spin_unlock_irqrestore(&hidden_dev_lock, flags);
}
