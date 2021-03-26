#ifndef _DENTRY_RESOLVER_H_
#define _DENTRY_RESOLVER_H_

#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/mount.h>
#include <linux/fs.h>

#include "defs.h"
#include "filters.h"
#include "dentry.h"

#define DENTRY_INVALID -1
#define DENTRY_DISCARDED -2

#define FAKE_INODE_MSW 0xdeadc001UL

#define DR_MAX_TAIL_CALL          30
#define DR_MAX_ITERATION_DEPTH    63
#define DR_MAX_SEGMENT_LENGTH     255

struct path_leaf_t {
  struct path_key_t parent;
  char name[DR_MAX_SEGMENT_LENGTH + 1];
};

struct bpf_map_def SEC("maps/pathnames") pathnames = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct path_key_t),
    .value_size = sizeof(struct path_leaf_t),
    .max_entries = 64000,
    .pinning = 0,
    .namespace = "",
};

#define DR_NO_CALLBACK                       -1
#define DR_OPEN_CALLBACK_KEY                  0
#define DR_SETATTR_CALLBACK_KEY               1
#define DR_MKDIR_CALLBACK_KEY                 2
#define DR_MOUNT_CALLBACK_KEY                 3
#define DR_SECURITY_INODE_RMDIR_CALLBACK_KEY  4
#define DR_SETXATTR_CALLBACK_KEY              5
#define DR_UNLINK_CALLBACK_KEY                6
#define DR_LINK_SRC_CALLBACK_KEY              7
#define DR_LINK_DST_CALLBACK_KEY              8
#define DR_RENAME_CALLBACK_KEY                9

struct bpf_map_def SEC("maps/dentry_resolver_callbacks") dentry_resolver_callbacks = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = EVENT_MAX,
};

#define DR_KERN_KEY 0
#define DR_ERPC_KEY 1

struct bpf_map_def SEC("maps/dentry_resolver_progs") dentry_resolver_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 2,
};

int __attribute__((always_inline)) resolve_dentry_tail_call(struct dentry_resolver_input_t *input) {
    struct path_leaf_t map_value = {};
    struct path_key_t key = input->key;
    struct path_key_t next_key = input->key;
    struct inode_discarder_t discarder_key = {};
    struct qstr qstr;
    struct dentry *dentry = input->dentry;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;

    if (key.ino == 0 || key.mount_id == 0) {
        return DENTRY_INVALID;
    }

#pragma unroll
    for (int i = 0; i < DR_MAX_ITERATION_DEPTH; i++)
    {
        d_parent = NULL;
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        key = next_key;
        if (dentry != d_parent) {
            write_dentry_inode(d_parent, &d_inode);
            write_inode_ino(d_inode, &next_key.ino);
        }

        // discard filename and its parent only in order to limit the number of lookup
        if (input->discarder_type && i < 2) {
            discarder_key.path_key = key;
            discarder_key.revision = get_discarder_revision(key.mount_id);
            discarder_key.is_leaf = i == 0;

            if (is_discarded(&inode_discarders, &discarder_key, input->discarder_type)) {
                return DENTRY_DISCARDED;
            }
        }

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&map_value.name, sizeof(map_value.name), (void *)qstr.name);

        if (map_value.name[0] == '/' || map_value.name[0] == 0) {
            map_value.name[0] = '/';
            next_key.ino = 0;
            next_key.mount_id = 0;
        }

        map_value.parent = next_key;

        bpf_map_update_elem(&pathnames, &key, &map_value, BPF_ANY);

        dentry = d_parent;
        if (next_key.ino == 0) {
            input->dentry = d_parent;
            input->key = next_key;
            return i + 1;
        }
    }

    if (input->iteration == DR_MAX_TAIL_CALL) {
        map_value.name[0] = 0;
        map_value.parent.mount_id = 0;
        map_value.parent.ino = 0;
        bpf_map_update_elem(&pathnames, &next_key, &map_value, BPF_ANY);
    }

    // prepare for the next iteration
    input->dentry = d_parent;
    input->key = next_key;
    return DR_MAX_ITERATION_DEPTH;
}

SEC("kprobe/dentry_resolver_kern")
int kprobe__dentry_resolver_kern(struct pt_regs *ctx) {
    struct syscall_cache_t *syscall = peek_syscall(ALL_SYSCALLS);
    if (!syscall)
        return 0;

    syscall->resolver.iteration++;
    syscall->resolver.ret = resolve_dentry_tail_call(&syscall->resolver);
    if (syscall->resolver.ret > 0) {
        if (syscall->resolver.iteration < DR_MAX_TAIL_CALL && syscall->resolver.key.ino != 0) {
            bpf_tail_call(ctx, &dentry_resolver_progs, DR_KERN_KEY);
        }

        syscall->resolver.ret += DR_MAX_ITERATION_DEPTH * (syscall->resolver.iteration - 1);
    }

    if (syscall->resolver.callback >= 0) {
        bpf_tail_call(ctx, &dentry_resolver_callbacks, syscall->resolver.callback);
    }
    return 0;
}

int __attribute__((always_inline)) handle_resolve_path(void *data) {
    struct path_key_t key = {};
    struct path_leaf_t *map_value = 0;
    char *userspace_buffer = 0;
    bpf_probe_read(&key, sizeof(key), data);
    bpf_probe_read(&userspace_buffer, sizeof(userspace_buffer), data + sizeof(key));

    u16 cursor = 0;
    int ret = 0;

    // select dentry then write in user space buffer
#pragma unroll
    for (int i = 0; i < DR_MAX_ITERATION_DEPTH; i++)
    {
        map_value = bpf_map_lookup_elem(&pathnames, &key);
        if (map_value == NULL) {
            break;
        }
        ret = bpf_probe_write_user((void *) userspace_buffer + cursor, map_value->name, DR_MAX_SEGMENT_LENGTH);
        if (ret < 0) {
            return ret;
        }
        cursor += DR_MAX_SEGMENT_LENGTH;

        key = map_value->parent;
        if (key.ino == 0) {
            break;
        }
    }

    return 0;
}

int __attribute__((always_inline)) handle_resolve_segment(void *data) {
    struct path_key_t key = {};
    char *userspace_buffer = 0;
    bpf_probe_read(&key, sizeof(key), data);
    bpf_probe_read(&userspace_buffer, sizeof(userspace_buffer), data + sizeof(key));

    // resolve segment and write in buffer
    struct path_leaf_t *map_value = bpf_map_lookup_elem(&pathnames, &key);
    if (map_value == NULL) {
        return 0;
    }
    int ret = bpf_probe_write_user((void *) userspace_buffer, map_value->name, DR_MAX_SEGMENT_LENGTH);
    return ret;
}

int __attribute__((always_inline)) resolve_dentry(struct pt_regs *ctx) {
    bpf_tail_call(ctx, &dentry_resolver_progs, DR_KERN_KEY);
    return 0;
}

#endif
