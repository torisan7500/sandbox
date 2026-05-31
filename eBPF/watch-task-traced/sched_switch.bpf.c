#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// linux/sched.h
#define __TASK_TRACED 0x00000008

// MAP: array
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} target_pid SEC(".maps");
#define KEY_PARENT 0
#define KEY_CHILD  1


// MAP: RingBuffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} ringbuff_p SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} ringbuff_c SEC(".maps");

struct ebpf_event {
    __u32 pid;
    __u32 state;
};


// 生の状態を見たいので、tp_btfを使う
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next,
             unsigned int prev_state)
{
    __u32 fired_pid = BPF_CORE_READ(prev, pid);
    __u32 *target_pid_p = bpf_map_lookup_elem(&target_pid, &((__u32){KEY_PARENT}));
    __u32 *target_pid_c = bpf_map_lookup_elem(&target_pid, &((__u32){KEY_CHILD}));

    // -----------------
    // Parent
    // -----------------
    if (target_pid_p && *target_pid_p != 0) {
        if (fired_pid != *target_pid_p)
            return 0;
        
        struct ebpf_event *e = bpf_ringbuf_reserve(&ringbuff_p, sizeof(*e), 0);
        if (!e)
            return 0;

        e->pid   = fired_pid;
        e->state = (__u32)prev_state;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    // -----------------
    // Child
    // -----------------
    else if (target_pid_c && *target_pid_c != 0) {
        if (fired_pid != *target_pid_c)
            return 0;
        
        struct ebpf_event *e = bpf_ringbuf_reserve(&ringbuff_c, sizeof(*e), 0);
        if (!e)
            return 0;

        e->pid   = fired_pid;
        e->state = (__u32)prev_state;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
