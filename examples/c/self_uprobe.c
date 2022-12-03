#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include ".output/bpf/libbpf.h"
#include ".output/self_uprobe.skel.h"
#include ".output/bpf/libbpf_internal.h"



static int libbpf_output(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void bump_memlock_limit(void)
{
    int32_t ret = 0;
    struct rlimit r1 =
    {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    ret = setrlimit(RLIMIT_MEMLOCK, &r1);
    if(ret != 0)
    {
        printf("Failed to increase RLIMIT_MEMLOCK limit\n");
        exit(1);
    }
    
}
int main(int argc, char *argvp[])
{
    int32_t ret=0;
    struct self_uprobe_bpf *skel = NULL;
    long func_offset = 0x0000000000001169;
    libbpf_set_print(libbpf_output);
    bump_memlock_limit();

    skel = self_uprobe_bpf__open_and_load();
    if(skel == NULL)
    {
        printf("Failed to open and load bpf skeleton\n");
        return -1;
    }
    skel->links.BPF_KRPOBE= bpf_program__attach_uprobe(skel->progs.BPF_KRPOBE, false, -1, "/home/joer/ebpf-test/btest/btest", func_offset);
    ret = libbpf_get_error(skel->links.BPF_KRPOBE);
    if (ret != 0)
    {
        printf("failed to attach uprobe:%d\n", ret);
        goto exit;

    }
    long addr = skel->links.BPF_KRPOBE->sym_off_addr;
        
    printf("BPF_KRPOBE elf offset is %ld\n", addr);
    skel->links.BPF_RETKRPOBE = bpf_program__attach_uprobe(skel->progs.BPF_RETKRPOBE, true, -1, "/home/joer/ebpf-test/btest/btest", func_offset);
    ret = libbpf_get_error(skel->links.BPF_RETKRPOBE);
    if (0 != ret)
    {
        printf("failed to attach uretprobe:%d\n", ret);
        goto exit;
    }
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
               "to see output of the BPF programs.\n");

    while (1)
    {
        printf("I am alive ...\n");
        sleep(1);
    }
    return 0;
exit:
    self_uprobe_bpf__destroy(skel);
    return -1;   
}