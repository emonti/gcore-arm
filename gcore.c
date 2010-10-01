/*
 * gcore.c
 *
 * Program for handcrafting a snapshot (core dump) of a running process
 * such that:
 *
 * a. The target process's RLIMIT_CORE limit doesn't matter (even if the limit
 *    is 0, as it is by default--core dump will still be obtained).
 * b. The target process doesn't automatically terminate after the core dump
 *    --as it would after a kernel-induced core dump.
 * c. Dump can be analyzed with gdb just like a kernel-induced core dump.
 * d. Core file location can be specified as an argument.
 * e. Entirely implemented in user space. The kernel's core dump mechanism
 *    is not involved. So aren't any signals.
 *
 * In light of a. and b., this program is especially useful if you wish
 * to make an already running process do a core dump without exiting.
 *
 * Copyright (c) 2007 Amit Singh. All Rights Reserved.
 * http://osxbook.com
 */

#define PROGVERS "1.3"

#define PROGNAME "gcore"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/machine.h>
#include <mach/thread_status.h>
#include <mach/vm_region.h>

#include <mach-o/loader.h>

#define CAST_DOWN(type, addr) (((type)((uintptr_t)(addr)))) 

typedef struct {
    int flavor;
    mach_msg_type_number_t count;
} coredump_thread_state_flavor_t;

#if defined (__ppc__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { PPC_THREAD_STATE,    PPC_THREAD_STATE_COUNT    },
    { PPC_FLOAT_STATE,     PPC_FLOAT_STATE_COUNT     },
    { PPC_EXCEPTION_STATE, PPC_EXCEPTION_STATE_COUNT },
    { PPC_VECTOR_STATE,    PPC_VECTOR_STATE_COUNT    },
};

static int coredump_nflavors = 4;

#elif defined (__ppc64__)

coredump_thread_state_flavor_t
thread_flavor_array[] = {
    { PPC_THREAD_STATE64,    PPC_THREAD_STATE64_COUNT    },
    { PPC_FLOAT_STATE,       PPC_FLOAT_STATE_COUNT       }, 
    { PPC_EXCEPTION_STATE64, PPC_EXCEPTION_STATE64_COUNT },
    { PPC_VECTOR_STATE,      PPC_VECTOR_STATE_COUNT      },
};

static int coredump_nflavors = 4;

#elif defined (__i386__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = { 
    { x86_THREAD_STATE32,    x86_THREAD_STATE32_COUNT    },
    { x86_FLOAT_STATE32,     x86_FLOAT_STATE32_COUNT     },
    { x86_EXCEPTION_STATE32, x86_EXCEPTION_STATE32_COUNT },
};

static int coredump_nflavors = 3;

#elif defined (__x86_64__)

static coredump_thread_state_flavor_t
thread_flavor_array[] = { 
    { x86_THREAD_STATE64,    x86_THREAD_STATE64_COUNT    },
    { x86_FLOAT_STATE64,     x86_FLOAT_STATE64_COUNT     },
    { x86_EXCEPTION_STATE64, x86_EXCEPTION_STATE64_COUNT },
};

static int coredump_nflavors = 3;

#else

#error Unsupported architecture

#endif

#define MAX_TSTATE_FLAVORS 10

typedef struct {
    vm_offset_t header; 
    int         hoffset;
    int         tstate_size;
    coredump_thread_state_flavor_t *flavors;
} tir_t;

typedef void(* thread_callback_t)(thread_t, void *);

static int  B_get_process_info(pid_t, struct kinfo_proc *);
static void M_collect_thread_states(thread_t, void *);
static int  M_get_processor_type(cpu_type_t *, cpu_subtype_t *);
static int  M_get_thread_status(register thread_t, int, thread_state_t,
                                mach_msg_type_number_t *);
static int  M_get_vmmap_entries(task_t);
static int  M_target_done(int);
static int  M_task_iterate_threads(task_t, thread_callback_t, void *);
static int  X_coredump(pid_t, const char *);

/* globals */
static mach_port_t target_task = MACH_PORT_NULL;
static int corefile_fd = -1;
static char corefile_path[MAXPATHLEN + 1] = { 0 };

void
SIGINT_handler(__unused int s)
{
    (void)M_target_done(EINTR);
}

static int
B_get_process_info(pid_t pid, struct kinfo_proc *kp)
{
    size_t bufsize      = 0;
    size_t orig_bufsize = 0;
    int    retry_count  = 0;
    int    local_error  = 0;
    int    mib[4]       = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };

    mib[3] = pid;
    orig_bufsize = bufsize = sizeof(struct kinfo_proc);

    for (retry_count = 0; ; retry_count++) {
        local_error = 0;
        bufsize = orig_bufsize;
        if ((local_error = sysctl(mib, 4, kp, &bufsize, NULL, 0)) < 0) {
            if (retry_count < 1000) {
                sleep(1);
                continue;
            }
            return local_error;
        } else if (local_error == 0) {
            break;
        }
        sleep(1);
    }

    return local_error;
}

static void
M_collect_thread_states(thread_t th, void *tirp)
{
    vm_offset_t header;
    int i, hoffset;
    coredump_thread_state_flavor_t *flavors;
    struct thread_command *tc;
    tir_t *t = (tir_t *)tirp;

    header = t->header;
    hoffset = t->hoffset;
    flavors = t->flavors;
    
    tc = (struct thread_command *)(header + hoffset);
    tc->cmd = LC_THREAD;
    tc->cmdsize = sizeof(struct thread_command) + t->tstate_size;
    hoffset += sizeof(struct thread_command);

    for (i = 0; i < coredump_nflavors; i++) {
        *(coredump_thread_state_flavor_t *)(header + hoffset) = flavors[i];
        hoffset += sizeof(coredump_thread_state_flavor_t);
        M_get_thread_status(th, flavors[i].flavor,
                            (thread_state_t)(header + hoffset),
                            &flavors[i].count);
        hoffset += flavors[i].count * sizeof(int);
    }

    t->hoffset = hoffset;
}

static int
M_get_processor_type(cpu_type_t *cpu_type, cpu_subtype_t *cpu_subtype)
{
    kern_return_t               kr = KERN_FAILURE;
    host_name_port_t            host = MACH_PORT_NULL;
    host_priv_t                 host_priv = MACH_PORT_NULL;
    processor_port_array_t      processor_list = (processor_port_array_t)0;
    natural_t                   processor_count;
    natural_t                   info_count;
    processor_basic_info_data_t basic_info;

    if (!cpu_type || !cpu_subtype) {
        return EINVAL;
    }

    *cpu_type = CPU_TYPE_ANY;
    *cpu_subtype = CPU_SUBTYPE_MULTIPLE;
   
    host = mach_host_self();

    kr = host_get_host_priv_port(host, &host_priv);
    if (kr != KERN_SUCCESS) {
        mach_error("host_get_host_priv_port:", kr);
        goto out;
    }

    processor_list = (processor_port_array_t)0;
    kr = host_processors(host_priv, &processor_list, &processor_count);
    if (kr != KERN_SUCCESS) {
        mach_error("host_processors:", kr);
        goto out;
    }

    info_count = PROCESSOR_BASIC_INFO_COUNT;
    kr = processor_info(processor_list[0], PROCESSOR_BASIC_INFO, &host, 
                        (processor_info_t)&basic_info, &info_count);
    if (kr == KERN_SUCCESS) {
        *cpu_type = basic_info.cpu_type;
        *cpu_subtype = basic_info.cpu_subtype;
    }

out:
    if (host != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), host);
    }

    if (host_priv != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), host_priv);
    }

    if (processor_list) {
        (void)vm_deallocate(mach_task_self(), (vm_address_t)processor_list,
                            processor_count * sizeof(processor_t *));
    }

    return kr;
}

static int
M_get_thread_status(register thread_t       thread,
                    int                     flavor,
                    thread_state_t          tstate,
                    mach_msg_type_number_t *count)
{
    return thread_get_state(thread, flavor, tstate, count);
}

static int
M_get_vmmap_entries(task_t task)
{
    kern_return_t kr      = KERN_SUCCESS;
    vm_address_t  address = 0;
    vm_size_t     size    = 0;
    int           n       = 1;

    while (1) {
        mach_msg_type_number_t count;
        struct vm_region_submap_info_64 info;
        uint32_t nesting_depth;
  
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(task, &address, &size, &nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }

        if (info.is_submap) {
            nesting_depth++;
        } else {
            address += size;
            n++;
        }
    }

    return n;
}

static int
M_target_done(int error)
{
    int ret = 0;

    if (target_task != MACH_PORT_NULL) {
        task_resume(target_task);
        mach_port_deallocate(mach_task_self(), target_task);
        target_task = MACH_PORT_NULL;
    }

    if ((corefile_fd != -1) && corefile_path) {
        ret = close(corefile_fd);
        corefile_fd = -1;
        if (error != 0) {
            (void)unlink(corefile_path);
        }
    }

    return ret;
}

static int
M_task_iterate_threads(task_t task,
                       void (* func_callback)(thread_t, void *),
                       void *func_arg)
{
    unsigned int i;
    kern_return_t kr;

    mach_msg_type_number_t thread_count;
    thread_array_t thread_list;

    kr = task_threads(task, &thread_list, &thread_count);
    if (kr != KERN_SUCCESS) {
        return kr;
    }

    for (i = 0; i < thread_count; i++) {
        (void)(*func_callback)(thread_list[i], func_arg);
    }

    for (i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), thread_list[i]);
    }

    (void)vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                        thread_count * sizeof(thread_act_t));

    return KERN_SUCCESS;
}

int
X_coredump(pid_t pid, const char *corefilename)
{
    unsigned int i;
    int is_64 = 0;
    int error = 0, error1 = 0;
    kern_return_t kr = KERN_SUCCESS;

    int                    segment_count;
    int                    command_size;
    int                    header_size;
    int                    tstate_size;
    int                    hoffset;
    off_t                  foffset;
    vm_map_offset_t        vmoffset;
    vm_offset_t            header;
    vm_map_size_t          vmsize;
    vm_prot_t              prot;
    vm_prot_t              maxprot;
    vm_inherit_t           inherit;
    struct mach_header    *mh;
    struct mach_header_64 *mh64;
    size_t                 mach_header_sz;
    size_t                 segment_command_sz;
    ssize_t                wc;
    cpu_type_t             cpu_type = CPU_TYPE_ANY;
    cpu_subtype_t          cpu_subtype = CPU_SUBTYPE_MULTIPLE;

    thread_array_t         thread_list;
    mach_msg_type_number_t thread_count;
    coredump_thread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];

    uint32_t                        nesting_depth = 0;
    struct vm_region_submap_info_64 vbr;
    mach_msg_type_number_t          vbrcount = 0;
    tir_t                           tir1;

    struct kinfo_proc kp, kp_self;

    kr = M_get_processor_type(&cpu_type, &cpu_subtype);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to get processor type (%d)\n", kr);
        return kr;
    }

    kr = task_for_pid(mach_task_self(), pid, &target_task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to find task for process %d\n", pid);
        return kr;
    }

    kr = B_get_process_info(pid, &kp);
    if (kr) {
        fprintf(stderr, "failed to retrieve process information for %d\n", pid);
        mach_port_deallocate(mach_task_self(), target_task);
        return kr;
    }

    kr = B_get_process_info(getpid(), &kp_self);
    if (kr) {
        fprintf(stderr, "failed to retrieve my own process information\n");
        mach_port_deallocate(mach_task_self(), target_task);
        return kr;
    }

    if ((kp.kp_proc.p_flag & P_LP64) ^ (kp_self.kp_proc.p_flag & P_LP64)) {
        fprintf(stderr, "%s is %d-bit whereas the target is %d-bit\n",
                PROGNAME, (kp_self.kp_proc.p_flag & P_LP64) ? 64 : 32,
                (kp.kp_proc.p_flag & P_LP64) ? 64 : 32);
        mach_port_deallocate(mach_task_self(), target_task);
        return EINVAL; /* bitness must match */
    }

#if defined(__ppc64__) || defined(__x86_64__)
    is_64 = 1;
    mach_header_sz = sizeof(struct mach_header_64);
    segment_command_sz = sizeof(struct segment_command_64);
#else /* 32-bit */
    mach_header_sz = sizeof(struct mach_header);
    segment_command_sz = sizeof(struct segment_command);
#endif

    (void)task_suspend(target_task);

    corefile_fd = open(corefilename, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (corefile_fd < 0) {
        error = errno;
        perror("open");
        goto out;
    }

    error = fchown(corefile_fd, kp.kp_eproc.e_ucred.cr_uid,
                   kp.kp_eproc.e_ucred.cr_gid);
    if (error) {
        fprintf(stderr, "failed to set core file ownership\n");
        goto out;
    }

    kr = task_threads(target_task, &thread_list, &thread_count);
    if (kr != KERN_SUCCESS) {
        error = kr;
        fprintf(stderr, "failed to retrieve threads for target task\n");
        goto out;
    } else {
        for (i = 0; i < thread_count; i++) {
            mach_port_deallocate(mach_task_self(), thread_list[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)thread_list,
                      thread_count * sizeof(thread_act_t));
    }

    segment_count = M_get_vmmap_entries(target_task);

    bcopy(thread_flavor_array, flavors, sizeof(thread_flavor_array));
    tstate_size = 0;

    for (i = 0; i < coredump_nflavors; i++) {
        tstate_size += sizeof(coredump_thread_state_flavor_t) +
                              (flavors[i].count * sizeof(int));
    }

    command_size = segment_count * segment_command_sz            +
                   thread_count  * sizeof(struct thread_command) +
                   tstate_size   * thread_count;

    header_size = command_size + mach_header_sz;

    header = (vm_offset_t)malloc(header_size);
    memset((void *)header, 0, header_size);

    if (is_64) {
        mh64             = (struct mach_header_64 *)header;
        mh64->magic      = MH_MAGIC_64;
        mh64->cputype    = cpu_type;
        mh64->cpusubtype = cpu_subtype;
        mh64->filetype   = MH_CORE;
        mh64->ncmds      = segment_count + thread_count;
        mh64->sizeofcmds = command_size;
        mh64->reserved   = 0; /* 8-byte alignment */
    } else {
        mh               = (struct mach_header *)header;
        mh->magic        = MH_MAGIC;
        mh->cputype      = cpu_type;
        mh->cpusubtype   = cpu_subtype;
        mh->filetype     = MH_CORE;
        mh->ncmds        = segment_count + thread_count;
        mh->sizeofcmds   = command_size;
    }

    hoffset = mach_header_sz;          /* offset into header */
    foffset = round_page(header_size); /* offset into file   */
    vmoffset = MACH_VM_MIN_ADDRESS;    /* offset into VM     */

    while (segment_count > 0) {

        struct segment_command    *sc;
        struct segment_command_64 *sc64;

        while (1) { /* next region */

            vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;

            if ((kr = mach_vm_region_recurse(target_task, &vmoffset, &vmsize,
                                             &nesting_depth,
                                             (vm_region_recurse_info_t)&vbr,
                                             &vbrcount)) != KERN_SUCCESS) {
                break;
            }

            if (!(is_64) && (vmoffset + vmsize > VM_MAX_ADDRESS)) {
                kr = KERN_INVALID_ADDRESS;
                break;
            }

            if(vbr.is_submap) {
                nesting_depth++;
                continue;
            } else {
                break;
            }
        } /* while (1) */

        if (kr != KERN_SUCCESS) {
            break;
        }

        prot = vbr.protection;
        maxprot = vbr.max_protection;
        inherit = vbr.inheritance;

        if (is_64) {
            sc64             = (struct segment_command_64 *)(header + hoffset);
            sc64->cmd        = LC_SEGMENT_64;
            sc64->cmdsize    = sizeof(struct segment_command_64);
            sc64->segname[0] = 0;
            sc64->vmaddr     = vmoffset;
            sc64->vmsize     = vmsize;
            sc64->fileoff    = foffset;
            sc64->filesize   = vmsize;
            sc64->maxprot    = maxprot;
            sc64->initprot   = prot;
            sc64->nsects     = 0;
        } else  {
            sc               = (struct segment_command *) (header + hoffset);
            sc->cmd          = LC_SEGMENT;
            sc->cmdsize      = sizeof(struct segment_command);
            sc->segname[0]   = 0;
            sc->vmaddr       = CAST_DOWN(vm_offset_t,vmoffset);
            sc->vmsize       = CAST_DOWN(vm_size_t,vmsize);
            sc->fileoff      = CAST_DOWN(uint32_t,foffset);
            sc->filesize     = CAST_DOWN(uint32_t,vmsize);
            sc->maxprot      = maxprot;
            sc->initprot     = prot;
            sc->nsects       = 0;
        }

        if ((prot & VM_PROT_READ) == 0) {
            mach_vm_protect(target_task, vmoffset, vmsize, FALSE,
                            prot | VM_PROT_READ);
        }

        if ((maxprot & VM_PROT_READ) == VM_PROT_READ &&
            (vbr.user_tag != VM_MEMORY_IOKIT)) {

            vm_map_size_t tmp_vmsize   = vmsize;
            off_t         xfer_foffset = foffset;

            while (tmp_vmsize > 0) {
                vm_map_size_t          xfer_vmsize = tmp_vmsize;
                vm_offset_t            local_address;
                mach_msg_type_number_t local_size;

                if (xfer_vmsize > INT_MAX) {
                    xfer_vmsize = INT_MAX;
                }

                kr = mach_vm_read(target_task, vmoffset, xfer_vmsize,
                                  &local_address, &local_size);

                if ((kr != KERN_SUCCESS) || (local_size != xfer_vmsize)) {
                    error = kr;
                    fprintf(stderr, "failed to read target's memory\n");
                    goto out;
                }

#if defined(__ppc64__) || defined(__x86_64__)
                wc = pwrite(corefile_fd, (void *)local_address, xfer_vmsize,
                            xfer_foffset);
#else
                wc = pwrite(corefile_fd,
                            (void *)CAST_DOWN(uint32_t, local_address),
                            CAST_DOWN(uint32_t, xfer_vmsize), xfer_foffset);
#endif
                if (wc < 0) {
                    error = errno;
                    fprintf(stderr, "failed to write core file\n");
                }

                (void)mach_vm_deallocate(mach_task_self(), local_address,
                                         local_size);

                if (wc < 0) {
                    goto out;
                }

                tmp_vmsize -= xfer_vmsize;
                xfer_foffset += xfer_vmsize;

            } /* while (tmp_vmsize > 0) */
        }

        hoffset  += segment_command_sz;
        foffset  += vmsize;
        vmoffset += vmsize;

        segment_count--;
    }

    if (is_64) {
        mh64->ncmds -= segment_count;
    } else {
        mh->ncmds -= segment_count;
    }

    tir1.header      = header;
    tir1.hoffset     = hoffset;
    tir1.flavors     = flavors;
    tir1.tstate_size = tstate_size;

    M_task_iterate_threads(target_task, M_collect_thread_states, &tir1);

    wc = pwrite(corefile_fd, (caddr_t)header, (size_t)header_size, (off_t)0); 

    if (wc < 0) {
        error = errno;
    }

    free((void *)header);

out:
    error1 = M_target_done(error);

    if (error == 0) {
        error = error1;
    }

    return error;
}

static void
usage_exit(void)
{
    fprintf(stderr, "usage: %s [-c <corefile>] <pid>\n", PROGNAME);
    exit(EINVAL);
}

int
main(int argc, char **argv)
{
    kern_return_t kr;
    pid_t pid;
    struct sigaction act;
    sigset_t sigset;
    int ch;

    if (argc < 2) {
        usage_exit();
    }

    while ((ch = getopt(argc, argv, "c:")) != -1) {
        switch (ch) {
        case 'c':
            if (strlen(optarg) > MAXPATHLEN) {
                fprintf(stderr, "specified path is too long (%s)\n", optarg);
                exit(ENAMETOOLONG);
            }
            snprintf(corefile_path, MAXPATHLEN, "%s", optarg);
            break;

        case '?':
        default:
            usage_exit();
            break;
        }
    }

    argc -= optind;
    argv += optind;

    pid = strtoul(argv[0], NULL, 10);

    if ((pid == 0) || (pid == ULONG_MAX)) {
        fprintf(stderr, "invalid process identifier %s\n", argv[0]);
        exit(EINVAL);
    }

    if (getpgid(pid) < 0) {
        if (errno == ESRCH) {
            fprintf(stderr, "no process found with identifier %d\n", pid);
            exit(ESRCH);
        }
    }

    if (pid == getpid()) {
        fprintf(stderr, "cannot use my own process identifier\n");
        exit(EINVAL);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "you must be root to use %s\n", PROGNAME);
        exit(EPERM);
    }

    if (!corefile_path[0]) {
        snprintf(corefile_path, MAXPATHLEN, "core.%u", pid);
    }

    sigfillset(&sigset);
    sigdelset(&sigset, SIGINT);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    act.sa_handler = SIGINT_handler;
    sigfillset(&(act.sa_mask));
    sigaction(SIGINT, &act, NULL);
    
    kr = X_coredump(pid, corefile_path);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "failed to dump core for process %d (%d)\n", pid, kr);
        exit(kr);
    }

    exit(0);
}
