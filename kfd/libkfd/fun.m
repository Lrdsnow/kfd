//
//  fun.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#include "fun.h"
#include "libkfd.h"
#include "helpers.h"
#include <sys/stat.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/mount.h>
#import "kfd-Bridging-Header.h"
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/snapshot.h>

struct hfs_mount_args {
    char    *fspec;            /* block special device to mount */
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding;    /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method)
{
    return kopen(puaf_pages, puaf_method, kread_method, kwrite_method);
}

void do_kclose(u64 kfd)
{
    kclose((struct kfd*)(kfd));
}

void do_respring()
{
    respringFrontboard();
}

uint8_t kread8(u64 kfd, uint64_t where) {
    uint8_t out;
    kread(kfd, where, &out, sizeof(uint8_t));
    return out;
}
uint32_t kread32(u64 kfd, uint64_t where) {
    uint32_t out;
    kread(kfd, where, &out, sizeof(uint32_t));
    return out;
}
uint64_t kread64(u64 kfd, uint64_t where) {
    uint64_t out;
    kread(kfd, where, &out, sizeof(uint64_t));
    return out;
}

void kwrite8(u64 kfd, uint64_t where, uint8_t what) {
    uint8_t _buf[8] = {};
    _buf[0] = what;
    _buf[1] = kread8(kfd, where+1);
    _buf[2] = kread8(kfd, where+2);
    _buf[3] = kread8(kfd, where+3);
    _buf[4] = kread8(kfd, where+4);
    _buf[5] = kread8(kfd, where+5);
    _buf[6] = kread8(kfd, where+6);
    _buf[7] = kread8(kfd, where+7);
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}
void kwrite32(u64 kfd, uint64_t where, uint32_t what) {
    u32 _buf[2] = {};
    _buf[0] = what;
    _buf[1] = kread32(kfd, where+4);
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}
void kwrite64(u64 kfd, uint64_t where, uint64_t what) {
    u64 _buf[1] = {};
    _buf[0] = what;
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}

uint64_t getProc(u64 kfd, pid_t pid) {
    uint64_t proc = ((struct kfd*)kfd)->info.kaddr.kernel_proc;
    
    while (true) {
        if(kread32(kfd, proc + 0x60/*PROC_P_PID_OFF*/) == pid) {
            return proc;
        }
        proc = kread64(kfd, proc + 0x8/*PROC_P_LIST_LE_PREV_OFF*/);
    }
    
    return 0;
}

uint64_t getProcByName(u64 kfd, char* nm) {
    uint64_t proc = ((struct kfd*)kfd)->info.kaddr.kernel_proc;
    
    while (true) {
        uint64_t nameptr = proc + 0x381;//PROC_P_NAME_OFF; probably the problem
        char name[32];
        kread(kfd, nameptr, &name, 32);
        printf("[i] pid: %d, process name: %s\n", kread32(kfd, proc + 0x60), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(kfd, proc + 0x8);//PROC_P_LIST_LE_PREV_OFF);
    }
    
    return 0;
}

int getPidByName(u64 kfd, char* nm) {
    print("function: getPidByName");
//    printf("%s", getProcByName(kfd, "tccd"));
    return kread32(kfd, getProcByName(kfd, nm) + 0x60);//PROC_P_PID_OFF);
}

int funProc(u64 kfd, uint64_t proc) {
    int p_ppid = kread32(kfd, proc + 0x20);
    printf("[i] self proc->p_ppid: %d\n", p_ppid);
    printf("[i] Patching proc->p_ppid %d -> 1 (for testing kwrite32)\n", p_ppid);
    kwrite32(kfd, proc + 0x20, 0x1);
    printf("getppid(): %u\n", getppid());
    kwrite32(kfd, proc + 0x20, p_ppid);

    int p_original_ppid = kread32(kfd, proc + 0x24);
    printf("[i] self proc->p_original_ppid: %d\n", p_original_ppid);
    
    int p_pgrpid = kread32(kfd, proc + 0x28);
    printf("[i] self proc->p_pgrpid: %d\n", p_pgrpid);
    
    kwrite32(kfd, proc + 0x2c, 0x0);
    kwrite32(kfd, proc + 0x30, 0x0);
    kwrite32(kfd, proc + 0x34, 0x0);
    kwrite32(kfd, proc + 0x38, 0x0);
    kwrite32(kfd, proc + 0x3c, 0x0);
    kwrite32(kfd, proc + 0x40, 0x0);
    kwrite32(kfd, proc + 0x44, 0x0);
    kwrite32(kfd, proc + 0x48, 0x0);
    
    int p_uid = kread32(kfd, proc + 0x2c);
    printf("[i] self proc->p_uid: %d\n", p_uid);
    
    int p_gid = kread32(kfd, proc + 0x30);
    printf("[i] self proc->p_gid: %d\n", p_gid);
    
    int p_ruid = kread32(kfd, proc + 0x34);
    printf("[i] self proc->p_ruid: %d\n", p_ruid);
    
    int p_rgid = kread32(kfd, proc + 0x38);
    printf("[i] self proc->p_rgid: %d\n", p_rgid);
    
    int p_svuid = kread32(kfd, proc + 0x3c);
    printf("[i] self proc->p_svuid: %d\n", p_svuid);
    
    int p_svgid = kread32(kfd, proc + 0x40);
    printf("[i] self proc->p_svgid: %d\n", p_svgid);
    
    int p_sessionid = kread32(kfd, proc + 0x44);
    printf("[i] self proc->p_sessionid: %d\n", p_sessionid);
    
    uint64_t p_puniqueid = kread64(kfd, proc + 0x48);
    printf("[i] self proc->p_puniqueid: 0x%llx\n", p_puniqueid);
    
    printf("[i] Patching proc->p_puniqueid 0x%llx -> 0x4142434445464748 (for testing kwrite64)\n", p_puniqueid);
    kwrite64(kfd, proc+0x48, 0x4142434445464748);
    printf("[i] self proc->p_puniqueid: 0x%llx\n", kread64(kfd, proc + 0x48));
    kwrite64(kfd, proc+0x48, p_puniqueid);
    
    return 0;
}

int funUcred(u64 kfd, uint64_t proc) {
    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    uint64_t ucreds = kread64(kfd, proc_ro + 0x20);
    
    uint64_t cr_label_pac = kread64(kfd, ucreds + 0x78);
    uint64_t cr_label = cr_label_pac | 0xffffff8000000000;
    printf("[i] self ucred->cr_label: 0x%llx\n", cr_label);
    
    uint64_t cr_posix_p = ucreds + 0x18;
    printf("[i] self ucred->posix_cred->cr_uid: %u\n", kread32(kfd, cr_posix_p + 0));
    printf("[i] self ucred->posix_cred->cr_ruid: %u\n", kread32(kfd, cr_posix_p + 4));
    printf("[i] self ucred->posix_cred->cr_svuid: %u\n", kread32(kfd, cr_posix_p + 8));
    printf("[i] self ucred->posix_cred->cr_ngroups: %u\n", kread32(kfd, cr_posix_p + 0xc));
    printf("[i] self ucred->posix_cred->cr_groups: %u\n", kread32(kfd, cr_posix_p + 0x10));
    printf("[i] self ucred->posix_cred->cr_rgid: %u\n", kread32(kfd, cr_posix_p + 0x50));
    printf("[i] self ucred->posix_cred->cr_svgid: %u\n", kread32(kfd, cr_posix_p + 0x54));
    printf("[i] self ucred->posix_cred->cr_gmuid: %u\n", kread32(kfd, cr_posix_p + 0x58));
    printf("[i] self ucred->posix_cred->cr_flags: %u\n", kread32(kfd, cr_posix_p + 0x5c));
    
//    sleep(3);
//    kwrite32(kfd, cr_posix_p+0, 501);
//    printf("[i] self ucred->posix_cred->cr_uid: %u\n", kread32(kfd, cr_posix_p + 0));
    
//    kwrite64(kfd, cr_posix_p+0, 0);
//    kwrite64(kfd, cr_posix_p+8, 0);
//    kwrite64(kfd, cr_posix_p+16, 0);
//    kwrite64(kfd, cr_posix_p+24, 0);
//    kwrite64(kfd, cr_posix_p+32, 0);
//    kwrite64(kfd, cr_posix_p+40, 0);
//    kwrite64(kfd, cr_posix_p+48, 0);
//    kwrite64(kfd, cr_posix_p+56, 0);
//    kwrite64(kfd, cr_posix_p+64, 0);
//    kwrite64(kfd, cr_posix_p+72, 0);
//    kwrite64(kfd, cr_posix_p+80, 0);
//    kwrite64(kfd, cr_posix_p+88, 0);
    
//    setgroups(0, 0);
    return 0;
}

uint64_t funVnodeHide(u64 kfd, char* filename) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] vnode: 0x%llx\n", vnode);
    
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(kfd, vnode + off_vnode_usecount);
    uint32_t iocount = kread32(kfd, vnode + off_vnode_iocount);
    printf("[i] vnode->usecount: %d, vnode->iocount: %d\n", usecount, iocount);
    kwrite32(kfd, vnode + off_vnode_usecount, usecount + 1);
    kwrite32(kfd, vnode + off_vnode_iocount, iocount + 1);
    
#define VISSHADOW 0x008000
    //hide file
    uint32_t v_flags = kread32(kfd, vnode + off_vnode_vflags);
    printf("[i] vnode->v_flags: 0x%x\n", v_flags);
    kwrite32(kfd, vnode + off_vnode_vflags, (v_flags | VISSHADOW));

    //exist test (should not be exist
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
//    //show file
//    v_flags = kread32(kfd, vnode + off_vnode_vflags);
//    kwrite32(kfd, vnode + off_vnode_vflags, (v_flags &= ~VISSHADOW));
    
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
    close(file_index);
    
    //restore vnode iocount, usecount
    usecount = kread32(kfd, vnode + off_vnode_usecount);
    iocount = kread32(kfd, vnode + off_vnode_iocount);
    if(usecount > 0)
        kwrite32(kfd, vnode + off_vnode_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(kfd, vnode + off_vnode_iocount, iocount - 1);

    return 0;
}

uint64_t funVnodeChown(u64 kfd, char* filename, uid_t uid, gid_t gid) {
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | 0xffffff8000000000;
    uint64_t v_data = kread64(kfd, vnode + off_vnode_v_data);
    uint32_t v_uid = kread32(kfd, v_data + 0x80);
    uint32_t v_gid = kread32(kfd, v_data + 0x84);
    
    //vnode->v_data->uid
    printf("[i] Patching %s vnode->v_uid %d -> %d\n", filename, v_uid, uid);
    kwrite32(kfd, v_data+0x80, uid);
    //vnode->v_data->gid
    printf("[i] Patching %s vnode->v_gid %d -> %d\n", filename, v_gid, gid);
    kwrite32(kfd, v_data+0x84, gid);
    
    close(file_index);
    
    struct stat file_stat;
    if(stat(filename, &file_stat) == 0) {
        printf("[i] %s UID: %d\n", filename, file_stat.st_uid);
        printf("[i] %s GID: %d\n", filename, file_stat.st_gid);
    }
    
    return 0;
}

uint64_t funVnodeChmod(u64 kfd, char* filename, mode_t mode) {
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());

    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | 0xffffff8000000000;
    uint64_t v_data = kread64(kfd, vnode + off_vnode_v_data);
    uint32_t v_mode = kread32(kfd, v_data + 0x88);
    
    close(file_index);
    
    printf("[i] Patching %s vnode->v_mode %o -> %o\n", filename, v_mode, mode);
    kwrite32(kfd, v_data+0x88, mode);
    
    struct stat file_stat;
    if(stat(filename, &file_stat) == 0) {
        printf("[i] %s mode: %o\n", filename, file_stat.st_mode);
    }
    
    return 0;
}

int funCSFlags(u64 kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);

    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    uint32_t csflags = kread32(kfd, proc_ro + 0x1C);
    printf("[i] %s proc->proc_ro->csflags: 0x%x\n", process, csflags);

#define TF_PLATFORM 0x400

#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */

#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */

//    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
//    sleep(3);
//    kwrite32(kfd, proc_ro + 0x1c, csflags);

    return 0;
}

int funTask(u64 kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);
    printf("[i] %s proc: 0x%llx\n", process, proc);
    uint64_t proc_ro = kread64(kfd, proc + 0x18);

    uint64_t pr_proc = kread64(kfd, proc_ro + 0x0);
    printf("[i] %s proc->proc_ro->pr_proc: 0x%llx\n", process, pr_proc);

    uint64_t pr_task = kread64(kfd, proc_ro + 0x8);
    printf("[i] %s proc->proc_ro->pr_task: 0x%llx\n", process, pr_task);

    //proc_is64bit_data+0x18: LDR             W8, [X8,#0x3D0]
    uint32_t t_flags = kread32(kfd, pr_task + 0x3D0);
    printf("[i] %s task->t_flags: 0x%x\n", process, t_flags);


    /*
     * RO-protected flags:
     */
    #define TFRO_PLATFORM                   0x00000400                      /* task is a platform binary */
    #define TFRO_FILTER_MSG                 0x00004000                      /* task calls into message filter callback before sending a message */
    #define TFRO_PAC_EXC_FATAL              0x00010000                      /* task is marked a corpse if a PAC exception occurs */
    #define TFRO_PAC_ENFORCE_USER_STATE     0x01000000                      /* Enforce user and kernel signed thread state */
    uint32_t t_flags_ro = kread64(kfd, proc_ro + 0x78);
    printf("[i] %s proc->proc_ro->t_flags_ro: 0x%x\n", process, t_flags_ro);

    return 0;
}

uint64_t funVnodeOverwriteFile(u64 kfd, char* to, char* from) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    uint32_t off_vnode_v_mount = 0xd8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_vnode_v_kusecount = 0x5c;
    uint32_t off_vnode_v_references = 0x5b;
    uint32_t off_vnode_v_parent = 0xc0;
    uint32_t off_vnode_v_label = 0xe8;
    uint32_t off_vnode_v_cred = 0x98;
    uint32_t off_mount_mnt_data = 0x11F;
    uint32_t off_mount_mnt_fsowner = 0x9c0;
    uint32_t off_mount_mnt_fsgroup = 0x9c4;
    
    int file_index = open(to, O_RDONLY);
    if (file_index == -1) return -1;
    
    uint64_t proc = getProc(kfd, getpid());
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t to_vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode: 0x%llx\n", to, to_vnode);
    
    uint64_t to_v_mount_pac = kread64(kfd, to_vnode + off_vnode_v_mount);
    uint64_t to_v_mount = to_v_mount_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode->v_mount: 0x%llx\n", to, to_v_mount);
    uint64_t to_v_data = kread64(kfd, to_vnode + off_vnode_v_data);
    printf("[i] %s to_vnode->v_data: 0x%llx\n", from, to_v_data);
    uint64_t to_v_label = kread64(kfd, to_vnode + off_vnode_v_label);
    printf("[i] %s to_vnode->v_label: 0x%llx\n", to, to_v_label);
    
    uint8_t to_v_references = kread8(kfd, to_vnode + off_vnode_v_references);
    printf("[i] %s to_vnode->v_references: %d\n", to, to_v_references);
    uint32_t to_usecount = kread32(kfd, to_vnode + off_vnode_usecount);
    printf("[i] %s to_vnode->usecount: %d\n", to, to_usecount);
    uint32_t to_iocount = kread32(kfd, to_vnode + off_vnode_iocount);
    printf("[i] %s to_vnode->iocount: %d\n", to, to_iocount);
    uint32_t to_v_kusecount = kread32(kfd, to_vnode + off_vnode_v_kusecount);
    printf("[i] %s to_vnode->kusecount: %d\n", to, to_v_kusecount);
    uint64_t to_v_parent_pac = kread64(kfd, to_vnode + off_vnode_v_parent);
    uint64_t to_v_parent = to_v_parent_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode->v_parent: 0x%llx\n", to, to_v_parent);
    uint64_t to_v_freelist_tqe_next = kread64(kfd, to_vnode + 0x10); //v_freelist.tqe_next
    printf("[i] %s to_vnode->v_freelist.tqe_next: 0x%llx\n", to, to_v_freelist_tqe_next);
    uint64_t to_v_freelist_tqe_prev = kread64(kfd, to_vnode + 0x18); //v_freelist.tqe_prev
    printf("[i] %s to_vnode->v_freelist.tqe_prev: 0x%llx\n", to, to_v_freelist_tqe_prev);
    uint64_t to_v_mntvnodes_tqe_next = kread64(kfd, to_vnode + 0x20);   //v_mntvnodes.tqe_next
    printf("[i] %s to_vnode->v_mntvnodes.tqe_next: 0x%llx\n", to, to_v_mntvnodes_tqe_next);
    uint64_t to_v_mntvnodes_tqe_prev = kread64(kfd, to_vnode + 0x28);  //v_mntvnodes.tqe_prev
    printf("[i] %s to_vnode->v_mntvnodes.tqe_prev: 0x%llx\n", to, to_v_mntvnodes_tqe_prev);
    uint64_t to_v_ncchildren_tqh_first = kread64(kfd, to_vnode + 0x30);
    printf("[i] %s to_vnode->v_ncchildren.tqh_first: 0x%llx\n", to, to_v_ncchildren_tqh_first);
    uint64_t to_v_ncchildren_tqh_last = kread64(kfd, to_vnode + 0x38);
    printf("[i] %s to_vnode->v_ncchildren.tqh_last: 0x%llx\n", to, to_v_ncchildren_tqh_last);
    uint64_t to_v_nclinks_lh_first = kread64(kfd, to_vnode + 0x40);
    printf("[i] %s to_vnode->v_nclinks.lh_first: 0x%llx\n", to, to_v_nclinks_lh_first);
    uint64_t to_v_defer_reclaimlist = kread64(kfd, to_vnode + 0x48);    //v_defer_reclaimlist
    printf("[i] %s to_vnode->v_defer_reclaimlist: 0x%llx\n", to, to_v_defer_reclaimlist);
    uint32_t to_v_listflag = kread32(kfd, to_vnode + 0x50);    //v_listflag
    printf("[i] %s to_vnode->v_listflag: 0x%x\n", to, to_v_listflag);
    uint64_t to_v_cred_pac = kread64(kfd, to_vnode + off_vnode_v_cred);
    uint64_t to_v_cred = to_v_cred_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode->v_cred: 0x%llx\n", to, to_v_cred);
    
    uint32_t to_m_fsowner = kread32(kfd, to_v_mount + off_mount_mnt_fsowner);
    printf("[i] %s to_vnode->v_mount->mnt_fsowner: %d\n", to, to_m_fsowner);
    uint32_t to_m_fsgroup = kread32(kfd, to_v_mount + off_mount_mnt_fsgroup);
    printf("[i] %s to_vnode->v_mount->mnt_fsgroup: %d\n", to, to_m_fsgroup);
    
    
    close(file_index);
    
    file_index = open(from, O_RDONLY);
    if (file_index == -1) return -1;
    
    //get vnode
    filedesc_pac = kread64(kfd, proc + off_p_pfd);
    filedesc = filedesc_pac | 0xffffff8000000000;
    openedfile = kread64(kfd, filedesc + (8 * file_index));
    fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    fileglob = fileglob_pac | 0xffffff8000000000;
    vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t from_vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode: 0x%llx\n", from, from_vnode);
    
    
    
    uint64_t from_v_mount_pac = kread64(kfd, from_vnode + off_vnode_v_mount);
    uint64_t from_v_mount = from_v_mount_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode->v_mount: 0x%llx\n", from, from_v_mount);
    uint64_t from_v_data = kread64(kfd, from_vnode + off_vnode_v_data);
    printf("[i] %s from_vnode->v_data: 0x%llx\n", from, from_v_data);
    uint64_t from_v_label = kread64(kfd, from_vnode + off_vnode_v_label);
    printf("[i] %s from_vnode->v_label: 0x%llx\n", from, from_v_label);
    uint8_t from_v_references = kread8(kfd, from_vnode + off_vnode_v_references);
    printf("[i] %s from_vnode->v_references: %d\n", from, from_v_references);
    uint32_t from_usecount = kread32(kfd, from_vnode + off_vnode_usecount);
    printf("[i] %s from_vnode->usecount: %d\n", from, from_usecount);
    uint32_t from_iocount = kread32(kfd, from_vnode + off_vnode_iocount);
    printf("[i] %s from_vnode->iocount: %d\n", from, from_iocount);
    uint32_t from_v_kusecount = kread32(kfd, from_vnode + off_vnode_v_kusecount);
    printf("[i] %s from_vnode->kusecount: %d\n", from, from_v_kusecount);
    uint64_t from_v_parent_pac = kread64(kfd, from_vnode + off_vnode_v_parent);
    uint64_t from_v_parent = from_v_parent_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode->v_parent: 0x%llx\n", from, from_v_parent);
    uint64_t from_v_freelist_tqe_next = kread64(kfd, from_vnode + 0x10); //v_freelist.tqe_next
    printf("[i] %s from_vnode->v_freelist.tqe_next: 0x%llx\n", from, from_v_freelist_tqe_next);
    uint64_t from_v_freelist_tqe_prev = kread64(kfd, from_vnode + 0x18); //v_freelist.tqe_prev
    printf("[i] %s from_vnode->v_freelist.tqe_prev: 0x%llx\n", from, from_v_freelist_tqe_prev);
    uint64_t from_v_mntvnodes_tqe_next = kread64(kfd, from_vnode + 0x20);   //v_mntvnodes.tqe_next
    printf("[i] %s from_vnode->v_mntvnodes.tqe_next: 0x%llx\n", from, from_v_mntvnodes_tqe_next);
    uint64_t from_v_mntvnodes_tqe_prev = kread64(kfd, from_vnode + 0x28);  //v_mntvnodes.tqe_prev
    printf("[i] %s from_vnode->v_mntvnodes.tqe_prev: 0x%llx\n", from, from_v_mntvnodes_tqe_prev);
    uint64_t from_v_ncchildren_tqh_first = kread64(kfd, from_vnode + 0x30);
    printf("[i] %s from_vnode->v_ncchildren.tqh_first: 0x%llx\n", from, from_v_ncchildren_tqh_first);
    uint64_t from_v_ncchildren_tqh_last = kread64(kfd, from_vnode + 0x38);
    printf("[i] %s from_vnode->v_ncchildren.tqh_last: 0x%llx\n", from, from_v_ncchildren_tqh_last);
    uint64_t from_v_nclinks_lh_first = kread64(kfd, from_vnode + 0x40);
    printf("[i] %s from_vnode->v_nclinks.lh_first: 0x%llx\n", from, from_v_nclinks_lh_first);
    uint64_t from_v_defer_reclaimlist = kread64(kfd, from_vnode + 0x48);    //v_defer_reclaimlist
    printf("[i] %s from_vnode->v_defer_reclaimlist: 0x%llx\n", from, from_v_defer_reclaimlist);
    uint32_t from_v_listflag = kread32(kfd, from_vnode + 0x50);    //v_listflag
    printf("[i] %s from_vnode->v_listflag: 0x%x\n", from, from_v_listflag);
    uint64_t from_v_cred_pac = kread64(kfd, from_vnode + off_vnode_v_cred);
    uint64_t from_v_cred = from_v_cred_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode->v_cred: 0x%llx\n", from, from_v_cred);
    
//    close(file_index);
    
    sleep(1);
    
    //mnt_devvp
    kwrite64(kfd, to_v_mount + 0x980, kread64(kfd, from_v_mount + 0x980));
    //mnt_data
//    kwrite64(kfd, to_v_mount + 0x8f8, kread64(kfd, from_v_mount + 0x8f8));
    //mnt_kern_flag
    kwrite32(kfd, to_v_mount + 0x74, kread32(kfd, from_v_mount + 0x74));
    //mnt_vfsstat
    uint64_t from_m_vfsstat = from_v_mount + 0x84;
    uint64_t to_m_vfsstat = to_v_mount + 0x84;
    kwrite32(kfd, to_m_vfsstat, kread32(kfd, from_m_vfsstat));
    kwrite32(kfd, to_m_vfsstat + 0x4, kread32(kfd, from_m_vfsstat + 0x4));
    kwrite64(kfd, to_m_vfsstat + 0x8, kread32(kfd, from_m_vfsstat + 0x8));
    kwrite64(kfd, to_m_vfsstat + 0x10, kread32(kfd, from_m_vfsstat + 0x10));
    kwrite64(kfd, to_m_vfsstat + 0x18, kread32(kfd, from_m_vfsstat + 0x18));
    kwrite64(kfd, to_m_vfsstat + 0x20, kread32(kfd, from_m_vfsstat + 0x20));
    kwrite64(kfd, to_m_vfsstat + 0x28, kread32(kfd, from_m_vfsstat + 0x28));
    kwrite64(kfd, to_m_vfsstat + 0x30, kread32(kfd, from_m_vfsstat + 0x30));
    
    //mnt_flag
    uint32_t from_m_flag = kread32(kfd, from_v_mount + 0x70);
    uint32_t to_m_flag = kread32(kfd, to_v_mount + 0x70);
    
    kwrite64(kfd, to_vnode + 0x20, from_v_mntvnodes_tqe_next);
    kwrite64(kfd, to_vnode + 0x28, from_v_mntvnodes_tqe_prev);
    
#define VISHARDLINK     0x100000
#define MNT_RDONLY      0x00000001
    kwrite32(kfd, to_vnode+off_vnode_vflags, kread32(kfd, to_vnode+off_vnode_vflags) & (~(0x1<<6)));
//    kwrite32(kfd, to_v_mount + 0x70, to_m_flag & (~(0x1<<6)));
    
    printf("from_m_flag: 0x%x, to_m_flag: 0x%lx\n", from_m_flag, to_m_flag);
    
    
//    uint32_t* p_bsize = (uint32_t*)((uintptr_t)&vfs + 0);
//        size_t* p_iosize = (size_t*)((uintptr_t)&vfs + 4);
//        uint64_t* p_blocks = (uint64_t*)((uintptr_t)&vfs + 8);
//        uint64_t* p_bfree = (uint64_t*)((uintptr_t)&vfs + 16);
//        uint64_t* p_bavail = (uint64_t*)((uintptr_t)&vfs + 24);
//        uint64_t* p_bused = (uint64_t*)((uintptr_t)&vfs + 32);
//        uint64_t* p_files = (uint64_t*)((uintptr_t)&vfs + 40);
//        uint64_t* p_ffree = (uint64_t*)((uintptr_t)&vfs + 48);
    
//    kwrite64(kfd, to_vnode + off_vnode_v_data, 0);
//    sleep(1);
    kwrite64(kfd, to_vnode + off_vnode_v_data, from_v_data);
//    kwrite64(kfd, to_v_data + 0x10, kread64(kfd, from_v_data + 0x10));
//    kwrite64(kfd, to_v_data + 0x18, kread64(kfd, from_v_data + 0x18));
//    kwrite64(kfd, to_v_data + 0x20, kread64(kfd, from_v_data + 0x20));
//    kwrite64(kfd, to_v_data + 0x30, kread64(kfd, from_v_data + 0x30));
//    kwrite64(kfd, to_v_data + 0xc0, kread64(kfd, from_v_data + 0xc0));
//    kwrite64(kfd, to_v_data + 0x130, kread64(kfd, from_v_data + 0x130));
//    kwrite64(kfd, to_v_data + 0x148, kread64(kfd, from_v_data + 0x148));
//    kwrite64(kfd, to_v_data + 0x150, kread64(kfd, from_v_data + 0x150));
//    kwrite64(kfd, to_v_data + 0x1b8, kread64(kfd, from_v_data + 0x1b8));
//    kwrite64(kfd, to_v_data + 0x1c0, kread64(kfd, from_v_data + 0x1c0));
//    kwrite64(kfd, to_v_data + 0x1d0, kread64(kfd, from_v_data + 0x1d0));
    
//    kwrite64(kfd, to_v_data + 0x20, kread64(kfd, from_v_data+0x20));
    
//        kwrite32(kfd, to_vnode + off_vnode_iocount, from_usecount + 1);

    kwrite32(kfd, to_vnode + off_vnode_usecount, to_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);

//        kwrite64(kfd, to_vnode + 0x10, from_v_freelist_tqe_next);
//        kwrite64(kfd, to_vnode + 0x18, from_v_freelist_tqe_prev);
//        kwrite64(kfd, to_vnode + 0x20, from_v_mntvnodes_tqe_next);
//        kwrite64(kfd, to_vnode + 0x28, from_v_mntvnodes_tqe_prev);
//        kwrite64(kfd, to_vnode + 0x30, from_v_ncchildren_tqh_first);
//        kwrite64(kfd, to_vnode + 0x38, from_v_ncchildren_tqh_last);
//        kwrite64(kfd, to_vnode + 0x40, from_v_nclinks_lh_first);
    
    
//    //v_data = (struct apfs_fsnode, closed-source...)
//    //    from_fd_vnode = kread64(kfd, from_v_data + 32);
//    printf("[i] vnode, %s from_vnode->v_data->fd_vnode: 0x%llx\n", from, from_fd_vnode);// <- vnode

    return 0;
}

uint64_t funVnodeRedirectFolder(u64 kfd, char* to, char* from) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    uint32_t off_vnode_v_mount = 0xd8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_vnode_v_kusecount = 0x5c;
    uint32_t off_vnode_v_references = 0x5b;
    uint32_t off_vnode_v_parent = 0xc0;
    uint32_t off_vnode_v_label = 0xe8;
    uint32_t off_vnode_v_cred = 0x98;
    uint32_t off_mount_mnt_fsowner = 0x9c0;
    uint32_t off_mount_mnt_fsgroup = 0x9c4;

    int file_index = open(to, O_RDONLY);
    if (file_index == -1) return -1;

    uint64_t proc = getProc(kfd, getpid());

    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t to_vnode = vnode_pac | 0xffffff8000000000;

    uint8_t to_v_references = kread8(kfd, to_vnode + off_vnode_v_references);
    uint32_t to_usecount = kread32(kfd, to_vnode + off_vnode_usecount);
    uint32_t to_v_kusecount = kread32(kfd, to_vnode + off_vnode_v_kusecount);

    close(file_index);

    file_index = open(from, O_RDONLY);
    if (file_index == -1) return -1;

    filedesc_pac = kread64(kfd, proc + off_p_pfd);
    filedesc = filedesc_pac | 0xffffff8000000000;
    openedfile = kread64(kfd, filedesc + (8 * file_index));
    fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    fileglob = fileglob_pac | 0xffffff8000000000;
    vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t from_vnode = vnode_pac | 0xffffff8000000000;
    uint64_t from_v_data = kread64(kfd, from_vnode + off_vnode_v_data);

    close(file_index);

    kwrite32(kfd, to_vnode + off_vnode_usecount, to_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);
    kwrite64(kfd, to_vnode + off_vnode_v_data, from_v_data);

    return 0;
}

//TODO: Redirect /System/Library/PrivateFrameworks/TCC.framework/Support/ -> NSHomeDirectory(), @"/Documents/mounted"
//Current: Redirect /var -> NSHomeDirectory(), @"/Documents/mounted"
void ls(u64 kfd, id path) {
//    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), path];
    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
    [[NSFileManager defaultManager] removeItemAtPath:mntPath error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:mntPath withIntermediateDirectories:NO attributes:nil error:nil];
    funVnodeRedirectFolder(kfd, mntPath.UTF8String, "/"); // redirect root from the mount path?
    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
    NSLog(@"/var directory: %@", dirs);
}

int do_fun(u64 kfd) {
    uint64_t kslide = ((struct kfd*)kfd)->perf.kernel_slide;
    uint64_t kbase = 0xfffffff007004000 + kslide;
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    uint64_t kheader64 = kread64(kfd, kbase);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kheader64);
    
    pid_t myPid = getpid();
    uint64_t selfProc = getProc(kfd, myPid);
    printf("[i] self proc: 0x%llx\n", selfProc);
    
    funUcred(kfd, selfProc);
    funProc(kfd, selfProc);
//    funVnodeHide(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    print("hiding home bar\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/MaterialKit.framework/Assets.car");
    print("hiding dock\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoreMaterial.framework/dockDark.materialrecipe");
//    funVnodeOverwrite(kfd, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", "/System/Library/AppPlaceholders/Tips.app/AppIcon60x60@2x.png"); // replace destination from targeted
//    funCSFlags(kfd, "launchd");
//    funTask(kfd, "kfd");
    
//    print("[i] chowning tccd to user NOW\n\n");
//    //Patch
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);
//
//    print("[i] chowning tccd to root NOW\n\n");
//    //Restore
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0, 0);
//
//    print("[i] chmodding tccd to 777 NOW\n\n");
//    //Patch
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0107777);
//
//    print("[i] chmodding tccd to 755 NOW\n\n");
//    //Restore
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);

    //ls(kfd, @"\"@/Documents/mounted\"");
    //    NSString *AAAApath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/AAAA.bin"];
    //    remove(AAAApath.UTF8String);
    //    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/AAAA.bin"] toPath:AAAApath error:nil];
    //
    //    NSString *BBBBpath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/BBBB.bin"];
    //    remove(BBBBpath.UTF8String);
    //    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/AAAA.bin"] toPath:BBBBpath error:nil];
        
        
    //    funVnodeOverwriteFile(kfd, mntPath.UTF8String, "/var/mobile/Library/Caches/com.apple.keyboards");
    //    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/AAAA.bin"] toPath:[NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted/images/BBBB.bin"] error:nil];
        
    //    symlink("/System/Library/PrivateFrameworks/TCC.framework/Support/", [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/Support"].UTF8String);
    //    mount("/System/Library/PrivateFrameworks/TCC.framework/Support/", mntPath, NULL, MS_BIND | MS_REC, NULL);
    //    printf("mount ret: %d\n", mount("apfs", mntpath, 0, &mntargs))
    //    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 501, 501);
    //    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 0107777);


    //    funVnodeOverwriteFile(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", AAAApath.UTF8String);
    //    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);
    //    funVnodeOverwriteFile(kfd, AAAApath.UTF8String, BBBBpath.UTF8String);
    //    funVnodeOverwriteFile(kfd, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", "/System/Library/AppPlaceholders/Tips.app/AppIcon60x60@2x.png");
        
    //    xpc_crasher("com.apple.tccd");
    //    xpc_crasher("com.apple.tccd");
    //    sleep(10);
    //    funUcred(kfd, getProc(kfd, getPidByName(kfd, "tccd")));
    //    funProc(kfd, getProc(kfd, getPidByName(kfd, "tccd")));
    //    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);
        
        
    //    funVnodeOverwrite(kfd, AAAApath.UTF8String, AAAApath.UTF8String);
        
    //    funVnodeOverwrite(kfd, selfProc, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", copyToAppDocs.UTF8String);
    
    //funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/lock.caf", "/System/Library/Audio/UISounds/connect_power.caf");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/key_press_click.caf", "/System/Library/Audio/UISounds/lock.caf");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/lock.caf", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/vineboom.caf");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/PrivateFrameworks/FocusUI.framework/dnd_cg_02.ca/main.caml", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/focusmain.caml");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca/main.caml", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/lpmmain.caml");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/PrivateFrameworks/MediaControls.framework/Volume.ca/main.caml", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/mainvolume.caml");
    
    //funVnodeOverwriteFile(kfd, "/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Bluetooth.ca/main.caml", "/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/mainbluetooth.caml");

    
    //funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/photoShutter.caf", "/System/Library/Audio/UISounds/lock.caf"); // DC4597C3-66C4-4717-BC0F-CE9E3937F490

    //Overwrite tccd:
    //    NSString *copyToAppDocs = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/tccd_patched.bin"];
    //    remove(copyToAppDocs.UTF8String);
    //    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/tccd_patched.bin"] toPath:copyToAppDocs error:nil];
    //    chmod(copyToAppDocs.UTF8String, 0755);
    //    funVnodeOverwrite(kfd, selfProc, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", [copyToAppDocs UTF8String]);
        
    //    xpc_crasher("com.apple.tccd");
    //    xpc_crasher("com.apple.tccd");

//    func overwriteBlacklist() -> Bool {
//        return overwriteFileWithDataImpl(originPath: "/private/var/db/MobileIdentityData/Rejections.plist", replacementData: try! Data(base64Encoded: blankplist)!)
//    }
//
//    func overwriteBannedApps() -> Bool {
//        return overwriteFileWithDataImpl(originPath: "/private/var/db/MobileIdentityData/AuthListBannedUpps.plist", replacementData: try! Data(base64Encoded: blankplist)!)
//    }
//
//    func overwriteCdHashes() -> Bool {
//        return overwriteFileWithDataImpl(originPath: "/private/var/db/MobileIdentityData/AuthListBannedCdHashes.plist", replacementData: try! Data(base64Encoded: blankplist)!)
//    } let blankplist = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdC8+CjwvcGxpc3Q+Cg=="
    print("done!!!\n");
    do_kclose(kfd);
    do_respring();
    return 0;
}

