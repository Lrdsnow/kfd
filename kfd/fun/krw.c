//
//  krw.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/29.
//

#include "krw.h"
#include "libkfd.h"
#include "helpers.h"

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

uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method)
{
    return kopen(puaf_pages, puaf_method, kread_method, kwrite_method);
}

void do_kclose(u64 kfd)
{
    kclose((struct kfd*)(kfd));
}

void do_kread(u64 kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread(kfd, kaddr, uaddr, size);
}

void do_kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size)
{
    kwrite(kfd, uaddr, kaddr, size);
}

uint64_t get_kslide(uint64_t kfd) {
    return ((struct kfd*)kfd)->perf.kernel_slide;
}

uint64_t get_kernproc(uint64_t kfd) {
    return ((struct kfd*)kfd)->info.kaddr.kernel_proc;
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
