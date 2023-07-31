//
//  fun.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>

int do_fun(uint64_t kfd);
uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method);
void do_kclose(uint64_t kfd);
void do_respring();
void hide_lsicons(uint64_t kfd);
void hide_homebar(uint64_t kfd);
void hide_darkmode_dock(uint64_t kfd);
void hide_lightmode_dock(uint64_t kfd);

#endif /* fun_h */
