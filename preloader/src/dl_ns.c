#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <link.h>
#include <dlfcn.h>
#include <assert.h>

void* _early_preload_dso(const char* dso) {
  void* handle = dlmopen(LM_ID_NEWLM, dso, RTLD_LAZY);
  Lmid_t id = 0;

  assert(dlinfo(handle, RTLD_DI_LMID, &id) == 0);

  return handle;
}
