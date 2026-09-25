#ifndef PBF_CLR_HOST_H
#define PBF_CLR_HOST_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <oleauto.h>

HRESULT __stdcall pbf_clr_execute_parameterless(
    const BYTE *assembly_bytes,
    ULONG assembly_size,
    LONG *managed_result);

#endif
