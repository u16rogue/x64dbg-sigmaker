
#if defined(_M_IX86)
    #pragma comment(lib, "../pluginsdk/x32bridge.lib")
    #pragma comment(lib, "../pluginsdk/x32dbg.lib")
#elif defined(_M_X64)
    #pragma comment(lib, "../pluginsdk/x64bridge.lib")
    #pragma comment(lib, "../pluginsdk/x64dbg.lib")
#endif

#include <Windows.h>
#include <pluginsdk/_plugins.h>
#include <string.h>
#include "global.h"

#define PLUG_EXPORT extern "C" __declspec(dllexport)

PLUG_EXPORT BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        global::hmod = hModule;

    return TRUE;
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, "x64dbg_sigmaker");
    global::plugin_handle = initStruct->pluginHandle;

    return true;
}

PLUG_EXPORT bool plugsetup(PLUG_SETUPSTRUCT *setupStruct)
{
    global::dlg         = setupStruct->hwndDlg;
    global::menu        = setupStruct->hMenu;
    global::menu_disasm = setupStruct->hMenuDisasm;
    global::menu_dump   = setupStruct->hMenuDump;
    global::menu_stack  = setupStruct->hMenuStack;

    return true;
}
