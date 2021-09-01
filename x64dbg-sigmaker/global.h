#pragma once

#if defined(_M_IX86)
    #pragma comment(lib, "../pluginsdk/x32bridge.lib")
    #pragma comment(lib, "../pluginsdk/x32dbg.lib")
#elif defined(_M_X64)
    #pragma comment(lib, "../pluginsdk/x64bridge.lib")
    #pragma comment(lib, "../pluginsdk/x64dbg.lib")
#endif

#include <Windows.h>
#include <pluginsdk/_plugins.h>
#include <cstdint>

namespace global
{
    // GLOBAL Plugin SDK variables
    inline static void   *hmod = nullptr;
    inline static int     plugin_handle;
    inline static void   *dlg;
    inline static int     menu;
    inline static int     menu_disasm;
    inline static int     menu_dump;
    inline static int     menu_stack;
}