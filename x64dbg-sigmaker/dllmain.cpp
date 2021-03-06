#include "global.h"
#include "sigmaker.h"

PLUG_EXPORT BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        global::hmod = hModule;

    return TRUE;
}

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *init)
{
    init->pluginVersion = PLUG_VERSION;
    init->sdkVersion    = PLUG_SDKVERSION;
    strcpy_s(init->pluginName, PLUG_NAME);
    global::plugin_handle = init->pluginHandle;

    return true;
}

PLUG_EXPORT bool plugsetup(PLUG_SETUPSTRUCT *setup)
{
    global::dlg         = setup->hwndDlg;
    global::menu        = setup->hMenu;
    global::menu_disasm = setup->hMenuDisasm;
    global::menu_dump   = setup->hMenuDump;
    global::menu_stack  = setup->hMenuStack;

    _plugin_menuaddentry(setup->hMenuDisasm, menu_entry::MAKE_AOB,  "Make: AOB");
    _plugin_menuaddentry(setup->hMenuDisasm, menu_entry::MAKE_IDA,  "Make: IDA");
    _plugin_menuaddentry(setup->hMenuDisasm, menu_entry::MAKE_IDA2, "Make: IDA (Double wildcard)");

    return true;
}

#pragma warning(disable: 26812)

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY *info)
{
    bool (*sig_vec2str)(sig_vec&, std::string&);
    switch (info->hEntry)
    {
        case menu_entry::MAKE_IDA2:
            sig_vec2str = sig_vec2ida2;
            break;
        case menu_entry::MAKE_IDA:
            sig_vec2str = sig_vec2ida;
            break;
        case menu_entry::MAKE_AOB:
            sig_vec2str = sig_vec2aob;
            break;
        default:
            sig_vec2str = nullptr;
            break;
    }

    if (sig_vec2str == nullptr) {
        W_PLUG_LOG_S("No menu entry matched.");
        return;
    }

    SELECTIONDATA sd;
    if (!GuiSelectionGet(GUISELECTIONTYPE::GUI_DISASSEMBLY, &sd))
    {
        W_PLUG_LOG_S("Failed to obtain disassembly selection data.");
        return;
    }

    sig_vec signature;
    if (!sig_make(sd.start, signature))
    {
        W_PLUG_LOG_S("Failed to generate a signature!");
        return;
    }

    std::string sig_str;
    if (!sig_vec2str(signature, sig_str))
    {
        W_PLUG_LOG_S("Failed to convert signature to specified style.");
        return;
    }

    #ifdef _M_IX86
    #define RES_HEX_FMT "0x%lx"
    #elif _M_X64
    #define RES_HEX_FMT "0x%llx"
    #endif

    char buffer[256];
    sprintf_s(buffer, "\n[" PLUG_NAME "] " RES_HEX_FMT " = %s\n", sd.start, sig_str.c_str());
    GuiAddLogMessage(buffer);
}

#pragma warning(default: 26812)