#pragma once

#include "global.h"
#include <vector>

#define PLUG_NAME "Signature Maker"
#define PLUG_VERSION 1

// Log message wrapper for static messages
#define W_PLUG_LOG_S(msg) GuiAddLogMessage("\n[" PLUG_NAME "] " msg "\n")

struct menu_entry
{
    enum : int
    {
        MAKE_AOB,
        MAKE_IDA,
        MAKE_IDA2,
    };
};

struct sig_frag
{
    std::uint8_t byte;
    bool mask;
};
using sig_vec = std::vector<sig_frag>;

bool sig_make(duint address, sig_vec &out_result);

bool sig_vec2aob(sig_vec &sig, std::string &out_result);
bool sig_vec2ida(sig_vec &sig, std::string &out_result);
bool sig_vec2ida2(sig_vec &sig, std::string &out_result);