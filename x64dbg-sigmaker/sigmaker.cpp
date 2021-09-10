#include "sigmaker.h"

#include <pluginsdk/_scriptapi.h>
#include <distorm.h>
#include <array>

#pragma warning (disable: 26812)

bool sig_make(duint address, sig_vec &out_result)
{
	auto paddress = reinterpret_cast<std::uint8_t *>(address);

	// Read instruction from the process that's being debugged
	constexpr auto read_len = 20; // Number of bytes to read from the target process
	std::array<std::uint8_t, read_len> dbg_read_buff;
	if (!DbgMemRead(address, dbg_read_buff.data(), read_len))
	{
		W_PLUG_LOG_S("Failed to read memory of target process.");
		return false;
	}

	std::array<_DInst, 15> decomp      = { 0 };
	unsigned int           inst_count  = 0;
	_CodeInfo ci =
	{
		.codeOffset = 0,
		.code       = dbg_read_buff.data(),
		.codeLen    = read_len,

		#ifdef _M_IX86
		.dt = Decode32Bits,
		#elif _M_X64
		.dt = Decode64Bits,
		#endif
	};

	// Decompose byte array of instructions
	auto decomp_result = distorm_decompose(&ci, decomp.data(), decomp.size(), &inst_count);
	if (decomp_result == _DecodeResult::DECRES_MEMORYERR)
	{
		W_PLUG_LOG_S("Decompose failed: MEMORY ERROR (Ignoring anyway)");
	}
	else
	{
		switch (decomp_result)
		{
			case _DecodeResult::DECRES_INPUTERR:
				W_PLUG_LOG_S("Decompose failed: INPUT ERROR");
				return false;
			case _DecodeResult::DECRES_NONE:
				W_PLUG_LOG_S("Decompose failed: what?");
				return false;
		}
	}

	for (auto i = 0ul; i < inst_count; i++)
	{
		const _DInst &inst = decomp[i];

		if (inst.flags == FLAG_NOT_DECODABLE)
		{
			W_PLUG_LOG_S("Couldn't decode message!");
			continue;
		}

		char log_buff[512] = { 0x00 };
		_DecodedInst di;
		distorm_format(&ci, &inst, &di);

		sprintf_s(log_buff, "\n> %s %s | %d", di.mnemonic.p, di.operands.p, inst.size);

		GuiAddLogMessage(log_buff);
	}

	return true;
}

bool sig_vec2aob(sig_vec &sig, std::string &out_result)
{
	return false;
}

bool sig_vec2ida(sig_vec &sig, std::string &out_result)
{
	return false;
}

bool sig_vec2ida2(sig_vec &sig, std::string &out_result)
{
	return false;
}

#pragma warning (default: 26812)