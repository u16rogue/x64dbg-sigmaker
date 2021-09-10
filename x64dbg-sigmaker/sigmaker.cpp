#include "sigmaker.h"

#include <pluginsdk/_scriptapi.h>
#include <distorm.h>
#include <mnemonics.h>
#include <array>
#include <string>

#pragma warning (disable: 26812)

// Determines the operands of an instruction. The following checks are made to determine how
// many bytes from right to left should become a wildcard.
//
// Reasoning: Observing how instructions are laid out, values that could change on compile time
// such as offsets, pointers, etc... are always placed at the right most area of bytes that comprises the instruction
// ex. JMP 0x00000000 is equivalent to  E9 00 00 00 00, the relative address is always at the right. Almost all instructions
// follow this, so all we need to do is to determine how many bytes from the right should become a wildcard with this we can
// get the entire instruction size, subtract the result from this function, copy the amount of bytes from the resulting difference
// then the rest are just wildcards.
static std::size_t determine_operand_wildcard_count(const _DInst &instruction)
{
	std::size_t byte_count = 0;
	for (auto i = 0; i < instruction.opsNo; i++)
	{
		const _Operand &opr = instruction.ops[i];
		switch (opr.type)
		{
			case O_IMM:
			case O_IMM1:
			case O_IMM2:
			case O_DISP:
			case O_SMEM:
			case O_MEM:
			case O_PC:
			case O_PTR:
				byte_count += opr.size / 8;
				break;
		}
	}

	return byte_count;
}

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

	// Instruction parsing
	for (auto i_ins = 0ul; i_ins < inst_count; i_ins++)
	{
		const _DInst &inst = decomp[i_ins];

		if (inst.flags == FLAG_NOT_DECODABLE)
		{
			// we don't care if the last instruction can't be decoded since we can just discard it
			if (i_ins == inst_count - 1)
				continue;

			// it only matters when it could affect the resulting pattern
			W_PLUG_LOG_S("Couldn't decode message!");
			return false;
		}

		#ifdef _DEBUG
		{
			char log_buff[512] = { 0x00 };
			_DecodedInst di;
			distorm_format(&ci, &inst, &di);
			sprintf_s(log_buff, "\n> %s %s | Size: %d | Opcode: %d | Operands (%d): %d[%d] %d[%d] %d[%d] %d[%d] | Wildcard count: %d",
				di.mnemonic.p, di.operands.p,
				inst.size,
				inst.opcode,
				inst.opsNo,
				inst.ops[0].type, inst.ops[0].size,
				inst.ops[1].type, inst.ops[1].size,
				inst.ops[2].type, inst.ops[2].size,
				inst.ops[3].type, inst.ops[3].size,
				determine_operand_wildcard_count(inst)
			);
			GuiAddLogMessage(log_buff);
		}
		#endif

		const auto c_wildcard = determine_operand_wildcard_count(inst);
		// TODO: start filling up patterns
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