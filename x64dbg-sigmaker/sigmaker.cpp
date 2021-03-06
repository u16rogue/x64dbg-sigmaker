#include "sigmaker.h"

#include <pluginsdk/_scriptapi.h>
#include <mnemonics.h>
#include <array>
#include <string>
#include <memory>

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

// Takes the starting address of the pattern, determines which module it belongs in the target process, determines the size
// of the module, reads the entire module into a buffer, then returns a tuple containing the buffer, the size of the buffer, and the RVA of address.
// <module buffer, module size, RVA of va_addr >
static std::tuple<std::unique_ptr<std::uint8_t[]>, duint, duint> load_module_memory_to_buffer(duint va_addr)
{
	// Determine which module the address belongs to and determine the size of the module
	duint mod_size = 0;
	duint mod_base = DbgMemFindBaseAddr(va_addr, &mod_size);
	if (!mod_base || !mod_size)
	{
		W_PLUG_LOG_S("load_module_memory_to_buffer ## Failed to find module.");
		return { nullptr, 0, 0 };
	}

	// Create the buffer
	auto buffer = std::make_unique<std::uint8_t[]>(mod_size);
	if (!buffer)
	{
		W_PLUG_LOG_S("load_module_memory_to_buffer ## Failed to allocate module buffer.");
		return { nullptr, 0, 0 };
	}

	// Load the entire module from the target process into the buffer
	if (!DbgMemRead(mod_base, buffer.get(), mod_size))
	{
		W_PLUG_LOG_S("load_module_memory_to_buffer ## Failed to read module to buffer.");
		return { nullptr, 0, 0 };
	}

	return std::make_tuple(std::move(buffer), mod_size, va_addr - mod_base);
}

// Decomposes the array of bytes that represent the instructions and returns the decomposed instructions and number
// of instructions decomposed.
static std::tuple<std::unique_ptr<_DInst[]>, unsigned int> decompose_instructions(std::uint8_t *ins_buffer, int nbytes_to_decompose, int ninst_to_store)
{
	auto dinst_buff = std::make_unique<_DInst[]>(ninst_to_store);
	if (!dinst_buff)
	{
		W_PLUG_LOG_S("decompose_instructions ## Failed to allocate decomposed instructions buffer");
		return { nullptr, 0 };
	}

	unsigned int inst_count = 0;
	_CodeInfo ci =
	{
		.codeOffset = 0,
		.code       = ins_buffer,
		.codeLen    = nbytes_to_decompose,

		#ifdef _M_IX86
		.dt = Decode32Bits,
		#elif _M_X64
		.dt = Decode64Bits,
		#endif
	};

	// Decompose byte array of instructions
	auto decomp_result = distorm_decompose(&ci, dinst_buff.get(), ninst_to_store, &inst_count);
	if (decomp_result == _DecodeResult::DECRES_MEMORYERR)
	{
		W_PLUG_LOG_S("decompose_instructions ## MEMORY ERROR (Ignoring anyway)");
	}
	else
	{
		switch (decomp_result)
		{
			case _DecodeResult::DECRES_INPUTERR:
				W_PLUG_LOG_S("decompose_instructions ## INPUT ERROR");
				return { nullptr, 0 };
			case _DecodeResult::DECRES_NONE:
				W_PLUG_LOG_S("decompose_instructions ## what?");
				return { nullptr, 0 };
		}
	}

	return std::make_tuple(std::move(dinst_buff), inst_count);
}

static std::uint8_t *sig_scan(std::uint8_t *buffer, duint rva, sig_vec &pattern)
{
	const auto pat_size = pattern.size();
	// use the RVA as the size of the module as there is no need to scan beyond the RVA for patterns
	for (duint i_buff = 0; i_buff <= rva; i_buff++)
	{
		for (std::size_t i_patt = 0; i_patt < pat_size; i_patt++)
		{
			if (pattern[i_patt].mask == false)
				continue;

			if (buffer[i_buff + i_patt] != pattern[i_patt].byte)
				break;

			if (i_patt == (pat_size - 1))
				return buffer + i_buff;
		}
	}

	return nullptr;
}

bool sig_make(duint address, sig_vec &out_result)
{
	auto paddress = reinterpret_cast<std::uint8_t *>(address);

	// Read instruction from the process that's being debugged
	auto [mod_buff, mod_size, rva] = load_module_memory_to_buffer(address);
	if (!mod_buff || !mod_size || !rva)
	{
		W_PLUG_LOG_S("Failed to read target.");
		return false;
	}

	std::uint8_t *trans_va = &mod_buff[rva]; // translated virtual address based off the local buffer using the RVA from the original virtual address in the target process

	auto [decomp_ins, decomp_count] = decompose_instructions(trans_va, NBYTES_TO_SIG, NBYTES_TO_SIG /* this is bloat, a proper impl would be to check how many instructions are there first. */);
	if (!decomp_ins || !decomp_count)
	{
		W_PLUG_LOG_S("Failed to decompose instructions.");
		return false;
	}

	// Instruction parsing
	sig_vec full_pattern;
	for (auto i_ins = 0ul; i_ins < decomp_count; i_ins++)
	{
		const _DInst &inst = decomp_ins[i_ins];

		if (inst.flags == FLAG_NOT_DECODABLE)
		{
			W_PLUG_LOG_S("Couldn't decode message! Ending instruction parsing.");
			break;
		}

		const auto c_wildcard = determine_operand_wildcard_count(inst);
		
		for (auto i_ins_b = 0ul; i_ins_b < inst.size; i_ins_b++)
		{
			if (i_ins_b < inst.size - c_wildcard)
				full_pattern.emplace_back(trans_va[i_ins_b], true);
			else
				full_pattern.emplace_back(0x00, false);
		}
		trans_va += inst.size;
	}

	// Pattern testing
	trans_va = &mod_buff[rva];
	for (auto &patt : full_pattern)
	{
		// Slowly copy full_pattern to out_result until we get a unique signature
		out_result.emplace_back(patt);

		if (patt.mask == false)
			continue;

		if (sig_scan(mod_buff.get(), rva, out_result) == trans_va)
			return true;
	}

	return false;
}

bool sig_vec2aob(sig_vec &sig, std::string &out_result)
{
	std::string mask;
	for (auto &s : sig)
	{
		if (s.mask)
		{
			char hex[8] = { 0 };
			sprintf_s(hex, "\\x%02X", s.byte);
			out_result.append(hex);
			mask.append("x");
		}
		else
		{
			out_result.append("\\x00");
			mask.append("?");
		}
	}

	out_result.append(" ");
	out_result.append(mask);

	return true;
}

bool sig_vec2ida(sig_vec &sig, std::string &out_result)
{
	const auto sig_s = sig.size();
	for (std::size_t i = 0; i < sig_s; i++)
	{
		const auto &s = sig[i];

		if (s.mask)
		{
			char hex[8] = { 0 };
			sprintf_s(hex, "%02X", s.byte);
			out_result.append(hex);
		}
		else
		{
			out_result.append("?");
		}

		if (i != sig_s - 1)
			out_result.append(" ");
	}

	return true;
}

// TODO: Can merge sig_vec2ida2 and sig_vec2ida

bool sig_vec2ida2(sig_vec &sig, std::string &out_result)
{
	const auto sig_s = sig.size();
	for (std::size_t i = 0; i < sig_s; i++)
	{
		const auto &s = sig[i];

		if (s.mask)
		{
			char hex[8] = { 0 };
			sprintf_s(hex, "%02X", s.byte);
			out_result.append(hex);
		}
		else
		{
			out_result.append("??");
		}

		if (i != sig_s - 1)
			out_result.append(" ");
	}

	return true;
}

#pragma warning (default: 26812)
