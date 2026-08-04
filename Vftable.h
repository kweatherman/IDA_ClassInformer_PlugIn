
// Virtual function table parsing support
#pragma once

namespace vftable
{
	// vftable info container
	struct vtinfo
	{
		ea_t start, end; // addresses
		int  methodCount;
		//char name[MAXSTR];
	};
	bool getTableInfo(ea_t ea, vtinfo &info);

	// Returns true if mangled name prefix indicates a vftable
	inline bool isValid(const char *name){ return(*((const uint32_t *) name) == 0x375F3F3F /*"??_7"*/); }
}
