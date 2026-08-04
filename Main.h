
// Class Informer
#pragma once

#include <stdint.h>

extern bool getVerifyEa(ea_t ea, ea_t &rValue);
extern bool hasAnteriorComment(ea_t ea);
extern void addTableEntry(uint32_t flags, ea_t vft, int methodCount, const char * format, ...);
extern bool getPlainTypeName(const char * mangled, char * outStr);

extern void fixDword(ea_t ea);
extern void fixEa(ea_t ea);
extern void fixFunction(ea_t eaFunc);

extern void setName(ea_t ea, const char * name);
extern void setComment(ea_t ea, const char * comment, bool rptble);
extern void setAnteriorComment(ea_t ea, const char *format, ...);
inline void setUnknown(ea_t ea, int size) {	del_items(ea, DELIT_EXPAND, size); }

// Return TRUE if there is a name at address that is not a dumbly name
inline bool hasName(ea_t ea) { return has_name(get_flags(ea)); }

// Return TRUE if there is a comment at address
inline bool hasComment(ea_t ea) { return has_cmt(get_flags(ea)); }

// Get IDA 32 bit value with IDB existence verification
template <class T> bool getVerify32(ea_t eaPtr, T& rValue)
{
	// Location valid?
	if (IS_VALID_ADDR(eaPtr))
	{
		// Get 32bit value
		rValue = (T) get_32bit(eaPtr);
		return true;
	}
	return false;
}

// Segment cache container
const uint32_t _CODE_SEG = (1 << 0);
const uint32_t _DATA_SEG = (1 << 1);
struct SEGMENT
{
	ea_t start, end;  // Start and end VA of the segment
	uint32_t type;      // Either SEG_CODE, SEG_DATA, or both for the corner case of a IDB with just one segment.
	char name[8 + 1]; // PE header format is 8 max
};
extern const SEGMENT *FindCachedSegment(ea_t addr);

extern bool g_optionPlaceStructs;
