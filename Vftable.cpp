
// Virtual function table parsing support
#include "StdAfx.h"
#include "Main.h"
#include "Vftable.h"
#include "RTTI.h"


// Attempt to get information of and fix vftable at address.
// Return true along with info if valid vftable parsed at address
bool vftable::getTableInfo(ea_t ea, vtinfo &info)
{
	// Start of a vft should have an xref and a name (auto, or user, etc).
    // Ideal flags 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
    //dumpFlags(ea);
    flags_t flags = get_flags(ea);
	if(has_xref(flags) && has_any_name(flags) && (plat.isEa(flags) || is_unknown(flags)))
    {
		memset(&info, 0, sizeof(info));

        // Get raw (auto-generated mangled, or user named) vft name
        //if (!get_name(BADADDR, ea, info.name, SIZESTR(info.name)))
        //    msg("%llX ** vftable::getTableInfo(): failed to get raw name!\n", ea);

        // Attempt to determine the vft's method count
        ea_t start = info.start = ea;

        while (true)
        {
            // Should be an pointer sized offset to a function here (could be unknown if dirty IDB)
            // Ideal flags for 32bit: FF_DWRD, FF_0OFF, FF_REF, FF_NAME, FF_DATA, FF_IVL
            //dumpFlags(ea);
            flags_t indexFlags = get_flags(ea);
            if (!(plat.isEa(indexFlags) || is_unknown(indexFlags)))
                break;

            // Look at what this (assumed vftable index) points too
            ea_t memberPtr = plat.getEa(ea);
            if (!(memberPtr && (memberPtr != BADADDR)))
            {
                // vft's some times have a trailing zero pointer (alignment, or?), fix it
                if (memberPtr == 0)
                    fixEa(ea);
                break;
            }

            // Should see code for a good vft method here, but it could be dirty
            flags_t flags = get_flags(memberPtr);
            if (!(is_code(flags) || is_unknown(flags)))
            {
				// Edge cases where IDA has unresolved bytes
				// 2nd chance if points to a code segment
				const SEGMENT *methodSeg = FindCachedSegment(memberPtr);
				if (methodSeg && (methodSeg->type & _CODE_SEG))
				{
                    _ASSERT(false);
				}
				else
				{
					break;
				}
            }

            if (ea != start)
            {
                // If we see a ref after first index it's probably the beginning of the next vft or something else
                if (has_xref(indexFlags))
                    break;

                // If we see a COL here it must be the start of another vftable
                if (RTTI::_RTTICompleteObjectLocator::isValid(memberPtr))
                    break;
            }

            // As needed fix ea_t pointer, and, or, missing code and function def here
            fixEa(ea);
            fixFunction(memberPtr);
            ea += (ea_t) plat.ptrSize;
        };

        // Reached the presumed end of it
        if ((info.methodCount = ((ea - start) / plat.ptrSize)) > 0)
        {
            info.end = ea;
            return true;
        }
    }

    return false;
}
