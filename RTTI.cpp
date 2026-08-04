
// Run-Time Type Information (RTTI) support
#include "StdAfx.h"
#include "Main.h"
#include "RTTI.h"
#include "Vftable.h"

// const Name::`vftable'
static const char *FORMAT_RTTI_VFTABLE_PREFIX = "??_7";
static const char *FORMAT_RTTI_VFTABLE ="??_7%s6B@";

// type 'RTTI Type Descriptor'
static const char * FORMAT_RTTI_TYPE = "??_R0?%s@8";

// 'RTTI Base Class Descriptor at (a,b,c,d)'
static const char * FORMAT_RTTI_BCD = "??_R1%s%s%s%s%s8";

// `RTTI Base Class Array'
static const char * FORMAT_RTTI_BCA = "??_R2%s8";

// 'RTTI Class Hierarchy Descriptor'
static const char * FORMAT_RTTI_CHD = "??_R3%s8";

// 'RTTI Complete Object Locator'
static const char * FORMAT_RTTI_COL_PREFIX = "??_R4";
static const char * FORMAT_RTTI_COL = "??_R4%s6B@";

// Skip type_info tag for class/struct mangled name strings
#define SKIP_TD_TAG(_str) ((_str) + SIZESTR(".?Ax"))

// Class name list container
struct bcdInfo
{
    char m_name[MAXSTR];
    uint32_t m_attribute;
	RTTI::PMD m_pmd;
};
typedef std::vector<bcdInfo> bcdList;

// Cache of IDA strings we have already read for performance
static std::map<ea_t, qstring> stringCache;

// Set of known RTTI types to address location
static eaSet tdSet;  // Known "type_info" type defines set
static eaSet chdSet; // _RTTIClassHierarchyDescriptor "Class Hierarchy Descriptor" (CHD) set
static eaSet bcdSet; // _RTTIBaseClassDescriptor "Base Class Descriptor" (BCD) set
eaSet vftSet;    // `vftable'
eaSet colSet;    // _RTTICompleteObjectLocator "Complete Object Locator" (COL) set
eaSet superSet;  // Combined for faster scanning

#define IN_SUPER(_addr) (superSet.find(_addr) != superSet.end())
// TO_INT64 defined in Compat.h

namespace RTTI
{
    void getBCDInfo(ea_t col, bcdList& nameList, uint32_t& numBaseClasses);
};

void RTTI::freeWorkingData()
{
    stringCache.clear();
    tdSet.clear();
    chdSet.clear();
    bcdSet.clear();
    colSet.clear();
    vftSet.clear();
    superSet.clear();
}

// Make a mangled number string for labeling
static char * mangleNumber(uint32_t number, char * buffer)
{
	//
	// 0 = A@
	// X = X-1 (1 <= X <= 10)
	// -X = ? (X - 1)
	// 0x0..0xF = 'A'..'P'

	// Can only get unsigned inputs
	int num = *((int32_t*) &number);
    if (num == 0)
        return strcpy(buffer, "A@");
	else
	{
		int sign = 0;
		if(num < 0)
		{
			sign = 1;
			num = -num;
		}

		if(num <= 10)
		{
			_snprintf_s(buffer, 64, (64 - 1), "%s%d", (sign ? "?" : ""), (num - 1));
			return buffer;
		}
		else
		{
			// Count digits
			char buffer2[64];
			int  count = sizeof(buffer2);

			while((num > 0) && (count > 0))
			{
				buffer2[sizeof(buffer2) - count] = ('A' + (num % 16));
				num = (num / 16);
				count--;
			};

			if(count == 0)
				msg(" *** mangleNumber() overflow! ***");

			_snprintf_s(buffer, 64, (64-1), "%s%s@", (sign ? "?" : ""), buffer2);
			return buffer;
		}
	}
}


// Return a short label indicating the CHD inheritance type by attributes
// TODO: Consider CHD_AMBIGUOUS?
static const char * attributeLabel(uint32_t attributes)
{
    switch (attributes & 3)
    {
        case RTTI::CHD_MULTINH: return "[MI]";
        case RTTI::CHD_VIRTINH: return "[VI]";
        case (RTTI::CHD_MULTINH | RTTI::CHD_VIRTINH): return "[MI VI]";
    };
    return "";
}


// Get or make RTTI type definitions
static tid_t s_type_info_ID = BADADDR;
static tid_t s_PMD_ID = BADADDR;
static tid_t s_ClassHierarchyDescriptor_ID = BADADDR;
static tid_t s_BaseClassDescriptor_ID = BADADDR;
static tid_t s_CompleteObjectLocator_ID = BADADDR;

static void typeDump(tinfo_t &tinf)
{
	qstring out;
	tinf.print(&out, NULL, PRTYPE_DEF | PRTYPE_MULTI | PRTYPE_1LINCMT | PRTYPE_OFFSETS);
	msg("type dump: \n\"%s\".\n", out.c_str());
}

// Look for existing type from a list of names
static tid_t GetKnownTypeID(const char * names[], int namesCount, asize_t expectedTypeSize)
{
	for (int i = 0; i < namesCount; i++)
	{
        tinfo_t tinf;
        if (tinf.get_named_type(names[i], /*BTF_STRUCT*/ BTF_TYPEDEF))
        {
            if (tinf.present())
            {
                //qstring out;
                //tinf.print(&out);
                //msg("print: \"%s\".\n", out.c_str());
                asize_t size = tinf.get_size();
                if (size == expectedTypeSize)
                {
                    // TODO: Could verify the type
                    //type_t _decltype = tinf.get_decltype(); // Looking for struct but it will be BTF_TYPEDEF
                    //typeDump(tinf);
                    return tinf.force_tid();
                }
            }
		}
	}

	return BADADDR;
}

void RTTI::addDefinitionsToIda()
{
    // std::type_info, aka "_TypeDescriptor" and "_RTTITypeDescriptor" in CRT source, class representation
    static const char * type_info_names[] =
    {
        "type_info",
        "??_Rtype_info_std@@3Vtype_info@@A", /*std::type_info*/

        // From at at least MSVC CRT sources 2017 and later. Will typically be there if the IDB has a matching PDB
        "_TypeDescriptor",
        "TypeDescriptor"
    };
    // Look for existing type by name
    s_type_info_ID = GetKnownTypeID(type_info_names, _countof(type_info_names), (plat.is64 ? sizeof(type_info_64) : sizeof(type_info_32)));

    // Not found so create it
	if (s_type_info_ID == BADADDR)
	{
		const char * def = R"DEF(
            // RTTI std::type_info class (#classinformer)
            struct type_info
            {
                const void *vfptr;
                void *_M_data;
                char _M_d_name[];
            };
        )DEF";
        if (parse_decls(NULL, def, msg, HTI_DCL) != 0)
            msg("** addDefinitionsToIda():  \"type_info\" create failed! **\n");
        s_type_info_ID = get_named_type_tid("type_info");

        // Set the representation of the "name" field to a string literal
     // TODO: Can put __strlit(C) in the definition?
		if (s_type_info_ID != BADADDR)
		{
			tinfo_t tinf;
			value_repr_t repr;
			if (tinf.get_type_by_tid(s_type_info_ID) && repr.parse_value_repr("__strlit(C,\"windows - 1252\");" /*"__strlit(C)"*/))
			{
				tinf.set_udm_repr(2, repr);
                //typeDump(tinf);
			}
		}
	}

    // PDM
	static const char * pdm_names[] =	{ "_PDM", "PDM" };
    s_PMD_ID = GetKnownTypeID(pdm_names, _countof(pdm_names), sizeof(PMD));
	if (s_PMD_ID == BADADDR)
	{
		const char * def = R"DEF(
            // RTTI Base class descriptor displacement container (#classinformer)
            struct PMD
            {
                int mdisp;
                int pdisp;
                int vdisp;
            };
        )DEF";
		if (parse_decls(NULL, def, msg, HTI_DCL) != 0)
			msg("** addDefinitionsToIda():  \"PMD\" create failed! **\n");
        s_PMD_ID = get_named_type_tid("PMD");
        /*
		tinfo_t tinf;
		if (tinf.get_type_by_tid(s_PMD_ID))
            typeDump(tinf);
        */
	}

    // _RTTIClassHierarchyDescriptor
	static const char * chd_names[] = { "_s__RTTIClassHierarchyDescriptor",	"__RTTIClassHierarchyDescriptor", "_RTTIClassHierarchyDescriptor", "RTTIClassHierarchyDescriptor" };
    s_ClassHierarchyDescriptor_ID = GetKnownTypeID(chd_names, _countof(chd_names), (sizeof(_RTTIClassHierarchyDescriptor) + (plat.is64 ? sizeof(uint32_t) : 0))); // The 64bit one in the CRT source shows it's a pointer while it's an int offset in binary
    if (s_ClassHierarchyDescriptor_ID == BADADDR)
    {
        const char * def;
        if (!plat.is64)
        {
            // 32bit
            def = R"DEF(
                // RTTI Class Hierarchy Descriptor (#classinformer)
                struct _RTTIClassHierarchyDescriptor
                {
                    unsigned int signature;
                    unsigned int attributes;
                    unsigned int numBaseClasses;
                    void *baseClassArray; // _RTTIBaseClassArray*
                };
            )DEF";
        }
        else
        {
            // 64bit
            def = R"DEF(
                // RTTI Class Hierarchy Descriptor (#classinformer)
                struct _RTTIClassHierarchyDescriptor
                {
                    unsigned int signature;
                    unsigned int attributes;
                    unsigned int numBaseClasses;
                    int baseClassArray;
                };
            )DEF";
        }
        if (parse_decls(NULL, def, msg, HTI_DCL) != 0)
            msg("** addDefinitionsToIda():  \"_RTTIClassHierarchyDescriptor\" create failed! **\n");
        s_ClassHierarchyDescriptor_ID = get_named_type_tid("_RTTIClassHierarchyDescriptor");
        /*
        tinfo_t tinf;
        if (tinf.get_type_by_tid(s_ClassHierarchyDescriptor_ID))
            typeDump(tinf);
        */
    }

    // _RTTIBaseClassDescriptor
	static const char * bcd_names[] = { "_s__RTTIBaseClassDescriptor", "__RTTIBaseClassDescriptor", "_RTTIBaseClassDescriptor", "RTTIBaseClassDescriptor" };
    s_BaseClassDescriptor_ID = GetKnownTypeID(bcd_names, _countof(bcd_names), (sizeof(_RTTIBaseClassDescriptor) + (plat.is64 ? sizeof(uint64_t) : 0)));
    if (s_BaseClassDescriptor_ID == BADADDR)
    {
		const char * def;
        if (!plat.is64)
        {
			// 32bit
			def = R"DEF(
                // RTTI Base class descriptor displacement container (#classinformer)
                struct _RTTIBaseClassDescriptor
	            {
		            int typeDescriptor;
		            unsigned int numContainedBases;
		            PMD pmd;
		            unsigned int attributes;
		            void *classDescriptor;  // _RTTIClassHierarchyDescriptor*
                };
            )DEF";
        }
        else
        {
            // 64bit
            def = R"DEF(
                // RTTI Base class descriptor displacement container (#classinformer)
                struct _RTTIBaseClassDescriptor
	            {
		            int typeDescriptor;
		            unsigned int numContainedBases;
		            PMD pmd;
		            unsigned int attributes;
		            int classDescriptor;
                };
            )DEF";
        }
        if (parse_decls(NULL, def, msg, HTI_DCL) != 0)
            msg("** addDefinitionsToIda():  \"_RTTIBaseClassDescriptor\" create failed! **\n");
        s_BaseClassDescriptor_ID = get_named_type_tid("_RTTIBaseClassDescriptor");
        /*
        tinfo_t tinf;
        if (tinf.get_type_by_tid(s_BaseClassDescriptor_ID))
            typeDump(tinf);
        */
    }

    // _RTTICompleteObjectLocator
    static const char * col_names[] = { "_s__RTTICompleteObjectLocator2", "_s__RTTICompleteObjectLocator", "__RTTICompleteObjectLocator", "_RTTICompleteObjectLocator", "RTTICompleteObjectLocator" };
    s_CompleteObjectLocator_ID = GetKnownTypeID(col_names, _countof(col_names), (sizeof(_RTTICompleteObjectLocator) + (plat.is64 ? 16 : 0)));
    if (s_CompleteObjectLocator_ID == BADADDR)
    {
		const char * def;
		if (!plat.is64)
		{
			// 32bit
			def = R"DEF(
                // RTTI Complete Object Locator (#classinformer)
                struct _RTTICompleteObjectLocator
                {
               	    unsigned int signature;
               	    unsigned int offset;
               	    unsigned int cdOffset;
               	    void *typeDescriptor;   // type_info*
               	    void *classDescriptor;  // _RTTIClassHierarchyDescriptor*
                };
            )DEF";
		}
		else
		{
			// 64bit
			def = R"DEF(
                // RTTI Complete Object Locator (#classinformer)
                struct _RTTICompleteObjectLocator
                {
               	    unsigned int signature;
               	    unsigned int offset;
               	    unsigned int cdOffset;
               	    int typeDescriptor;
               	    int classDescriptor;
                    int objectBase;
                };
            )DEF";
		}
        if (parse_decls(NULL, def, msg, HTI_DCL) != 0)
            msg("** addDefinitionsToIda():  \"_RTTICompleteObjectLocator\" create failed! **\n");
        s_CompleteObjectLocator_ID = get_named_type_tid("_RTTICompleteObjectLocator");
        /*
        tinfo_t tinf;
        if (tinf.get_type_by_tid(s_CompleteObjectLocator_ID))
            typeDump(tinf);       
        */
    }
}


// Place an RTTI structure by type ID add address w/optional name
// Returns true if structure was placed, else FLASE it was already set
static bool tryStructRTTI(ea_t ea, tid_t tid, char * typeName = NULL, bool bHasChd = false)
{
    if (tid == BADADDR)
    {
        _ASSERT(false);
        return false;
    }

    #define put32(ea) create_dword(ea, sizeof(EA_32), true)
    #define put64(ea) create_qword(ea, sizeof(ea_t), true)

    // type_info
	if(tid == s_type_info_ID)
	{
        if (!plat.is64)
        {
            // EA_32
            if (!hasName(ea))
            {
                _ASSERT(typeName != NULL);
                uint32_t nameLen = (uint32_t) (strlen(typeName) + 1);
                uint32_t structSize = (offsetof(RTTI::type_info_32, _M_d_name) + nameLen);

                // Place struct
                setUnknown(ea, structSize);
                bool result = false;
                if (g_optionPlaceStructs)
                    result = create_struct(ea, structSize, s_type_info_ID);
                if (!result)
                {
                    // Else fix/place the proper type fields and name it
                    put32(ea + offsetof(RTTI::type_info_32, vfptr));
                    put32(ea + offsetof(RTTI::type_info_32, _M_data));
                    create_strlit((ea + offsetof(RTTI::type_info_32, _M_d_name)), nameLen, STRTYPE_C);
                }

                // sh!ft: End should be aligned
                ea_t end = (ea + offsetof(RTTI::type_info_32, _M_d_name) + nameLen);
                if (end % 4)
                    create_align(end, (4 - (end % 4)), 0);

                return true;
            }
        }
        else
        {
            // EA_64
            if (!hasName(ea))
            {
                _ASSERT(typeName != NULL);
                uint32_t nameLen = (uint32_t) (strlen(typeName) + 1);
                uint32_t structSize = (offsetof(RTTI::type_info_64, _M_d_name) + nameLen);

                // Place struct
                setUnknown(ea, structSize);
                bool result = false;
                if (g_optionPlaceStructs && (s_type_info_ID > 5))
                    result = create_struct(ea, structSize, s_type_info_ID);
                if (!result)
                {
                    put64(ea + offsetof(RTTI::type_info_64, vfptr));
                    put64(ea + offsetof(RTTI::type_info_64, _M_data));
                    create_strlit((ea + offsetof(RTTI::type_info_64, _M_d_name)), nameLen, STRTYPE_C);
                }

                // sh!ft: End should be aligned
             // TODO: Should be align 8?
                ea_t end = (ea + offsetof(RTTI::type_info_64, _M_d_name) + nameLen);
                if (end % 4)
                    create_align(end, (4 - (end % 4)), 0);

                return true;
            }
        }

        return false;
	}

    // _RTTIClassHierarchyDescriptor
	if (tid == s_ClassHierarchyDescriptor_ID)
	{
		if (!hasName(ea))
		{
			setUnknown(ea, sizeof(RTTI::_RTTIClassHierarchyDescriptor));
			bool result = false;
			if (g_optionPlaceStructs)
				result = create_struct(ea, sizeof(RTTI::_RTTIClassHierarchyDescriptor), s_ClassHierarchyDescriptor_ID);
			if (!result)
			{
				put32(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, signature));
				put32(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, attributes));
				put32(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, numBaseClasses));
				put32(ea + offsetof(RTTI::_RTTIClassHierarchyDescriptor, baseClassArray));
			}

			return true;
		}

        return false;
	}

    // PMD
	if(tid == s_PMD_ID)
	{
		if (!hasName(ea))
		{
			setUnknown(ea, sizeof(RTTI::PMD));
			bool result = false;
			if (g_optionPlaceStructs)
				result = create_struct(ea, sizeof(RTTI::PMD), s_PMD_ID);
			if (!result)
			{
                put32(ea + offsetof(RTTI::PMD, mdisp));
                put32(ea + offsetof(RTTI::PMD, pdisp));
                put32(ea + offsetof(RTTI::PMD, vdisp));
			}

			return true;
		}

        return false;
	}

	// _RTTICompleteObjectLocator
	if(tid == s_CompleteObjectLocator_ID)
	{
        if (!plat.is64)
        {
            // EA_32
            if (!hasName(ea))
            {
                setUnknown(ea, sizeof(RTTI::_RTTICompleteObjectLocator_32));
                bool result = false;
                if (g_optionPlaceStructs)
                    result = create_struct(ea, sizeof(RTTI::_RTTICompleteObjectLocator_32), s_CompleteObjectLocator_ID);
                if (!result)
                {
                    put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_32, signature));
                    put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_32, offset));
                    put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_32, cdOffset));
                    put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_32, typeDescriptor));
                    put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_32, classDescriptor));
                }

                return true;
            }
        }
        else
        {
            // EA_64
			if (!hasName(ea))
			{
				setUnknown(ea, sizeof(RTTI::_RTTICompleteObjectLocator_64));
				bool result = false;
				if (g_optionPlaceStructs)
					result = create_struct(ea, sizeof(RTTI::_RTTICompleteObjectLocator_64), s_CompleteObjectLocator_ID);
				if (!result)
				{
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, signature));
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, offset));
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, cdOffset));
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, typeDescriptor));
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, classDescriptor));
					put32(ea + offsetof(RTTI::_RTTICompleteObjectLocator_64, objectBase));
				}

				return true;
			}
        }

        return false;
	}

	// _RTTIBaseClassDescriptor
	if (tid == s_BaseClassDescriptor_ID)
	{
        // Recursive
        //msg("PMD: 0x%llX\n", (ea + offsetof(RTTI::_RTTIBaseClassDescriptor, pmd)));
        tryStructRTTI(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, pmd), s_PMD_ID);

        if (!hasName(ea))
        {
            setUnknown(ea, sizeof(RTTI::_RTTIBaseClassDescriptor));
            bool result = false;
            if (g_optionPlaceStructs)
                result = create_struct(ea, sizeof(RTTI::_RTTIBaseClassDescriptor), s_BaseClassDescriptor_ID);
            if (!result)
            {
                put32(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, typeDescriptor));
                put32(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, numContainedBases));
                put32(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, attributes));
                //if (bHasChd)
                put32(ea + offsetof(RTTI::_RTTIBaseClassDescriptor, classDescriptor));
                if (bHasChd)
                    setComment((ea + offsetof(RTTI::_RTTIBaseClassDescriptor, classDescriptor)), "BCD_HASPCHD set", true);
            }

            return true;
        }

        return false;
	}

	_ASSERT(false);
	return false;
}


// Read ASCII string from IDB at address
static int getIdaString(ea_t ea, char * buffer, int bufferSize)
{
	buffer[0] = 0;

    // Return cached name if already exists
    auto it = stringCache.find(ea);
    if (it != stringCache.end())
    {
        const char * str = it->second.c_str();
        int len = (int) strlen(str);
        if (len > bufferSize)
			len = bufferSize;
        strncpy_s(buffer, MAXSTR, str, len);
        return len;
    }
    else
    {
        // Read string at ea if it exists
        int len = (int) get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS);
        if (len > 0)
        {
			// Length includes terminator
            if (len > bufferSize)
				len = bufferSize;

			qstring str;
			int len2 = get_strlit_contents(&str, ea, len, STRTYPE_C);
            if (len2 > 0)
            {
				// Length with out terminator
				if (len2 > bufferSize)
					len2 = bufferSize;

                // Cache it
				memcpy(buffer, str.c_str(), len2);
                buffer[len2] = 0;
                stringCache[ea] = buffer;
            }
            else
                len = 0;
        }

        return len ;
    }
}


// --------------------------- Type descriptor ---------------------------

// Get type name into a buffer
// type_info assumed to be valid
int RTTI::type_info::getName(ea_t typeInfo, char * buffer, int bufferSize)
{
    return getIdaString(typeInfo + (plat.is64 ? offsetof(type_info_64, _M_d_name) : offsetof(type_info_32, _M_d_name)), buffer, bufferSize);
}

// A valid type_info/TypeDescriptor at pointer?
bool RTTI::type_info::isValid(ea_t typeInfo)
{
    // true if we've already seen it
    if (tdSet.find(typeInfo) != tdSet.end())
        return true;

    if (IS_VALID_ADDR(typeInfo))
	{
		// Verify what should be a vftable
        ea_t ea = plat.getEa(typeInfo + (plat.is64 ? offsetof(type_info_64, vfptr) : offsetof(type_info_32, vfptr)));
        if (IS_VALID_ADDR(ea))
		{
            // _M_data should be NULL statically
            ea_t _M_data = BADADDR;
            if (getVerifyEa((typeInfo + (plat.is64 ? offsetof(type_info_64, _M_data) : offsetof(type_info_32, _M_data))), _M_data))
            {
                if (_M_data == 0)
                    return isTypeName(typeInfo + (plat.is64 ? offsetof(type_info_64, _M_d_name) : offsetof(type_info_32, _M_d_name)));
            }
		}
	}

	return false;
}
//
// Returns true if known typename at address
bool RTTI::type_info::isTypeName(ea_t name)
{
    // Should start with a period
    if (get_byte(name) == '.')
    {
        // Read the rest of the possible name string
        char buffer[MAXSTR];
        if (getIdaString(name, buffer, SIZESTR(buffer)))
        {
            // Should be valid if it properly demangles
            if (char * s = __unDName(NULL, buffer+1 /*skip the '.'*/, 0, mallocWrap, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY)))
            {
                free(s);
                return true;
            }
        }
    }
    return false;
}

// Put struct and place name at address
void RTTI::type_info::tryStruct(ea_t typeInfo)
{
	// Only place once per address
	if (tdSet.find(typeInfo) != tdSet.end())
		return;
	else
		tdSet.insert(typeInfo);

	// Get type name
	char name[MAXSTR];
	int nameLen = getName(typeInfo, name, SIZESTR(name));

    //msg("TD: 0x%llX\n", typeInfo);
	tryStructRTTI(typeInfo, s_type_info_ID, name);

	if (nameLen > 0)
	{
		if (!hasName(typeInfo))
		{
			// Set decorated name/label
			char name2[MAXSTR];
			_snprintf_s(name2, sizeof(name2), SIZESTR(name2), FORMAT_RTTI_TYPE, (name + 2));
			setName(typeInfo, name2);
		}
	}
	else
	{
		_ASSERT(false);
	}
}

// --------------------------- Complete Object Locator ---------------------------

// Return true if address is a valid RTTI structure
bool RTTI::_RTTICompleteObjectLocator::isValid(ea_t col)
{
    // True if already known
    if (colSet.find(col) != colSet.end())
        return true;

    if (IS_VALID_ADDR(col))
    {
        // Check signature
        uint32_t signature = -1;
        if (getVerify32((col + offsetof(_RTTICompleteObjectLocator, signature)), signature))
        {
            if (!plat.is64)
            {
                // 32bit direct addresses
                if (signature == 0)
                {
                    // Check valid type_info
                    ea_t typeInfo = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, typeDescriptor));
                    if (type_info_32::isValid(typeInfo))
                    {
                        ea_t classDescriptor = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, classDescriptor));
                        if (_RTTIClassHierarchyDescriptor::isValid(classDescriptor))
                        {
                            //msg("%llX %llX %llX\n", col, typeInfo, classDescriptor);
                            return true;
                        }
                    }
                }
            }
            else
            {
                // 64bit bases plus objectBase offsets
				if (signature == 1)
				{
					// TODO: Can any of these be zero and still be valid?
					uint32_t objectLocator32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, objectBase));
                    int64_t objectLocator64 = TO_INT64(objectLocator32);
					if (objectLocator64 != 0)
					{
						uint32_t tdOffset32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, typeDescriptor));
                        int64_t tdOffset64 = TO_INT64(tdOffset32);
						if (tdOffset64 != 0)
						{
							uint32_t cdOffset32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, classDescriptor));
                            int64_t cdOffset64 = TO_INT64(cdOffset32);
							if (cdOffset64 != 0)
							{
								int64_t colBase64 = ((int64_t) col - objectLocator64);
								ea_t typeInfo = (ea_t) (colBase64 + tdOffset64);
								if (type_info_64::isValid(typeInfo))
								{
									ea_t classDescriptor = (ea_t) (colBase64 + cdOffset64);
									if (_RTTIClassHierarchyDescriptor::isValid(classDescriptor, colBase64))
									{
										//msg("%llX %llX %llX\n", col, typeInfo, classDescriptor);
										return true;
									}
								}
							}
						}
					}
				}
            }
		}
	}

	return false;
}

// Same as above but from an already validated type_info perspective
bool RTTI::_RTTICompleteObjectLocator_32::isValid2(ea_t col)
{
	// True if already known
	if (colSet.find(col) != colSet.end())
		return true;

    // 'signature' should be zero
    uint32_t signature = -1;
    if (getVerify32((col + offsetof(_RTTICompleteObjectLocator_32, signature)), signature))
    {
        if (signature == 0)
        {
            // Verify CHD
            ea_t classDescriptor = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, classDescriptor));
            if (classDescriptor && (classDescriptor != BADADDR))
                return _RTTIClassHierarchyDescriptor::isValid(classDescriptor);
        }
    }

    return false;
}

// Place full COL hierarchy structures if they don't already exist
bool RTTI::_RTTICompleteObjectLocator::tryStruct(ea_t col)
{
	// Place it once
	if (colSet.find(col) != colSet.end())
		return true;

	// If it doesn't have a name, IDA's analyzer missed it
	if (!hasName(col))
	{
		#if 0
		qstring buf;
		idaFlags2String(get_flags(col), buf);
		msg("%llX fix COL (%s)\n", col, buf.c_str());
		#endif
        //msg("COL: 0x%llX\n", col);
		tryStructRTTI(col, s_CompleteObjectLocator_ID);

		// Put type_def
        if (!plat.is64)
        {
            // 32bit direct address
            ea_t typeInfo = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, typeDescriptor));
            type_info_32::tryStruct(typeInfo);

            // Place CHD hierarchy
            ea_t classDescriptor = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, classDescriptor));
            _RTTIClassHierarchyDescriptor::tryStruct(classDescriptor);
        }
        else
        {
            // 64bit offsets plus objectBase
			uint32_t tdOffset32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, typeDescriptor));
            int64_t tdOffset64 = TO_INT64(tdOffset32);	 
			uint32_t cdOffset32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, classDescriptor));
            int64_t cdOffset64 = TO_INT64(cdOffset32);
			uint32_t objectLocator32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, objectBase));
            int64_t objectLocator64 = TO_INT64(objectLocator32);
        		 
			int64_t colBase64 = ((int64_t) col - objectLocator64);
			ea_t typeInfo = (ea_t) (colBase64 + tdOffset64);
			type_info::tryStruct(typeInfo);

			ea_t classDescriptor = (ea_t) (colBase64 + cdOffset64);
			_RTTIClassHierarchyDescriptor::tryStruct(classDescriptor, colBase64);

			// Set absolute address comments
			ea_t ea = (col + offsetof(_RTTICompleteObjectLocator_64, typeDescriptor));
			if (!hasComment(ea))
			{
				char buffer[64];
				sprintf_s(buffer, sizeof(buffer), "0x%llX", typeInfo);
				setComment(ea, buffer, true);
			}

			ea = (col + offsetof(_RTTICompleteObjectLocator_64, classDescriptor));
			if (!hasComment(ea))
			{
				char buffer[64];
				sprintf_s(buffer, sizeof(buffer), "0x%llX", classDescriptor);
				setComment(ea, buffer, true);
			}
        }

		return true;
	}

	return false;
}


// --------------------------- Base Class Descriptor ---------------------------

// Return true if address is a valid BCD
bool RTTI::_RTTIBaseClassDescriptor::isValid(ea_t bcd, int64_t colBase64)
{
    // true if already known
    if (bcdSet.find(bcd) != bcdSet.end())
        return true;

    if (IS_VALID_ADDR(bcd))
    {
        // Check attributes flags first
        uint32_t attributes = -1;
        if (getVerify32((bcd + offsetof(_RTTIBaseClassDescriptor, attributes)), attributes))
        {
            // Valid flags are the lower byte only
            if ((attributes & 0xFFFFFF00) == 0)
            {
                // Check for valid type_info
                if (!plat.is64)
                {
                    // When 32bit direct address
                    return type_info_32::isValid(plat.getEa32(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor)));
                }
                else
                {
                    // When 64bit plus COL bass ea_t
					uint32_t tdOffset32 = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                    int64_t tdOffset64 = TO_INT64(tdOffset32);
					return type_info_64::isValid((ea_t) (colBase64 + tdOffset64));
                }
            }
        }
    }

    return false;
}

// Put BCD structure at address
void RTTI::_RTTIBaseClassDescriptor::tryStruct(ea_t bcd, char * baseClassName, int64_t colBase64)
{
    // Only place it once
    if (bcdSet.find(bcd) != bcdSet.end())
    {
        // Seen already, just return type name
        ea_t typeInfo = BADADDR;
        if (!plat.is64)
        {
            // When 32bit direct address
            typeInfo = plat.getEa32(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
        }
        else
        {
            // When 64bit plus COL bass ea_t
			uint32_t tdOffset32 = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
            int64_t tdOffset64 = TO_INT64(tdOffset32);
			typeInfo = (ea_t) (colBase64 + tdOffset64);
        }

        char buffer[MAXSTR];
        type_info::getName(typeInfo, buffer, SIZESTR(buffer));
        strcpy_s(baseClassName, sizeof(buffer), SKIP_TD_TAG(buffer));
        return;
    }
    else
        bcdSet.insert(bcd);

    if (IS_VALID_ADDR(bcd))
    {
        uint32_t attributes = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));
        //msg("BCD: 0x%llX\n", bcd);
        tryStructRTTI(bcd, s_BaseClassDescriptor_ID, NULL, ((attributes & BCD_HASPCHD) > 0));

        // Has appended CHD?
        if (attributes & BCD_HASPCHD)
        {
            // yes, process it
            ea_t chdOffset = (bcd + (offsetof(_RTTIBaseClassDescriptor, classDescriptor)));
            ea_t chd = BADADDR;
            if (!plat.is64)
            {
                // EA_32
                fixDword(chdOffset);
                chd = get_32bit(chdOffset);
            }
            else
            {
                // EA_64
				fixDword(chdOffset);
				uint32_t chdOffset32 = get_32bit(chdOffset);
                int64_t chdOffset64 = TO_INT64(chdOffset32);              			 
				chd = (ea_t) (colBase64 + chdOffset64);
				if (!hasComment(chdOffset))
				{
					char buffer[32];
					sprintf_s(buffer, sizeof(buffer), "0x%llX", chd);
					setComment(chdOffset, buffer, true);
				}
            }

            if (IS_VALID_ADDR(chd))
                _RTTIClassHierarchyDescriptor::tryStruct(chd, colBase64);
            else
                _ASSERT(false);
        }

        // Place type_info struct
        ea_t typeInfo = BADADDR;
        if (!plat.is64)
        {
            // When 32bit direct address
            typeInfo = plat.getEa32(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
        }
        else
        {
            // When 64bit plus COL bass ea_t
			uint32_t tdOffset = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
			typeInfo = (colBase64 + (ea_t)tdOffset);
        }
        type_info::tryStruct(typeInfo);

        // Get raw type/class name
        char buffer[MAXSTR];
        type_info::getName(typeInfo, buffer, SIZESTR(buffer));
        strcpy_s(baseClassName, sizeof(buffer), SKIP_TD_TAG(buffer));

        if (!g_optionPlaceStructs && attributes)
        {
            // Place attributes comment
			ea_t ea = (bcd + offsetof(_RTTIBaseClassDescriptor, attributes));
			if (!hasComment(ea))
            {
                qstring s("");
                bool b = 0;
                #define ATRIBFLAG(_flag) { if (attributes & _flag) { if (b) s += " | ";  s += #_flag; b = 1; } }
                ATRIBFLAG(BCD_NOTVISIBLE);
                ATRIBFLAG(BCD_AMBIGUOUS);
                ATRIBFLAG(BCD_PRIVORPROTINCOMPOBJ);
                ATRIBFLAG(BCD_PRIVORPROTBASE);
                ATRIBFLAG(BCD_VBOFCONTOBJ);
                ATRIBFLAG(BCD_NONPOLYMORPHIC);
                ATRIBFLAG(BCD_HASPCHD);
                #undef ATRIBFLAG
                setComment(ea, s.c_str(), true);
            }
        }

        // Give it a label
        if (!hasName(bcd))
        {
            // Name::`RTTI Base Class Descriptor at (0, -1, 0, 0)'
            ZeroMemory(buffer, sizeof(buffer));
            char buffer1[64] = { 0 }, buffer2[64] = { 0 }, buffer3[64] = { 0 }, buffer4[64] = { 0 };
            _snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), FORMAT_RTTI_BCD,
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp))), buffer1),
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp))), buffer2),
                mangleNumber(get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp))), buffer3),
                mangleNumber(attributes, buffer4),
                baseClassName);

			setName(bcd, buffer);
        }
    }
    else
        _ASSERT(false);
}


// --------------------------- Class Hierarchy Descriptor ---------------------------

// Return true if address is a valid CHD structure
bool RTTI::_RTTIClassHierarchyDescriptor::isValid(ea_t chd, int64_t colBase64)
{
    // true is already known
    if (chdSet.find(chd) != chdSet.end())
        return(true);

    if (IS_VALID_ADDR(chd))
    {
        // signature should be zero statically
        uint32_t signature = -1;
        if (getVerify32((chd + offsetof(_RTTIClassHierarchyDescriptor, signature)), signature))
        {
            if (signature == 0)
            {
                // Check attributes flags
                uint32_t attributes = -1;
                if (getVerify32((chd + offsetof(_RTTIClassHierarchyDescriptor, attributes)), attributes))
                {
                    // Valid flags are the lower nibble only
                    if ((attributes & 0xFFFFFFF0) == 0)
                    {
                        // Should have at least one base class
                        uint32_t numBaseClasses = 0;
                        if (getVerify32((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
                        {
                            if (numBaseClasses >= 1)
                            {
                                // Check the first BCD entry
                                ea_t baseClassArray = BADADDR;
                                if (!plat.is64)
                                {
                                    // When 32bit a pointer
                                    baseClassArray = plat.getEa32(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
                                    if (IS_VALID_ADDR(baseClassArray))
                                    {
										// When 32bit direct address
										ea_t baseClassDescriptor = plat.getEa32(baseClassArray);
										return RTTI::_RTTIBaseClassDescriptor::isValid(baseClassDescriptor);
                                    }
                                }
                                else
                                {
                                    // When 64bit plus COL bass ea_t
									uint32_t baseClassArrayOffset32 = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
                                    int64_t baseClassArrayOffset64 = TO_INT64(baseClassArrayOffset32);
									baseClassArray = (ea_t) (colBase64 + baseClassArrayOffset64);
                                    if (IS_VALID_ADDR(baseClassArray))
                                    {
										// When 64bit plus COL bass ea_t
										uint32_t baseClassDescriptor32 = get_32bit(baseClassArray);
                                        int64_t baseClassDescriptor64 = (TO_INT64(baseClassDescriptor32) + colBase64);
										return RTTI::_RTTIBaseClassDescriptor::isValid((ea_t) baseClassDescriptor64, colBase64);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}

// Put CHD structure at address
void RTTI::_RTTIClassHierarchyDescriptor::tryStruct(ea_t chd, int64_t colBase64)
{
    // Only place it once per address
    if (chdSet.find(chd) != chdSet.end())
        return;
    else
        chdSet.insert(chd);

    if (IS_VALID_ADDR(chd))
    {
        // Place CHD
        //msg("CHD: 0x%llX\n", chd);
        tryStructRTTI(chd, s_ClassHierarchyDescriptor_ID);

        // Place attributes comment
        uint32_t attributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
        if (!g_optionPlaceStructs && attributes)
        {
			ea_t ea = (chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
			if (!hasComment(ea))
            {
                qstring s("");
                bool b = 0;
                #define ATRIBFLAG(_flag) { if (attributes & _flag) { if (b) s += " | ";  s += #_flag; b = 1; } }
                ATRIBFLAG(CHD_MULTINH);
                ATRIBFLAG(CHD_VIRTINH);
                ATRIBFLAG(CHD_AMBIGUOUS);
                #undef ATRIBFLAG
                setComment(ea, s.c_str(), true);
            }
        }

        // ---- Place BCD's ----
        uint32_t numBaseClasses = 0;
        if (getVerify32((chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)), numBaseClasses))
        {
            // Get pointer
            ea_t baseClassArray = BADADDR;
            if (!plat.is64)
            {
                // 32bit direct address
                baseClassArray = plat.getEa32(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
            }
            else
            {
                // 64bit plus COL bass ea_t
				uint32_t baseClassArrayOffset = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
				baseClassArray = (colBase64 + (ea_t) baseClassArrayOffset);

				ea_t ea = (chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
				if (!hasComment(ea))
				{
					char buffer[32];
					_snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), "0x%llX", baseClassArray);
					setComment(ea, buffer, true);
				}
            }

            if (baseClassArray && (baseClassArray != BADADDR))
            {
                // Create offset string based on input digits
                char format[128];
                if(numBaseClasses > 1)
                {
                    if (!plat.is64)
                    {
                        // EA_32
                        int digits = (int) strlen(_itoa(numBaseClasses, format, 10));
                        if (digits > 1)
                            _snprintf_s(format, sizeof(format), SIZESTR(format), "  BaseClass[%%0%dd]", digits);
                        else
                            strcpy_s(format, sizeof(format), "  BaseClass[%d]");
                    }
                    else
                    {
                        // EA_64
						int digits = (int) strlen(_itoa(numBaseClasses, format, 10));
						if (digits > 1)
							_snprintf_s(format, sizeof(format), SIZESTR(format), "  BaseClass[%%0%dd] 0x%%016llX", digits);
						else
							strcpy_s(format, sizeof(format), "  BaseClass[%d] 0x%016llX");
                    }
                }

                for (uint32_t i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(uint32_t))
                {
                    fixDword(baseClassArray);

                    char baseClassName[MAXSTR];
					if (!plat.is64)
					{
                        // EA_32
                        if (!hasComment(baseClassArray))
                        {
                            // Add index comment to to it
                            if (numBaseClasses == 1)
                                setComment(baseClassArray, "  BaseClass", false);
                            else
                            {
                                char ptrComent[MAXSTR];
                                _snprintf_s(ptrComent, sizeof(ptrComent), SIZESTR(ptrComent), format, i);
                                setComment(baseClassArray, ptrComent, false);
                            }
                        }

						// Place BCD struct, and grab the base class name
                        // 32bit, direct address
                        ea_t bcd = plat.getEa32(baseClassArray);
						_RTTIBaseClassDescriptor::tryStruct(bcd, baseClassName);
                    }
                    else
                    {
                        // EA_64
						uint32_t bcdOffset32 = get_32bit(baseClassArray);
                        int64_t bcdOffset64 = TO_INT64(bcdOffset32);
						ea_t bcd = (ea_t) (colBase64 + bcdOffset64);

                        if (!hasComment(baseClassArray))
                        {
                            // Add index comment to to it
                            if (numBaseClasses == 1)
                            {
                                char buffer[MAXSTR];
                                sprintf_s(buffer, sizeof(buffer), "  BaseClass 0x%llX", bcd);
                                setComment(baseClassArray, buffer, false);
                            }
                            else
                            {
                                char buffer[MAXSTR];
                                _snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), format, i, bcd);
                                setComment(baseClassArray, buffer, false);
                            }
                        }

						// Place BCD struct, and grab the base class name
                        // 64bit plus COL bass ea_t
						_RTTIBaseClassDescriptor::tryStruct(bcd, baseClassName, colBase64);
                    }

                    // Now we have the base class name, name and label some things
                    if (i == 0)
                    {
                        // Set array name
                        if (!hasName(baseClassArray))
                        {
                            // ??_R2A@@8 = A::`RTTI Base Class Array'
                            char mangledName[MAXSTR];
                            _snprintf_s(mangledName, sizeof(mangledName), SIZESTR(mangledName), FORMAT_RTTI_BCA, baseClassName);
							setName(baseClassArray, mangledName);
                        }

                        // Add a spacing comment line above us
                        if (!hasAnteriorComment(baseClassArray))
							setAnteriorComment(baseClassArray, "");

                        // Set CHD name
                        if (!hasName(chd))
                        {
                            // A::`RTTI Class Hierarchy Descriptor'
                            char mangledName[MAXSTR];
                            _snprintf_s(mangledName, sizeof(mangledName), SIZESTR(mangledName), FORMAT_RTTI_CHD, baseClassName);
							setName(chd, mangledName);
                        }
                    }
                }

                // Make following DWORD if it's bytes are zeros
                if (numBaseClasses > 0)
                {
                    if (IS_VALID_ADDR(baseClassArray))
                    {
                        if (get_32bit(baseClassArray) == 0)
                            fixDword(baseClassArray);
                    }
                }
            }
            else
                _ASSERT(false);
        }
        else
            _ASSERT(false);
    }
    else
        _ASSERT(false);
}


// --------------------------- Vftable ---------------------------

// Get list of base class descriptor info
void RTTI::getBCDInfo(ea_t col, bcdList &list, uint32_t &numBaseClasses)
{
	numBaseClasses = 0;

    if(!plat.is64)
    {
        // 32bit version
        ea_t chd = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, classDescriptor));
	    if(chd)
	    {
            if (numBaseClasses = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)))
		    {
                list.resize(numBaseClasses);

			    // Get pointer
                ea_t baseClassArray = plat.getEa32(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
			    if(baseClassArray && (baseClassArray != BADADDR))
			    {
				    for(uint32_t i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(uint32_t))
				    {
                        // Get next BCD
                        ea_t bcd = get_32bit(baseClassArray);

                        // Get type name
                        ea_t typeInfo = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                        bcdInfo *bi = &list[i];
                        type_info_32::getName(typeInfo, bi->m_name, SIZESTR(bi->m_name));

					    // Add info to list
                        uint32_t mdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp)));
                        uint32_t pdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp)));
                        uint32_t vdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp)));
                        // As signed int
                        bi->m_pmd.mdisp = *((int32_t*) &mdisp);
                        bi->m_pmd.pdisp = *((int32_t*) &pdisp);
                        bi->m_pmd.vdisp = *((int32_t*) &vdisp);
                        bi->m_attribute = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));

					    //msg("   BN: [%d] \"%s\", ATB: %04X\n", i, szBuffer1, get_32bit((ea_t) &pBCD->attributes));
					    //msg("       mdisp: %d, pdisp: %d, vdisp: %d, attributes: %04X\n", *((PINT) &mdisp), *((PINT) &pdisp), *((PINT) &vdisp), attributes);
				    }
			    }
		    }
	    }
    }
    else
    {
        // 64bit version
        uint32_t cdOffset32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, classDescriptor));
        int64_t cdOffset64 = TO_INT64(cdOffset32);
        uint32_t objectLocator32 = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, objectBase));
        int64_t objectLocator64 = TO_INT64(objectLocator32);
        int64_t colBase64 = ((int64_t) col - objectLocator64);
        ea_t chd = (ea_t) (colBase64 + cdOffset64);

	    if(chd)
	    {
            if (numBaseClasses = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, numBaseClasses)))
		    {
                list.resize(numBaseClasses);

			    // Get pointer
                uint32_t bcaOffset32 = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, baseClassArray));
                int64_t bcaOffset64 = TO_INT64(bcaOffset32);
                ea_t baseClassArray = (ea_t) (colBase64 + bcaOffset64);
			    if(IS_VALID_ADDR(baseClassArray))
			    {
				    for(uint32_t i = 0; i < numBaseClasses; i++, baseClassArray += sizeof(uint32_t))
				    {
                        uint32_t bcdOffset32 = get_32bit(baseClassArray);
                        int64_t bcdOffset64 = TO_INT64(bcdOffset32);
                        ea_t bcd = (ea_t) (colBase64 + bcdOffset64);

                        uint32_t tdOffset32 = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, typeDescriptor));
                        int64_t tdOffset64 = TO_INT64(tdOffset32);
                        ea_t typeInfo = (ea_t) (colBase64 + tdOffset64);
                        bcdInfo *bi = &list[i];
                        type_info_64::getName(typeInfo, bi->m_name, SIZESTR(bi->m_name));

					    // Add info to list
                        uint32_t mdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, mdisp)));
                        uint32_t pdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, pdisp)));
                        uint32_t vdisp = get_32bit(bcd + (offsetof(_RTTIBaseClassDescriptor, pmd) + offsetof(PMD, vdisp)));
                        // As signed int
                        bi->m_pmd.mdisp = *((int32_t*) &mdisp);
                        bi->m_pmd.pdisp = *((int32_t*) &pdisp);
                        bi->m_pmd.vdisp = *((int32_t*) &vdisp);
                        bi->m_attribute = get_32bit(bcd + offsetof(_RTTIBaseClassDescriptor, attributes));

					    //msg("   BN: [%d] \"%s\", ATB: %04X\n", i, szBuffer1, get_32bit((ea_t) &pBCD->attributes));
					    //msg("       mdisp: %d, pdisp: %d, vdisp: %d, attributes: %04X\n", *((PINT) &mdisp), *((PINT) &pdisp), *((PINT) &vdisp), attributes);
				    }
			    }
		    }
	    }
    }
}


// ======================================================================================

// Process RTTI vftable info
// Returns true if if vftable and wasn't named on entry
bool RTTI::processVftable(ea_t vft, ea_t col, bool known)
{
	bool result = false;

    ea_t chd = BADADDR;
    ea_t typeInfo = BADADDR;
    if (!plat.is64)
    {
        // 32bit direct address
        chd = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, classDescriptor));
	    typeInfo = plat.getEa32(col + offsetof(_RTTICompleteObjectLocator_32, typeDescriptor));
    }
    else
	{
        // 64bit offsets relative to objectBase
		uint32_t tdOffset = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, typeDescriptor));
        uint32_t chdOffset = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, classDescriptor));
		uint32_t objectLocator = get_32bit(col + offsetof(_RTTICompleteObjectLocator_64, objectBase));

        ea_t colBase = (col - (ea_t) objectLocator);
        typeInfo = (colBase + (ea_t) tdOffset);
		chd = (colBase + (ea_t) chdOffset);
	}

    // Verify and fix if vftable exists here
    vftable::vtinfo vi;
    if(vftable::getTableInfo(vft, vi))
    {
	    // Get COL type name
        char colName[MAXSTR];
        type_info::getName(typeInfo, colName, SIZESTR(colName));
        char demangledColName[MAXSTR];
        getPlainTypeName(colName, demangledColName);

        uint32_t chdAttributes = get_32bit(chd + offsetof(_RTTIClassHierarchyDescriptor, attributes));
        uint32_t offset = get_32bit(col + offsetof(_RTTICompleteObjectLocator, offset));

	    // Parse BCD info
	    bcdList list;
        uint32_t numBaseClasses;
	    getBCDInfo(col, list, numBaseClasses);

        bool sucess = false, isTopLevel = false;
        qstring cmt;

	    // ======= Simple or no inheritance
        if ((offset == 0) && ((chdAttributes & (CHD_MULTINH | CHD_VIRTINH)) == 0))
	    {
		    // Set the vftable name
            if (!hasName(vft))
		    {
				result = true;

                // Decorate raw name as a vftable. I.E. const Name::`vftable'
                char decorated[MAXSTR];
                _snprintf_s(decorated, sizeof(decorated), SIZESTR(decorated), FORMAT_RTTI_VFTABLE, SKIP_TD_TAG(colName));
                setName(vft, decorated);
		    }

		    // Set COL name. I.E. const Name::`RTTI Complete Object Locator'
            if (!hasName(col))
            {
                char decorated[MAXSTR];
                _snprintf_s(decorated, sizeof(decorated), SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
                setName(col, decorated);
            }

		    // Build object hierarchy string
            int placed = 0;
            if (numBaseClasses > 1)
            {
                // Parent
                char plainName[MAXSTR];
                getPlainTypeName(list[0].m_name, plainName);
                cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
                placed++;
                isTopLevel = ((strcmp(list[0].m_name, colName) == 0) ? true : false);

                // Child object hierarchy
                for (uint32_t i = 1; i < numBaseClasses; i++)
                {
                    // Append name
                    getPlainTypeName(list[i].m_name, plainName);
                    cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;
                }

                // Nix the ending ',' for the last one
                if (placed > 1)
                    cmt.remove((cmt.length() - 2), 2);
            }
            else
            {
                // Plain, no inheritance object(s)
                cmt.sprnt("%s%s: ", ((colName[3] == 'V') ? "" : "struct "), demangledColName);
                isTopLevel = true;
            }

            if (placed > 1)
                cmt += ';';

            sucess = true;
	    }
	    // ======= Multiple inheritance, and, or, virtual inheritance hierarchies
        else
        {
            bcdInfo *bi = NULL;
            int index = 0;

            // Must be the top level object for the type
            if (offset == 0)
            {
                _ASSERT(strcmp(colName, list[0].m_name) == 0);
                bi = &list[0];
                isTopLevel = true;
            }
            else
            {
                // Get our object BCD level by matching COL offset to displacement
                for (uint32_t i = 0; i < numBaseClasses; i++)
                {
                    if (list[i].m_pmd.mdisp == offset)
                    {
                        bi = &list[i];
                        index = i;
                        break;
                    }
                }

                // If not found in list, use the first base object instead
                if (!bi)
                {
                    //msg("** %llX MI COL class offset: %X(%d) not in BCD.\n", vft, offset, offset);
                    for (uint32_t i = 0; i < numBaseClasses; i++)
                    {
                        if (list[i].m_pmd.pdisp != -1)
                        {
                            bi = &list[i];
                            index = i;
                            break;
                        }
                    }
                }
            }

            if (bi)
            {
                // Top object level layout
                int placed = 0;
                if (isTopLevel)
                {
                    // Set the vft name
                    if (!hasName(vft))
                    {
						result = true;

                        char decorated[MAXSTR];
                        _snprintf_s(decorated, sizeof(decorated), SIZESTR(decorated), FORMAT_RTTI_VFTABLE, SKIP_TD_TAG(colName));
                        setName(vft, decorated);
                    }

                    // COL name
                    if (!hasName(col))
                    {
                        char decorated[MAXSTR];
                        _snprintf_s(decorated, sizeof(decorated), SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
                        setName(col, decorated);
                    }

                    // Build hierarchy string starting with parent
                    char plainName[MAXSTR];
                    getPlainTypeName(list[0].m_name, plainName);
                    cmt.sprnt("%s%s: ", ((list[0].m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;

                    // Concatenate forward child hierarchy
                    for (uint32_t i = 1; i < numBaseClasses; i++)
                    {
                        getPlainTypeName(list[i].m_name, plainName);
                        cmt.cat_sprnt("%s%s, ", ((list[i].m_name[3] == 'V') ? "" : "struct "), plainName);
                        placed++;
                    }
                    if (placed > 1)
                        cmt.remove((cmt.length() - 2), 2);
                }
                else
                {
                    // Combine COL and CHD name
                    char combinedName[MAXSTR];
                    _snprintf_s(combinedName, sizeof(combinedName), SIZESTR(combinedName), "%s6B%s@", SKIP_TD_TAG(colName), SKIP_TD_TAG(bi->m_name));

                    // Set vftable name
                    if (!hasName(vft))
                    {
						result = true;

                        char decorated[MAXSTR];
						strcpy(decorated, FORMAT_RTTI_VFTABLE_PREFIX);
						strncat_s(decorated, MAXSTR, combinedName, (MAXSTR - (1 + SIZESTR(FORMAT_RTTI_VFTABLE_PREFIX))));
                        setName(vft, decorated);
                    }

                    // COL name
                    if (!hasName((ea_t) col))
                    {
						char decorated[MAXSTR];
						strcpy(decorated, FORMAT_RTTI_COL_PREFIX);
						strncat_s(decorated, MAXSTR, combinedName, (MAXSTR - (1 + SIZESTR(FORMAT_RTTI_COL_PREFIX))));
                        setName((ea_t) col, decorated);
                    }

                    // Build hierarchy string starting with parent
                    char plainName[MAXSTR];
                    getPlainTypeName(bi->m_name, plainName);
                    cmt.sprnt("%s%s: ", ((bi->m_name[3] == 'V') ? "" : "struct "), plainName);
                    placed++;

                    // Concatenate forward child hierarchy
                    if (++index < (int) numBaseClasses)
                    {
                        for (; index < (int) numBaseClasses; index++)
                        {
                            getPlainTypeName(list[index].m_name, plainName);
                            cmt.cat_sprnt("%s%s, ", ((list[index].m_name[3] == 'V') ? "" : "struct "), plainName);
                            placed++;
                        }
                        if (placed > 1)
                            cmt.remove((cmt.length() - 2), 2);
                    }
                }

                /*
                Experiment, maybe better this way to show before and after to show it's location in the hierarchy
                // Concatenate reverse child hierarchy
                if (--index >= 0)
                {
                    for (; index >= 0; index--)
                    {
                        getPlainTypeName(list[index].m_name, plainName);
                        cmt.cat_sprnt("%s%s, ", ((list[index].m_name[3] == 'V') ? "" : "struct "), plainName);
                        placed++;
                    }
                    if (placed > 1)
                        cmt.remove((cmt.length() - 2), 2);
                }
                */

                if (placed > 1)
                    cmt += ';';

                sucess = true;
            }
            else
                msg("%llX ** Couldn't find a BCD for MI/VI hierarchy!\n", vft);
        }

        if (sucess)
        {
            // Store entry
            addTableEntry(((chdAttributes & 0xF) | (isTopLevel ? RTTI::IS_TOP_LEVEL : 0)), vft, vi.methodCount, "%s@%s", demangledColName, cmt.c_str());

            // Add a separating comment above RTTI COL
			ea_t colPtr = (vft - plat.ptrSize);
			fixEa(colPtr);
			//cmt.cat_sprnt("  %s O: %d, A: %d  (#classinformer)", attributeLabel(chdAttributes, numBaseClasses), offset, chdAttributes);
			cmt.cat_sprnt(" %s (#classinformer)", attributeLabel(chdAttributes));
			if (!hasAnteriorComment(colPtr))
				setAnteriorComment(colPtr, "\n; %s %s", ((colName[3] == 'V') ? "class" : "struct"), cmt.c_str());

            result = true;
        }
    }
    else
	// Usually a typedef reference to a COL, not a vftable
    {
		#if 0
		qstring tmp;
		idaFlags2String(get_flags(vft), tmp);
        msg("%llX ** Vftable attached to this COL, error? (%s)\n", vft, tmp.c_str());
		#endif

        // Just set COL name
        if (!hasName(col))
        {
            char colName[MAXSTR];
            type_info::getName(typeInfo, colName, SIZESTR(colName));

            char decorated[MAXSTR];
            _snprintf_s(decorated, sizeof(decorated), SIZESTR(decorated), FORMAT_RTTI_COL, SKIP_TD_TAG(colName));
            setName(col, decorated);
        }
    }

	return result;
}


// ===============================================================================================

// New strategy: Since IDA's own internal RTTI system is so good now at leat at version 9, we'll
// first gather all the IDA defined ones into cache.
bool RTTI::gatherKnownRttiData()
{
	try
	{
        // RTTI type mangled name patterns
        #define PATE(_prefix, _verify, _eaSet) { _prefix, _verify, _eaSet }
        struct PATCE
        {
            const char * prefix;
            const char * verify;
            eaSet *set;
        } ALIGN(32) rttiTypePatterns[] =
        {
            PATE("??_R0", "`RTTI Type Descriptor'", &tdSet),
            PATE("??_R1", "`RTTI Base Class Descriptor", &bcdSet),
            PATE("??_R3", "`RTTI Class Hierarchy Descriptor'", &chdSet),
            PATE("??_R4", "`RTTI Complete Object Locator'", &colSet),
            PATE("??_7", "`vftable'", &vftSet)
        };

	    // Walk all names in the IDB
        TIMESTAMP startTime = GetTimeStamp();
	    size_t nameCount = get_nlist_size();
	    for (size_t i = 0; i < nameCount; i++)
	    {
            // Next name
            const char * name = get_nlist_name(i);
            for (size_t j = 0; j < _countof(rttiTypePatterns); j++)
            {
                // Match a known RTTI type pattern?
                PATCE &pe = rttiTypePatterns[j];
                if (strncmp(name, pe.prefix, strlen(pe.prefix)) == 0)
                {
				    // Yes
				    ea_t ea = get_nlist_ea(i);
                    /*
					// Verify it
					// Fails for many "??_R4" types
				    qstring qstr;
				    demangle_name(&qstr, name, MT_MSCOMP, DQT_FULL);
				    if (!strstr(qstr.c_str(), pe.verify))
					    msg(" ** 0x%llX \"%s\" \"%s\"\n", ea, pe.prefix, qstr.c_str());
                    */
                    pe.set->insert(ea);
                }
            }

            if(i % 1000)
			    if (WaitBox::isUpdateTime())
				    if (WaitBox::updateAndCancelCheck())
					    return true;
	    }
        TIMESTAMP endTime = (GetTimeStamp() - startTime);
        char buf1[32], buf2[32], buf3[32], buf4[32];
        msg("%s name search took: %s\n", NumberCommaString(nameCount, buf1), TimeString(endTime));
        msg("Totals: COL: %s, BCD: %s, CHD: %s, TD: %s\n", NumberCommaString(colSet.size(), buf1), NumberCommaString(bcdSet.size(), buf2), NumberCommaString(chdSet.size(), buf3), NumberCommaString(tdSet.size(), buf4));
        WaitBox::processIdaEvents();
        #undef PATE

        // Merge them all into a supper set
        superSet.clear();
	    std::vector<eaSet*> all = { &tdSet, &bcdSet, &chdSet, &colSet, &vftSet };
	    for (const eaSet *sp: all) superSet.insert(sp->begin(), sp->end());
	}
	CATCH()
    return false;
}
