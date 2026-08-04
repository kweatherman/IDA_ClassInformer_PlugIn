
// Run-Time Type Information (RTTI) support
#pragma once

namespace RTTI
{
	#pragma pack(push, 1)

	// std::type_info, aka "_TypeDescriptor" and "_RTTITypeDescriptor" in CRT source, class representation
	struct type_info
	{
		static bool isValid(ea_t typeInfo);
		static bool isTypeName(ea_t name);
		static int  getName(ea_t typeInfo, char * buffer, int bufferSize);
		static void tryStruct(ea_t typeInfo);
	};

	#ifdef _MSC_VER
	#pragma warning(push)
	#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union
	#endif
    struct type_info_32 : type_info
	{
        EA_32 vfptr;	  // 00 type_info class vftable
        EA_32 _M_data;    // 04 NULL until loaded at runtime.
		char _M_d_name[]; // 08 Mangled name (prefix: .?AV=classes, .?AU=structs)
    };

	struct type_info_64 : type_info
	{
		ea_t vfptr;	      // 00 type_info class vftable
		ea_t _M_data;     // 08 NULL until loaded at runtime.
		char _M_d_name[]; // 10 Mangled name (prefix: .?AV=classes, .?AU=structs)
	};
	#ifdef _MSC_VER
	#pragma warning(pop)
	#endif

    // Pointer to Member Data: generalized pointer-to-member descriptor
	struct PMD
	{
		int mdisp;	// 00 Member displacement, "Offset of intended data within base"
		int pdisp;  // 04 Vftable displacement, "Displacement to virtual base pointer"
		int vdisp;  // 08 Displacement inside vftable, "Index within vbTable to offset of base"
	};

	// "Base Class Descriptor" (BCD)
    // Describes all base classes together with information to derived class access dynamically
    // attributes flags
    const uint32_t BCD_NOTVISIBLE          = 0x01;
    const uint32_t BCD_AMBIGUOUS           = 0x02;
    const uint32_t BCD_PRIVORPROTINCOMPOBJ = 0x04;
    const uint32_t BCD_PRIVORPROTBASE      = 0x08;
    const uint32_t BCD_VBOFCONTOBJ         = 0x10;
    const uint32_t BCD_NONPOLYMORPHIC      = 0x20;
    const uint32_t BCD_HASPCHD             = 0x40; // pClassDescriptor field is present
//
    struct _RTTIBaseClassDescriptor
	{
		int typeDescriptor;			// 00 Image relative offset of TypeDescriptor. Pointer EA_32 for 32bit, offset added to COL base ea_t for 64bit
		uint32_t numContainedBases;   // 04 Number of nested classes following in the Base Class Array
		PMD pmd;					// 08 Pointer-to-member displacement info
		uint32_t attributes;			// 0C Flags
		int classDescriptor;		// 10 Image relative offset of _RTTIClassHierarchyDescriptor. If "attributes" & BCD_HASPCHD

        static bool isValid(ea_t bcd, int64_t colBase64 = 0);
        static void tryStruct(ea_t bcd, char * baseClassName, int64_t colBase64 = 0);
	};

    // "Class Hierarchy Descriptor" (CHD) describes the inheritance hierarchy of a class; shared by all COLs for the class
    // attributes flags
    const uint32_t CHD_MULTINH   = 0x01;    // Multiple inheritance
    const uint32_t CHD_VIRTINH   = 0x02;    // Virtual inheritance
    const uint32_t CHD_AMBIGUOUS = 0x04;    // Ambiguous inheritance

    struct _RTTIClassHierarchyDescriptor
	{
		uint32_t signature;		// 00 Zero until loaded
		uint32_t attributes;		// 04 Flags
		uint32_t numBaseClasses;	// 08 Number of classes in the following 'baseClassArray'
        int baseClassArray;     // 0C _RTTIBaseClassArray*. Pointer EA_32 for 32bit, offset added to COL base ea_t for 64bit

        static bool isValid(ea_t chd, int64_t colBase64 = 0);
        static void tryStruct(ea_t chd, int64_t colBase64 = 0);
	};

	#if 0
	typedef const struct _s_RTTIBaseClassArray
	{
		#ifdef __X64__
		int	arrayOfBaseClassDescriptors[];  // Image relative offset of _RTTIBaseClassDescriptor
		#else
		_RTTIBaseClassDescriptor* arrayOfBaseClassDescriptors[];
		#endif
	} _RTTIBaseClassArray;
	#endif

    // "Complete Object Locator" (COL) location of the complete object from a specific vftable pointer
	struct _RTTICompleteObjectLocator
	{
		uint32_t signature;		// 00 32bit zero, 64bit one, until loaded
		uint32_t offset;			// 04 Offset of this vftable in the complete class
		uint32_t cdOffset;		// 08 Constructor displacement offset
		int typeDescriptor;	    // 0C (type_info *) of the complete class. Pointer EA_32 for 32bit, offset added to ea_t for 64bit
		int classDescriptor;	// 10 (_RTTIClassHierarchyDescriptor *) Describes inheritance hierarchy. Pointer EA_32 for 32bit, offset added to ea_t for 64bit

		static bool isValid(ea_t col);
		static bool tryStruct(ea_t col);
	};

	struct _RTTICompleteObjectLocator_32 : _RTTICompleteObjectLocator
	{
		static bool isValid2(ea_t col);
	};

    struct _RTTICompleteObjectLocator_64 : _RTTICompleteObjectLocator
	{
        int objectBase;  // 14 Object base offset (base = ptr col - objectBase)
	};
	#pragma pack(pop)

    const uint16_t IS_TOP_LEVEL = 0x8000;

    void freeWorkingData();
	void addDefinitionsToIda();
	bool gatherKnownRttiData();
    bool processVftable(ea_t eaTable, ea_t col, bool known = false);
}

