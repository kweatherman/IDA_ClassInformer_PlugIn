
// Class Informer
#include "StdAfx.h"
#include "Main.h"
#include "Vftable.h"
#include "RTTI.h"
#include "MainDialog.h"
#include <map>

// Netnode constants
const static char NETNODE_NAME[] = {"$ClassInformer_node"};
const char NN_DATA_TAG  = 'A';
const char NN_TABLE_TAG = 'S';

/// Maximum length of strings or objects stored in a supval array element
// Commented out in "netnode.hpp"
const int MAXSPECSIZE = 1024;

// Our netnode value indexes
enum NETINDX
{
    NIDX_VERSION,   // ClassInformer version
    NIDX_COUNT      // Table entry count
};

// VFTable entry container (fits in a netnode MAXSPECSIZE size)
#pragma pack(push, 1)
struct TBLENTRY
{
    ea_t vft;
    uint16_t methods;
    uint16_t flags;
    uint16_t strSize;
    char str[MAXSPECSIZE - (sizeof(ea_t) + (sizeof(uint16_t) * 3))]; // Note: IDA MAXSTR = 1024
};
#pragma pack(pop)
static_assert(sizeof(TBLENTRY) == MAXSPECSIZE);

// Line background color for non parent/top level hierarchy lines
// TOOD: Assumes text background is white. A way to make these user theme/style color aware?
#define GRAY(v) RGB(v,v,v)
static const bgcolor_t NOT_PARENT_COLOR = GRAY(235);

// === Function Prototypes ===
static void cacheSegments();
static bool processStaticTables();
static void showEndStats();
static bool gatherRttiDataSet(SegSelect::segments &segs);

// === Data ===
static TIMESTAMP s_startTime = 0;
static uint32_t staticCCtorCnt = 0, staticCppCtorCnt = 0, staticCDtorCnt = 0;
static uint32_t startingFuncCount = 0, staticCtorDtorCnt = 0;
static bool initResourcesOnce = false;
static int chooserIcon = 0;
static netnode *netNode = NULL;
static std::vector<SEGMENT> segmentCache;
static eaList colList;

extern eaSet superSet, colSet, vftSet;

#define IN_SUPER(_addr) (superSet.find(_addr) != superSet.end())

// "_initterm*" Static ctor/dtor pattern container
struct INITTERM_ARGPAT
{
	const char *pattern;
	uint32_t start, end;
};
std::vector<INITTERM_ARGPAT> initTermArgPatterns;

// Options
bool g_optionPlaceStructs  = true;
bool g_optionProcessStatic = true;
bool g_optionAudioOnDone   = true;

static void freeWorkingData()
{
    try
    {
        RTTI::freeWorkingData();
        colList.clear();
        segmentCache.clear();
        initTermArgPatterns.clear();

        if (netNode)
        {
            delete netNode;
            netNode = NULL;
        }
    }
    CATCH()
}

// Initialize
plugmod_t* idaapi init()
{
    char procName[IDAINFO_PROCNAME_SIZE + 1] = { 0 };
    if(inf_get_procname(procName, sizeof(procName)) && (strncmp(procName, "metapc", IDAINFO_PROCNAME_SIZE) == 0))
	{
		return PLUGIN_KEEP;
	}

	return PLUGIN_SKIP;
}

// Uninitialize
// Normally doesn't happen as we need to stay resident for the modal windows
void idaapi term()
{
	try
	{
		OggPlay::endPlay();
		freeWorkingData();

		if (initResourcesOnce)
		{
			if (chooserIcon)
			{
				free_custom_icon(chooserIcon);
				chooserIcon = 0;
			}

			Q_CLEANUP_RESOURCE(ClassInformerRes);
			initResourcesOnce = false;
		}
	}
	CATCH()
}


// Init new netnode storage
#define DB_FORMAT_VERSION MAKEWORD(6, 0)
static void newNetnodeStore()
{
    // Kill any existing store data first
    netNode->altdel_all(NN_DATA_TAG);
    netNode->supdel_all(NN_TABLE_TAG);

    // Init defaults
    netNode->altset_idx8(NIDX_VERSION, DB_FORMAT_VERSION, NN_DATA_TAG);
    netNode->altset_idx8(NIDX_COUNT, 0, NN_DATA_TAG);
}

static uint16_t getStoreVersion(){ return((uint16_t) netNode->altval_idx8(NIDX_VERSION, NN_DATA_TAG)); }
static uint32_t getTableCount(){ return((uint32_t)netNode->altval_idx8(NIDX_COUNT, NN_DATA_TAG)); }
static bool setTableCount(uint32_t count){ return(netNode->altset_idx8(NIDX_COUNT, count, NN_DATA_TAG)); }
static bool getTableEntry(TBLENTRY &entry, uint32_t index){ return(netNode->supval(index, &entry, sizeof(TBLENTRY), NN_TABLE_TAG) > 0); }
static bool setTableEntry(TBLENTRY &entry, uint32_t index){ return(netNode->supset(index, &entry, (offsetof(TBLENTRY, str) + entry.strSize), NN_TABLE_TAG)); }

// Add an entry to the vftable list
void addTableEntry(uint32_t flags, ea_t vft, int methodCount, const char *format, ...)
{
	TBLENTRY e;
	e.vft = vft;
	e.methods = methodCount;
	e.flags = flags;

	va_list vl;
	va_start(vl, format);
	vsnprintf(e.str, sizeof(e.str), format, vl);
	va_end(vl);
	e.strSize = (uint16_t) (strlen(e.str) + 1);

	uint32_t count = getTableCount();
	setTableEntry(e, count);
	setTableCount(++count);
}


// RTTI list chooser
static const char LBTITLE[] = { "[Class Informer]" };
static const uint32_t LBCOLUMNCOUNT = 5;
static const int LBWIDTHS[LBCOLUMNCOUNT] = { (8 | CHCOL_HEX), (4 | CHCOL_DEC), 3, 19, 500 };
static const char *const LBHEADER[LBCOLUMNCOUNT] =
{
	"Vftable",
	"Methods",
	"Flags",
	"Type",
	"Hierarchy"
};

class rtti_chooser : public chooser_multi_t
{
public:
	rtti_chooser() : chooser_multi_t(CH_QFTYP_DEFAULT, LBCOLUMNCOUNT, LBWIDTHS, LBHEADER, LBTITLE)
	{
		// Create a minimal hex address format string w/leading zero
		uint32_t count = getTableCount();
		ea_t largestAddres = 0;
		for (uint32_t i = 0; i < count; i++)
		{
			TBLENTRY e; e.vft = 0;
			getTableEntry(e, i);
			if (e.vft > largestAddres)
				largestAddres = e.vft;
		}
        GetEaFormatString(largestAddres, addressFormat);

		// Chooser icon
		icon = chooserIcon;
	}

	virtual const void *get_obj_id(size_t *len) const
	{
		*len = sizeof(LBTITLE);
		return LBTITLE;
	}

	virtual size_t get_count() const { return (size_t)getTableCount(); }

	virtual void get_row(qstrvec_t *cols_, int *icon_, chooser_item_attrs_t *attributes, size_t n) const
	{
		try
		{
			if (netNode)
			{
				// Generate the line
				TBLENTRY e;
				getTableEntry(e, (uint32_t)n);

				// vft address
				qstrvec_t &cols = *cols_;
				cols[0].sprnt(addressFormat, e.vft);

				// Method count
				if (e.methods > 0)
					cols[1].sprnt("%u", e.methods); // "%04u"
				else
					cols[1].sprnt("???");

				// Flags
				char flags[4];
				int pos = 0;
				if (e.flags & RTTI::CHD_MULTINH)   flags[pos++] = 'M';
				if (e.flags & RTTI::CHD_VIRTINH)   flags[pos++] = 'V';
				if (e.flags & RTTI::CHD_AMBIGUOUS) flags[pos++] = 'A';
				flags[pos++] = 0;
				cols[2] = flags;

				// Type
				const char *tag = strchr(e.str, '@');
				if (tag)
				{
					char buffer[MAXSTR];
					int pos = (int)(tag - e.str);
					if (pos > (int)SIZESTR(buffer)) pos = (int)SIZESTR(buffer);
					memcpy(buffer, e.str, pos);
					buffer[pos] = 0;
					cols[3] = buffer;
					++tag;
				}
				else
				{
					// Can happen when string is MAXSTR and greater
					cols[3] = "??** MAXSTR overflow!";
					tag = e.str;
				}

				// Composition/hierarchy
				cols[4] = tag;

				//*icon_ = ((e.flags & RTTI::IS_TOP_LEVEL) ? 77 : 191);
				*icon_ = 191;

				// Indicate entry is not a top/parent level by color
				if (!(e.flags & RTTI::IS_TOP_LEVEL))
					attributes->color = NOT_PARENT_COLOR;
			}
		}
		CATCH()
	}

	virtual cbres_t enter(sizevec_t *sel)
	{
		size_t n = sel->front();
		if (n < get_count())
		{
			TBLENTRY e;
			getTableEntry(e, (uint32_t)n);
			jumpto(e.vft);
		}
		return NOTHING_CHANGED;
	}

	virtual void closed()
	{
		freeWorkingData();
	}

private:
	char addressFormat[20];
};


// Locate Qt widget by class name
static QWidget *findChildByClass(QWidgetList &wl, const char *className)
{
    Q_FOREACH(QWidget *w, wl)
    {
        if (strcmp(w->metaObject()->className(), className) == 0)
            return w;
    }
    return NULL;
}


// Find widget by title text
// If IDs are constant can use "static QWidget *QWidget::find(WId);"?
void customizeChooseWindow()
{
    try
    {
		QApplication::processEvents();

        // Mod the chooser view
        QWidgetList pl = QApplication::activeWindow()->findChildren<QWidget*>("[Class Informer]");
        if (QWidget *dw = findChildByClass(pl, "TChooser"))
        {
            QFile file(QT_RES_PATH "view-style.qss");
            if (file.open(QFile::ReadOnly | QFile::Text))
                dw->setStyleSheet(QTextStream(&file).readAll());
        }
        else
            msg("** customizeChooseWindow(): \"TChooser\" not found!\n");

        // Mod chooser widget to our own preferences
        if (QTableView *tv = (QTableView *) findChildByClass(pl, "tchooser_table_widget_t"))
        {
            // Set sort by type name
            tv->sortByColumn(3, Qt::DescendingOrder);

            // Resize to contents to push the class hierarchy view to the right
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
            tv->resizeColumnsToContents();
            tv->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

            // Tweak the row height
            uint32_t count = getTableCount();
            for (uint32_t row = 0; row < count; row++)
                tv->setRowHeight(row, 24);
        }
        else
            msg("** customizeChooseWindow(): \"tchooser_table_widget_t\" not found!\n");
    }
    CATCH()
}


bool idaapi run(size_t arg)
{
    try
    {
		qstring version;
        msg("\n>> Class Informer: v%s, built %s.\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);
		if (!auto_is_ok())
		{
			msg("** Class Informer: Must wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");
			return true;
		}
        WaitBox::processIdaEvents();

        // Configure platform specifics
        plat.Configure();

		if (!initResourcesOnce)
		{
			initResourcesOnce = true;
            QResource::registerResource(":/resources.qrc");

			QFile file(QT_RES_PATH "icon.png");
			if (file.open(QFile::ReadOnly))
			{
				QByteArray ba = file.readAll();
				chooserIcon = load_custom_icon(ba.constData(), ba.size(), "png");
			}
		}

        OggPlay::endPlay();
        freeWorkingData();
        g_optionAudioOnDone   = true;
        g_optionProcessStatic = true;
        g_optionPlaceStructs  = true;
        startingFuncCount   = (uint32_t) get_func_qty();
        staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;
        colList.clear();

        // Create storage netnode
        if(!(netNode = new netnode(NETNODE_NAME, SIZESTR(NETNODE_NAME), true)))
        {
            _ASSERT(false);
            return true;
        }

		// Read existing storage if any
        uint32_t tableCount   = getTableCount();
        uint16_t storageVersion = getStoreVersion();
        bool storageExists  = (tableCount > 0);

        // Ask if we should use storage or process again
		if (storageExists)
		{
			// Version 2.3 didn't change the format
			if (storageVersion != DB_FORMAT_VERSION)
			{
				msg("* Storage version mismatch, must rescan *\n");
                storageExists = false;
			}
			else
				storageExists = (ask_yn(1, "TITLE Class Informer \nHIDECANCEL\nUse previously stored result?        ") == 1);
		}

        bool aborted = false;
        if(!storageExists)
        {
            newNetnodeStore();

            // Only MS Visual C++ targets are known
            comp_t cmp = get_comp(default_compiler());
            if (cmp != COMP_MS)
            {
                msg("** IDA reports target compiler: \"%s\"\n", get_compiler_name(cmp));
                int iResult = ask_buttons(NULL, NULL, NULL, 0, "TITLE Class Informer\nHIDECANCEL\nIDA reports this IDB's compiler as: \"%s\" \n\nThis plug-in only understands MS Visual C++ targets.\nRunning it on other targets (like Borland compiled, etc.) will have unpredicted results.   \n\nDo you want to continue anyhow?", get_compiler_name(cmp));
                if (iResult != 1)
                {
                    msg("- Aborted -\n\n");
                    return true;
                }
            }

            // Do UI
			SegSelect::segments segs;
            if (doMainDialog(g_optionPlaceStructs, g_optionProcessStatic, g_optionAudioOnDone, segs, version, arg))
            {
                msg("- Canceled -\n\n");
				freeWorkingData();
                return true;
            }

            WaitBox::show("Class Informer", "Please wait..", "url(" QT_RES_PATH "progress-style.qss)", QT_RES_PATH "icon.png");
            WaitBox::updateAndCancelCheck(-1);
            s_startTime = GetTimeStamp();

			try
			{
                // Add RTTI type definitions to IDA once per session
                static bool createStructsOnce = false;
                if (g_optionPlaceStructs && !createStructsOnce)
                {
                    createStructsOnce = true;
                    RTTI::addDefinitionsToIda();
                }

                msg("Caching data and code segments:\n");
                WaitBox::processIdaEvents();
                cacheSegments();

                if(g_optionProcessStatic)
                {
                    // Process global and static ctor sections
                    msg("\nProcessing C/C++ ctor & dtor tables:\n");
				    msg("-------------------------------------------------\n");
                    WaitBox::processIdaEvents();
                    if (!(aborted = processStaticTables()))
                    {
                        //msg("Processing time: %s.\n", TimeString(GetTimeStamp() - s_startTime));
                    }
                }

                if (!aborted)
                {
                    // Get RTTI data
                    if (!(aborted = gatherRttiDataSet(segs)))
                    {
                        // Optionally play completion sound if processing took more than a few seconds to notify user
                        if (g_optionAudioOnDone)
                        {
                            TIMESTAMP endTime = (GetTimeStamp() - s_startTime);
                            if (endTime > (TIMESTAMP) 2.4)
                            {
                                OggPlay::endPlay();
                                QFile file(QT_RES_PATH "completed.ogg");
                                if (file.open(QFile::ReadOnly))
                                {
                                    QByteArray ba = file.readAll();
                                    OggPlay::playFromMemory((const void *)ba.constData(), ba.size(), true);
                                }
                            }
                        }

                        showEndStats();
                    }
                }
			}
			CATCH()

			WaitBox::hide();
            refresh_idaview_anyway();
            if (aborted)
            {
                msg("- Aborted -\n\n");
                return true;
            }
        }

        // Show list result window
        if (!aborted && (getTableCount() > 0))
        {
			// The chooser allocation will free it's self automatically
			rtti_chooser *chooserPtr = new rtti_chooser();
			chooserPtr->choose();

			customizeChooseWindow();
        }
    }
	CATCH()

	return true;
}

// Print out end stats
static void showEndStats()
{
    try
    {
        msg("\n-------------------------------------------------\n");
        char buffer[32];
		msg("RTTI vftables located: %s\n", NumberCommaString(getTableCount(), buffer));
		uint32_t functionsFixed = ((uint32_t) get_func_qty() - startingFuncCount);
		if(functionsFixed)
            msg("Missing functions fixed: %s\n", NumberCommaString(functionsFixed, buffer));

        msg("Done. Total processing time: %s\n\n", TimeString(GetTimeStamp() - s_startTime));
    }
    CATCH()
}


// ================================================================================================

// Fix/create label and comment C/C++ initializer tables
static void setIntializerTable(ea_t start, ea_t end, bool isCpp)
{
    try
    {
        if (uint32_t count = ((end - start) / plat.ptrSize))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                fixEa(ea);

                // Might fix missing/messed stubs
                if (ea_t func = plat.getEa(ea))
                    fixFunction(func);

                ea += (ea_t) plat.ptrSize;
            };

            // Start label
            if (!hasName(start))
            {
                char name[MAXSTR];
                if (isCpp)
                    snprintf(name, sizeof(name), "__xc_a_%d", staticCppCtorCnt);
                else
                    snprintf(name, sizeof(name), "__xi_a_%d", staticCCtorCnt);
                setName(start, name);
            }

            // End label
            if (!hasName(end))
            {
                char name[MAXSTR];
                if (isCpp)
                    snprintf(name, sizeof(name), "__xc_z_%d", staticCppCtorCnt);
                else
                    snprintf(name, sizeof(name), "__xi_z_%d", staticCCtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
            {
                if (isCpp)
					setAnteriorComment(start, "%d C++ static ctors (#classinformer)", count);
                else
					setAnteriorComment(start, "%d C initializers (#classinformer)", count);
            }
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                if (isCpp)
                {
					char comment[MAXSTR];
                    snprintf(comment, sizeof(comment), "%d C++ static ctors (#classinformer)", count);
                    setComment(start, comment, true);
                }
                else
                {
					char comment[MAXSTR];
                    snprintf(comment, sizeof(comment), "%d C initializers (#classinformer)", count);
                    setComment(start, comment, true);
                }
            }

            if (isCpp)
                staticCppCtorCnt++;
            else
                staticCCtorCnt++;
        }
    }
    CATCH()
}

// Fix/create label and comment C/C++ terminator tables
static void setTerminatorTable(ea_t start, ea_t end)
{
    try
    {
        if (uint32_t count = ((end - start) / plat.ptrSize))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                // Fix pointer as needed
                fixEa(ea);

                // Fix function as needed
                if (ea_t func = plat.getEa(ea))
                    fixFunction(func);

                ea += (ea_t) plat.ptrSize;
            };

            // Start label
            if (!hasName(start))
            {
                char name[MAXSTR];
                snprintf(name, sizeof(name), "__xt_a_%d", staticCDtorCnt);
                setName(start, name);
            }

            // End label
            if (!hasName(end))
            {
				char name[MAXSTR];
                snprintf(name, sizeof(name), "__xt_z_%d", staticCDtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
				setAnteriorComment(start, "%d C terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                char comment[MAXSTR];
                snprintf(comment, sizeof(comment), "%d C terminators (#classinformer)", count);
                setComment(start, comment, true);
            }

            staticCDtorCnt++;
        }
    }
    CATCH()
}

// "" for when we are uncertain of ctor or dtor type table
static void setCtorDtorTable(ea_t start, ea_t end)
{
    try
    {
        if (uint32_t count = ((end - start) / plat.ptrSize))
        {
            // Set table elements as pointers
            ea_t ea = start;
            while (ea <= end)
            {
                // Fix pointer as needed
                fixEa(ea);

                // Fix function as needed
                if (ea_t func = plat.getEa(ea))
                    fixFunction(func);

                ea += (ea_t) plat.ptrSize;
            };

            // Start label
            if (!hasName(start))
            {
                char name[MAXSTR];
                snprintf(name, sizeof(name), "__x?_a_%d", staticCtorDtorCnt);
                setName(start, name);
            }

            // End label
            if (!hasName(end))
            {
                char name[MAXSTR];
                snprintf(name, sizeof(name), "__x?_z_%d", staticCtorDtorCnt);
                setName(end, name);
            }

            // Comment
            // Never overwrite, it might be the segment comment
            if (!hasAnteriorComment(start))
				setAnteriorComment(start, "%d C initializers/terminators (#classinformer)", count);
            else
            // Place comment @ address instead
            if (!hasComment(start))
            {
                char comment[MAXSTR];
                snprintf(comment, sizeof(comment), "%d C initializers/terminators (#classinformer)", count);
                setComment(start, comment, true);
            }

            staticCtorDtorCnt++;
        }
    }
    CATCH()
}


// Process redister based _initterm()
static void processRegisterInitterm(ea_t start, ea_t end, ea_t call)
{
    if ((end != BADADDR) && (start != BADADDR))
    {
        // Should be in the same segment
        const SEGMENT *startSeg = FindCachedSegment(start);
        const SEGMENT *endSeg = FindCachedSegment(end);
        if ((startSeg && endSeg) && (startSeg == endSeg))
        {
            if (start > end)
                std::swap(start, end);

            msg("    %llX to %llX CTOR table.\n", start, end);
            setIntializerTable(start, end, true);
			if(!hasComment(call))
				setComment(call, "_initterm", true);
        }
        else
            msg("  ** Bad address range of  %llX, %llX for \"_initterm\" type ** <click address>.\n", start, end);
    }
}

static uint32_t doInittermTable(func_t *func, ea_t start, ea_t end, const char *name)
{
    uint32_t found = false;

    if ((start != BADADDR) && (end != BADADDR))
    {
        // Should be in the same segment
        const SEGMENT *startSeg = FindCachedSegment(start);
        const SEGMENT *endSeg = FindCachedSegment(end);
        if ((startSeg && endSeg) && (startSeg == endSeg))
        {
            if (start > end)
                std::swap(start, end);

            // Try to determine if we are in dtor or ctor section
            if (func)
            {
                qstring qstr;
                if (get_long_name(&qstr, func->start_ea) > 0)
                {
					char funcName[MAXSTR];
                    strncpy_s(funcName, MAXSTR, qstr.c_str(), (MAXSTR - 1));
                    _strlwr(funcName);

                    // Start/ctor?
                    if (strstr(funcName, "cinit") || strstr(funcName, "tmaincrtstartup") || strstr(funcName, "start"))
                    {
                        msg("     %llX to %llX CTOR table.\n", start, end);
                        setIntializerTable(start, end, true);
                        found = true;
                    }
                    else
                    // Exit/dtor function?
                    if (strstr(funcName, "exit"))
                    {
                        msg("     %llX to %llX DTOR table.\n", start, end);
                        setTerminatorTable(start, end);
                        found = true;
                    }
                }
            }

            if (!found)
            {
                // Fall back to generic assumption
                msg("     %llX to %llX CTOR/DTOR table.\n", start, end);
                setCtorDtorTable(start, end);
                found = true;
            }
        }
        else
            msg("    ** Miss matched segment table addresses  %llX, %llX for \"%s\" type **\n", start, end, name);
    }
    else
        msg("    ** Bad input address range of  %llX, %llX for \"%s\" type **\n", start, end, name);

    return(found);
}

// Process _initterm function
// Returns true if at least one found
static bool processInitterm(ea_t address, const char *name)
{
    msg("%llX process initterm: \"%s\" \n", address, name);
    uint32_t count = 0;

    // Walk xrefs
    ea_t xref = get_first_fcref_to(address);
    while (xref && (xref != BADADDR))
    {
        msg("   %llX \"%s\" xref.\n", xref, name);

        // Should be code
        if (is_code(get_flags(xref)))
        {
            do
            {
                // The most common are two instruction arguments
                // Back up two instructions
                ea_t instruction1 = prev_head(xref, 0);
                if (instruction1 == BADADDR)
                    break;
                ea_t instruction2 = prev_head(instruction1, 0);
                if (instruction2 == BADADDR)
                    break;

                // Bail instructions are past the function start now
                func_t *func = get_func(xref);
                if (func && (instruction2 < func->start_ea))
                {
                    //msg("    %llX arg2 outside of contained function **\n", func->start_ea);
                    break;
                }

                bool matched = false;
                uint32_t patternCount = (uint32_t) initTermArgPatterns.size();
                for (uint32_t i = 0; (i < patternCount) && !matched; i++)
                {
					ea_t match = FIND_BINARY(instruction2, xref, initTermArgPatterns[i].pattern);
					if (match != BADADDR)
					{
                        ea_t start, end;
                        if (!plat.is64)
                        {
							start = plat.getEa32(match + initTermArgPatterns[i].start);
							end = plat.getEa32(match + initTermArgPatterns[i].end);
                        }
                        else
                        {
							uint32_t startOffset = get_32bit(instruction1 + initTermArgPatterns[i].start);
							uint32_t endOffset = get_32bit(instruction2 + initTermArgPatterns[i].end);

							start = (instruction1 + 7 + *((int32_t *) &startOffset)); // TODO: 7 is hard coded instruction length, put this in arg2pat table?
							end = (instruction2 + 7 + *((int32_t *) &endOffset));
                        }

						msg("   %llX Two instruction pattern match #%d\n", match, i);
						count += doInittermTable(func, start, end, name);
						matched = true;
						break;
					}
                }

                if (!matched)
                    msg("  ** arguments not located!\n");

            } while (false);
        }
        else
            msg("   %llX ** \"%s\" xref is not code! **\n", xref, name);

        xref = get_next_fcref_to(address, xref);
    };

    if(count > 0)
        msg(" \n");
    return(count > 0);
}


// Cache code and data segments for fast indexing
static void cacheSegments()
{
    segmentCache.clear();

    // Special case for a single segment, probably from a binary blob
    int count = get_segm_qty();
    if (count == 1)
    {
        segment_t *seg = getnseg(0);
        SEGMENT ns = { seg->start_ea, seg->end_ea, (_CODE_SEG | _DATA_SEG) };

        // Max PE COFF segment names are 8 chars
        ns.name[0] = 0;
        qstring name;
        if (get_segm_name(&name, seg, 0) > 0)
            strncpy_s(ns.name, 9, name.c_str(), 8);
        segmentCache.push_back(ns);
    }
    else
    {
        for (int i = 0; i < count; i++)
        {
            if (segment_t *seg = getnseg(i))
            {
                uint32_t type = 0;
                if (seg->type == SEG_DATA)
                    type |= _DATA_SEG;
                else
                if (seg->type == SEG_CODE)
                    type |= _CODE_SEG;

                if (type)
                {
					SEGMENT ns = { seg->start_ea, seg->end_ea, type };
                    ns.name[0] = 0;
					qstring name;
					if (get_segm_name(&name, seg, 0) > 0)
						strncpy_s(ns.name, 9, name.c_str(), 8);
					segmentCache.push_back(ns);
                }
            }
        }
    }

    // Ensure sort by ascending address
	std::sort(segmentCache.begin(), segmentCache.end(), [](const SEGMENT &a, const SEGMENT &b) { return a.start < b.start; });
}

// Segment cache O(log n) binary search lookup
const SEGMENT *FindCachedSegment(ea_t addr)
{
    int left = 0;
    int right = (int) segmentCache.size();

    while (left != (right - 1))
    {
        int mid = (left + (right - left) / 2);
        if (addr <= segmentCache[mid - 1].end)
            right = mid;
        else
        if (addr >= segmentCache[mid].start)
            left = mid;
        else
        {
            // Gap between regions
            return NULL;
        }
    };

    const SEGMENT *seg = &segmentCache[left];
    if ((addr >= seg->start) && (addr <= seg->end))
        return seg;

    // Below or above all regions
    return NULL;
}

// Process global/static ctor & dtor tables.
// Returns true if user aborted
static bool processStaticTables()
{
    staticCppCtorCnt = staticCCtorCnt = staticCtorDtorCnt = staticCDtorCnt = 0;

    try
    {
        // _cinit()
        func_t *cinitFunc = NULL;
        ea_t cinitFuncEa = get_name_ea(inf_get_min_ea(), "_cinit");
        if (cinitFuncEa != BADADDR)
        {
            cinitFunc = get_func(cinitFuncEa);
            if (!cinitFunc)
            {
				// If pointer to code, the function is probably broken
				const SEGMENT *seg = FindCachedSegment(cinitFuncEa);
				if (seg && (seg->type & _CODE_SEG))
				{
					// So attempt to fix it
					fixFunction(cinitFuncEa);
					auto_wait();
                    cinitFunc = get_func(cinitFuncEa);
				}
            }
        }

		// Locate _initterm() and _initterm_e() functions
        static const char *inittermNames[] = { "_initterm", "_initterm_e" };
        std::map<ea_t, std::string> inittermMap;
        for (size_t i = 0; i < _countof(inittermNames); i++)
        {
			ea_t inittAddr = get_name_ea(inf_get_min_ea(), inittermNames[i]);
			if (inittAddr != BADADDR)
			{
				func_t *func = get_func(inittAddr);
                if (func)
                    inittermMap[func->start_ea] = inittermNames[i];
                else
                {
					const SEGMENT *seg = FindCachedSegment(inittAddr);
                    if (seg && (seg->type & _CODE_SEG))
                    {
                        fixFunction(inittAddr);
                        auto_wait();
						func_t *func = get_func(inittAddr);
						if (func)
							inittermMap[func->start_ea] = inittermNames[i];
                    }
                }
			}
        }

		if(WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(true);

        // Look for import versions
        {
            static const char *imports[] =
            {
                "__imp__initterm", "__imp__initterm_e"
            };

            for (uint32_t i = 0; i < _countof(imports); i++)
            {
                ea_t adress = get_name_ea(BADADDR, imports[i]);
                if (adress != BADADDR)
                {
                    if (inittermMap.find(adress) == inittermMap.end())
                    {
                        msg("%llX import: \"%s\".\n", adress, imports[i]);
                        inittermMap[adress] = imports[i];
                    }
                }
            }
        }

        // Process register based _initterm() calls inside _cint()
        if (cinitFunc)
        {
            struct CREPAT
            {
                const char *pattern;
                uint32_t start, end, call;
            } static const ALIGN(16) pat[] =
            {
                // TODO: Add more patterns as they are located
                { "B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 59 8B F8 3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1", 1, 6, 0x17},
                { "BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1", 1, 8, 0x17},
            };

            for (uint32_t i = 0; i < _countof(pat); i++)
            {
				ea_t match = FIND_BINARY(cinitFunc->start_ea, cinitFunc->end_ea, pat[i].pattern);
                while (match != BADADDR)
                {
                    msg("   %llX Register _initterm(), pattern #%d.\n", match, i);
                    ea_t start = plat.getEa(match + pat[i].start);
                    ea_t end   = plat.getEa(match + pat[i].end);
                    processRegisterInitterm(start, end, (match + pat[i].call));
					match = FIND_BINARY(match + 30, cinitFunc->end_ea, pat[i].pattern);
                };
            }
        }

        msg(" \n");
		if (WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(true);

        // Generate _initterm argument pattern table
		if (plat.is64)
		{
			// 64bit patterns
			initTermArgPatterns.push_back({ "48 8D 15 ?? ?? ?? ?? 48 8D 0D", 3, 3 }); // lea rdx,s, lea rcx,e
		}
		else
		{
			// 32bit patterns
            // TODO: Add more patterns as they are located
			initTermArgPatterns.push_back({ "68 ?? ?? ?? ?? 68", 6, 1 });       // push offset s, push offset e
			initTermArgPatterns.push_back({ "B8 ?? ?? ?? ?? C7 04 24", 8, 1 }); // mov [esp+4+var_4], offset s, mov eax, offset e
			initTermArgPatterns.push_back({ "68 ?? ?? ?? ?? B8", 6, 1 });       // mov eax, offset s, push offset e
		}

        // Process _initterm references
        for (const auto &[address, name]: inittermMap)
        {
            if (processInitterm(address, name.c_str()))
				if (WaitBox::isUpdateTime())
					if (WaitBox::updateAndCancelCheck())
						return(true);
        }

		if (WaitBox::isUpdateTime())
			if (WaitBox::updateAndCancelCheck())
				return(true);
    }
    CATCH()

    return(false);
}

// ================================================================================================


// Return true if address as a anterior comment
inline bool hasAnteriorComment(ea_t ea)
{
    return (get_first_free_extra_cmtidx(ea, E_PREV) != E_PREV);
}

// Force a memory location to be DWORD size
void fixDword(ea_t ea)
{
	if (!is_dword(get_flags(ea)))
	{
		setUnknown(ea, sizeof(uint32_t));
		create_dword(ea, sizeof(uint32_t), true);
        auto_wait();
	}
}

// Force memory location to be ea_t size
void fixEa(ea_t ea)
{
	if (!plat.is64)
	{
		// 32bit
		if (!is_dword(get_flags(ea)))
		{
			setUnknown(ea, sizeof(uint32_t));
			create_dword(ea, sizeof(uint32_t), true);
            auto_wait();
		}
	}
	else
	{
		// If already a QWORD size value here it's good
		if (!is_qword(get_flags(ea)))
		{
			setUnknown(ea, sizeof(uint64_t));
			create_qword(ea, sizeof(uint64_t), true);
            auto_wait();
		}
	}
}

// Get IDA EA bit value with verification
bool getVerifyEa(ea_t ea, ea_t &rValue)
{
	// Location valid?
	if (IS_VALID_ADDR(ea))
	{
		// Get ea_t value
		rValue = plat.getEa(ea);
		return true;
	}

	return false;
}

// Address should be a code function
void fixFunction(ea_t ea)
{
	// No code here?
    flags_t flags = get_flags(ea);
    if (!is_code(flags))
    {
		// Attempt to make it so
        create_insn(ea);
        add_func(ea, BADADDR);
    }
    else
	// Yea there is code here, should have a function body too
    if (!is_func(flags))
        add_func(ea, BADADDR);
}


// Undecorate to minimal class name
// typeid(T).name()
// http://en.wikipedia.org/wiki/Name_mangling
// http://en.wikipedia.org/wiki/Visual_C%2B%2B_name_mangling
// http://www.agner.org/optimize/calling_conventions.pdf
bool getPlainTypeName(const char *mangled, char *outStr)
{
    outStr[0] = outStr[MAXSTR - 1] = 0;

    // Use demangler for type names
    if (mangled[0] == '.')
    {
        __unDName(outStr, mangled + 1, MAXSTR, mallocWrap, free, (UNDNAME_32_BIT_DECODE | UNDNAME_TYPE_ONLY | UNDNAME_NO_ECSU));
        if ((outStr[0] == 0) || (strcmp((mangled + 1), outStr) == 0))
        {
            msg("** getPlainClassName:__unDName() failed to unmangle! input: \"%s\"\n", mangled);
            return false;
        }
    }
    else
    // IDA demangler for everything else
    {
        qstring qstr;
        int result = demangle_name(&qstr, mangled, M_COMPILER /*MT_MSCOMP*/, DQT_FULL);
        if (result < 0)
        {
            //msg("** getPlainClassName:demangle_name2() failed to unmangle! result: %d, input: \"%s\"\n", result, mangled);
            return false;
        }

        // No inhibit flags will drop this
        strncpy_s(outStr, MAXSTR, qstr.c_str(), (MAXSTR - 1));
        if (char *ending = strstr(outStr, "::`vftable'"))
            *ending = 0;
    }

    return true;
}


// Set name for address
void setName(ea_t ea, const char *name)
{
	set_name(ea, name, (SN_NON_AUTO | SN_NOWARN | SN_NOCHECK | SN_FORCE));
    //msg("setName: %llX \"%s\"\n", ea, name);
}

// Set comment at address
void setComment(ea_t ea, const char *comment, bool rptble)
{
	set_cmt(ea, comment, rptble);
    //msg("setComment: %llX \"%s\"\n", ea, comment);
}

// Set comment at the line above the address
void setAnteriorComment(ea_t ea, const char *format, ...)
{
	va_list va;
	va_start(va, format);
	vadd_extra_line(ea, 0, format, va);
	va_end(va);
    //msg("setAnteriorComment: %llX\n", ea);
}


// Scan segment for COLs
static bool scanSeg4Cols(segment_t *seg)
{
	qstring name;
    if (get_segm_name(&name, seg) <= 0)
		name = "???";
    msg("N: \"%s\", %llX - %llX, S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));
    uint32_t newCount = 0, existingCount = 0;
    WaitBox::processIdaEvents();

    size_t colSize = (plat.is64 ? sizeof(RTTI::_RTTICompleteObjectLocator_64) : sizeof(RTTI::_RTTICompleteObjectLocator_32));
    if (seg->size() >= colSize)
    {
		ea_t startEA = ((seg->start_ea + plat.ptrSize) & ~((ea_t) plat.ptrSize - 1));
        ea_t endEA   = (seg->end_ea - colSize);

        for (ea_t ptr = startEA; ptr < endEA;)
        {
            if (!plat.is64)
            {
				// 32bit
                if (!IN_SUPER(ptr))
                {
                    // TypeDescriptor address here?
                    ea_t ea = plat.getEa(ptr);
                    if (!plat.isBadAddress(ea))
                    {
                        if (RTTI::type_info_32::isValid(ea))
                        {
                            // yes, a COL here?
                            ea_t col = (ptr - offsetof(RTTI::_RTTICompleteObjectLocator_32, typeDescriptor));
                            if (RTTI::_RTTICompleteObjectLocator_32::isValid2(col))
                            {
                                // yes
                                //msg("%llX located COL.\n", col);
                                colList.push_back(col);
                                newCount++;
                                RTTI::_RTTICompleteObjectLocator_32::tryStruct(col);
                                ptr += sizeof(RTTI::_RTTICompleteObjectLocator_32);
                                continue;
                            }
                        }
                    }
                }
				else
				{
					if (colSet.find(ptr) != colSet.end())
						existingCount++;
				}
            }
            else
            {
                // 64bit
                if (!IN_SUPER(ptr))
                {
                    // Check for possible COL here
                    // Signature will be one
                    // TODO: Is this always 1 or can it be zero like 32bit?
                    if (get_32bit(ptr + offsetof(RTTI::_RTTICompleteObjectLocator_64, signature)) == 1)
                    {
                        if (RTTI::_RTTICompleteObjectLocator_64::isValid(ptr))
                        {
                            // yes
                            //msg("%llX located COL.\n", ptr);
                            colList.push_back(ptr);
                            newCount++;
                            RTTI::_RTTICompleteObjectLocator_64::tryStruct(ptr);
                            ptr += sizeof(RTTI::_RTTICompleteObjectLocator_64);
                            continue;
                        }
                    }
                    else
                    {
                        // TODO: Should we check stray BCDs?
                        // Each value would have to be tested for a valid type_def and the pattern is pretty ambiguous.
                    }
                }
                else
                {
					if (colSet.find(ptr) != colSet.end())
						existingCount++;
                }
            }

            if(ptr % 1000)
                if (WaitBox::isUpdateTime())
                    if (WaitBox::updateAndCancelCheck())
                        return true;

            ptr += (ea_t) plat.ptrSize;
        }
    }

    if (newCount)
    {
        char numBuffer[32];
        msg(" Found: %s\n", NumberCommaString(newCount, numBuffer));
    }
	if (existingCount)
	{
		char numBuffer[32];
		msg(" Existing: %s\n", NumberCommaString(existingCount, numBuffer));
	}
    return false;
}

// Locate COL by descriptor list
static bool findCols(SegSelect::segments &segs)
{
    try
    {
		// Use user selected segments
        TIMESTAMP startTime = GetTimeStamp();
		if (!segs.empty())
		{
            for (auto &seg: segs)
			{
				if (scanSeg4Cols(&seg))
					return false;
			}
		}
		else
		// Scan data segments named
		{
			for (int i = 0; i < get_segm_qty(); i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Cols(seg))
							return false;
					}
				}
			}
		}

        char numBuffer[32];
        msg("%s total new COLs located in %s.\n", NumberCommaString(colList.size(), numBuffer), TimeString(GetTimeStamp() - startTime));
        WaitBox::processIdaEvents();

        // Append it to the colSet
        for (auto &addr: colList)
            colSet.insert(addr);
        colList.clear();
    }
    CATCH()
    return false;
}


// Locate virtual function tables (vftable)
static bool scanSeg4Vftables(segment_t *seg)
{
	qstring name;
	if (get_segm_name(&name, seg) <= 0)
		name = "???";
	msg("N: \"%s\", %llX - %llX, S: %s.\n", name.c_str(), seg->start_ea, seg->end_ea, byteSizeString(seg->size()));
    uint32_t foundCount = 0;
    WaitBox::processIdaEvents();

    if (seg->size() >= (asize_t)plat.ptrSize)
    {
        // The default for vftable alignment is native pointer size
        ea_t startEA = ((seg->start_ea + plat.ptrSize) & ~((ea_t) plat.ptrSize - 1));
        ea_t endEA   = (seg->end_ea - plat.ptrSize);

		// Walk pointer at the time..
        for (ea_t ptr = startEA; ptr < endEA; ptr += (ea_t) plat.ptrSize)
        {
            // Points to a known COL?
            ea_t colEa = plat.getEa(ptr);
            if (colSet.find(colEa) != colSet.end())
            {
                // yes, look for vftable one pointer below
                ea_t vfptr = (ptr + (ea_t) plat.ptrSize);

                // Already known?
                if (vftSet.find(vfptr) != vftSet.end())
                {
                    // Yes, process it now
                    RTTI::processVftable(vfptr, colEa, true);
                    foundCount++;
                }
                else
                {
                    // Points to code?
                    ea_t method = plat.getEa(vfptr);
                    const SEGMENT *methodSeg = FindCachedSegment(method);
                    if (methodSeg && (methodSeg->type & _CODE_SEG))
                    {
                        // Yes, see if vftable here
                        foundCount += (uint32_t) RTTI::processVftable(vfptr, colEa);
                    }
                }
            }

            if(ptr % 1000)
                if (WaitBox::isUpdateTime())
                    if (WaitBox::updateAndCancelCheck())
                        return true;
        }
    }

	if (foundCount)
	{
		char numBuffer[32];
		msg(" Found: %s\n", NumberCommaString(foundCount, numBuffer));
	}
    return false;
}

static bool findVftables(SegSelect::segments &segs)
{
    try
    {
        TIMESTAMP startTime = GetTimeStamp();

		// User selected segments
		if (!segs.empty())
		{
            for (auto &seg: segs)
			{
				if (scanSeg4Vftables(&seg))
					return false;
			}
		}
		else
		// Scan data segments named
		{
			int segCount = get_segm_qty();
			for (int i = 0; i < segCount; i++)
			{
				if (segment_t *seg = getnseg(i))
				{
					if (seg->type == SEG_DATA)
					{
						if (scanSeg4Vftables(seg))
							return false;
					}
				}
			}
		}

        msg("Vftable scan took: %s\n", TimeString(GetTimeStamp() - startTime));
        WaitBox::processIdaEvents();
    }
    CATCH()
    return false;
}


// ================================================================================================

// Gather RTTI data set
static bool gatherRttiDataSet(SegSelect::segments &segs)
{
    // Free RTTI working data on return
    struct OnReturn  { ~OnReturn(){	RTTI::freeWorkingData(); };} onReturn;

    try
    {
        // Gather known types by name from IDA RTTI places and/or PDB placed names
		msg("\nLocating IDA placed RTTI types by name:\n");
        msg("-------------------------------------------------\n");
        WaitBox::processIdaEvents();
        if(RTTI::gatherKnownRttiData())
            return true;

        // ==== Find and process Complete Object Locators (COL)
        msg("\nScanning for for Complete Object Locators:\n");
		msg("-------------------------------------------------\n");
        WaitBox::processIdaEvents();
        if(findCols(segs))
            return true;

        // ==== Find and process vftables
        msg("\nScanning for Virtual Function Tables:\n");
		msg("-------------------------------------------------\n");
        WaitBox::processIdaEvents();
        if(findVftables(segs))
			return true;
    }
    CATCH()

    return false;
}


// ================================================================================================

static char _comment[] = "Class Informer: Locates and fixes C++ Run Time Type class and structure information.";
static char _help[] = "";
static char _name[] = "ClassInformer";

// Plug-in description block
#ifdef _MSC_VER
__declspec(dllexport)
#endif
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
    PLUGIN_PROC,        // Plug-in flags
	init,	            // Initialization function
	term,	            // Clean-up function
	run,	            // Main plug-in body
	_comment,	        // Comment
	_help,	            // Help
	_name,	            // Plug-in name shown in Edit->Plugins menu
	"Alt-2"             // Hot key to run the plug-in
};
