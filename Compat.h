
// Cross-platform compatibility layer
// Replaces: Utility.h, undname.h, WaitBoxEx.h, IdaOgg.h, SegSelect.h
#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <cassert>

// IDA SDK
#include <ida.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>

// ============================================================================
// Windows type replacements
// ============================================================================
#ifndef _WIN32
typedef int32_t  BOOL;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  INT32;
typedef int64_t  INT64;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef char*    LPSTR;
typedef const char* LPCSTR;
typedef int32_t* PINT32;
typedef uint32_t* PDWORD;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef NULL
#define NULL nullptr
#endif

#define RGB(r,g,b) ((uint32_t)(((uint8_t)(r)) | (((uint32_t)(uint8_t)(g)) << 8) | (((uint32_t)(uint8_t)(b)) << 16)))
#define MAKEWORD(lo, hi) ((WORD)(((uint8_t)(lo)) | (((WORD)(uint8_t)(hi)) << 8)))
#define ZeroMemory(p, sz) memset((p), 0, (sz))

// SAL annotations (no-ops on non-MSVC)
#define __in
#define __out
#define __in_opt
#define __out_bcount(s)

// MSVC safe string replacements
inline int sprintf_s(char* buf, size_t bufSize, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int r = vsnprintf(buf, bufSize, fmt, args);
    va_end(args);
    return r;
}

inline int _snprintf_s(char* buf, size_t bufSize, size_t maxCount, const char* fmt, ...) {
    (void)maxCount;
    va_list args;
    va_start(args, fmt);
    int r = vsnprintf(buf, bufSize, fmt, args);
    va_end(args);
    return r;
}

inline int vsnprintf_s(char* buf, size_t bufSize, size_t maxCount, const char* fmt, va_list args) {
    (void)maxCount;
    return vsnprintf(buf, bufSize, fmt, args);
}

inline errno_t strncpy_s(char* dest, size_t destSize, const char* src, size_t count) {
    if (!dest || destSize == 0) return -1;
    size_t n = (count < destSize - 1) ? count : destSize - 1;
    strncpy(dest, src, n);
    dest[n] = '\0';
    return 0;
}

inline errno_t strncat_s(char* dest, size_t destSize, const char* src, size_t count) {
    if (!dest || destSize == 0) return -1;
    size_t dlen = strlen(dest);
    size_t remaining = destSize - dlen - 1;
    size_t n = (count < remaining) ? count : remaining;
    strncat(dest, src, n);
    return 0;
}

inline char* _strlwr(char* str) {
    for (char* p = str; *p; ++p) *p = (char)tolower((unsigned char)*p);
    return str;
}

inline errno_t strcpy_s(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return -1;
    strncpy(dest, src, destSize - 1);
    dest[destSize - 1] = '\0';
    return 0;
}

inline char* _itoa(int val, char* buf, int radix) {
    if (radix == 10) { snprintf(buf, 64, "%d", val); return buf; }
    if (radix == 16) { snprintf(buf, 64, "%x", val); return buf; }
    snprintf(buf, 64, "%d", val);
    return buf;
}

#endif // !_WIN32

// Sign-extend uint32_t to int64_t (reinterpret as signed 32-bit then widen)
#define TO_INT64(_uint32) ((int64_t)(int32_t)(_uint32))

// ============================================================================
// Common macros (needed on all platforms)
// ============================================================================
#ifndef SIZESTR
#define SIZESTR(s) (sizeof(s) - 1)
#endif

#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef IS_VALID_ADDR
#define IS_VALID_ADDR(ea) ((ea) != 0 && (ea) != BADADDR)
#endif

#ifndef ALIGN
  #ifdef _MSC_VER
    #define ALIGN(n) __declspec(align(n))
  #else
    #define ALIGN(n) __attribute__((aligned(n)))
  #endif
#endif

// _ASSERT: use cassert in debug, no-op in release
#ifdef _DEBUG
  #define _ASSERT(expr) assert(expr)
#else
  #define _ASSERT(expr) ((void)0)
#endif

// CATCH macro for exception handling
#define CATCH() catch (...) { msg("** Exception in %s()! ***\n", __FUNCTION__); }

// __LOC2__ for pragma message (MSVC only, no-op elsewhere)
#ifdef _MSC_VER
  #define __LOC2__ __FILE__ "(" QSTRINGIZE(__LINE__) ")"
  #define QSTRINGIZE(x) QSTRINGIZE2(x)
  #define QSTRINGIZE2(x) #x
#endif

// EA_32 type
typedef uint32_t EA_32;

// ============================================================================
// Timestamp / timing utilities
// ============================================================================
typedef double TIMESTAMP;

inline TIMESTAMP GetTimeStamp()
{
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

inline const char* TimeString(TIMESTAMP t)
{
    static char buf[64];
    if (t < 60.0)
        snprintf(buf, sizeof(buf), "%.2f seconds", t);
    else if (t < 3600.0)
        snprintf(buf, sizeof(buf), "%.1f minutes", t / 60.0);
    else
        snprintf(buf, sizeof(buf), "%.1f hours", t / 3600.0);
    return buf;
}

// ============================================================================
// Number/string formatting utilities
// ============================================================================
inline const char* NumberCommaString(size_t n, char* buf)
{
    // Simple: just format with commas
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%zu", n);
    int len = (int)strlen(tmp);
    int commas = (len - 1) / 3;
    int total = len + commas;
    buf[total] = '\0';
    int j = total - 1;
    for (int i = len - 1, c = 0; i >= 0; i--, c++) {
        if (c > 0 && c % 3 == 0)
            buf[j--] = ',';
        buf[j--] = tmp[i];
    }
    return buf;
}

inline const char* byteSizeString(asize_t size)
{
    static char buf[64];
    if (size < 1024)
        snprintf(buf, sizeof(buf), "%u bytes", (unsigned)size);
    else if (size < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f KB", size / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%.1f MB", size / (1024.0 * 1024.0));
    return buf;
}

// Version string utilities
#ifndef MAKE_SEMANTIC_VERSION
#define VERSION_RELEASE 0
#define MAKE_SEMANTIC_VERSION(type, major, minor, patch) \
    (((uint32_t)(major) << 16) | ((uint32_t)(minor) << 8) | (uint32_t)(patch))
#endif

inline qstring& GetVersionString(uint32_t ver, qstring& out)
{
    out.sprnt("%d.%d.%d", (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF);
    return out;
}

// Format string for EA display with leading zeros
inline void GetEaFormatString(ea_t maxAddr, char* fmt)
{
    int digits = 0;
    ea_t tmp = maxAddr;
    while (tmp > 0) { digits++; tmp >>= 4; }
    if (digits < 8) digits = 8;
    if (digits > 16) digits = 16;
#ifdef __EA64__
    snprintf(fmt, 20, "%%0%d" FMT_64 "X", digits);
#else
    snprintf(fmt, 20, "%%0%dX", digits);
#endif
}

// ============================================================================
// Binary pattern search wrapper
// ============================================================================
inline ea_t findBinary(ea_t startEA, ea_t endEA, const char* pattern)
{
    compiled_binpat_vec_t bv;
    if (!parse_binpat_str(&bv, startEA, pattern, 16))
        return BADADDR;
    return bin_search(startEA, endEA, bv, BIN_SEARCH_FORWARD);
}
#define FIND_BINARY(start, end, pattern) findBinary(start, end, pattern)

// ============================================================================
// Platform abstraction (replaces Utility.h plat object)
// ============================================================================
struct PlatformInfo
{
    bool is64;
    int ptrSize;

    void Configure()
    {
        is64 = inf_is_64bit();
        ptrSize = is64 ? 8 : 4;
    }

    ea_t getEa(ea_t addr) const
    {
        return is64 ? get_64bit(addr) : (ea_t)get_32bit(addr);
    }

    ea_t getEa32(ea_t addr) const
    {
        return (ea_t)get_32bit(addr);
    }

    bool isEa(flags_t flags) const
    {
        return is64 ? is_qword(flags) : is_dword(flags);
    }

    bool isBadAddress(ea_t addr) const
    {
        return (addr == 0 || addr == BADADDR);
    }
};

// Global platform instance
inline PlatformInfo& getPlatform()
{
    static PlatformInfo p;
    return p;
}
#define plat getPlatform()

// ============================================================================
// WaitBox replacement (uses IDA's built-in wait box)
// ============================================================================
namespace WaitBox
{
    inline void show(const char* /*title*/, const char* message, ...)
    {
        show_wait_box("%s", message);
    }

    inline void hide()
    {
        hide_wait_box();
    }

    inline bool updateAndCancelCheck(int = 0)
    {
        return user_cancelled();
    }

    inline bool isUpdateTime()
    {
        // Throttle UI updates to avoid overhead
        static clock_t last = 0;
        clock_t now = clock();
        if ((now - last) > (CLOCKS_PER_SEC / 5)) // ~200ms
        {
            last = now;
            return true;
        }
        return false;
    }

    inline void processIdaEvents()
    {
        // Allow IDA to process pending UI events
        request_refresh(IWID_ALL);
    }
}

// ============================================================================
// SegSelect replacement (segment selection dialog using IDA's chooser)
// ============================================================================
namespace SegSelect
{
    using segments = std::vector<segment_t>;
    enum { DATA_HINT = 1, RDATA_HINT = 2 };

    // Segment chooser that allows multi-selection
    struct SegChooser : public chooser_multi_t
    {
        static const int widths_[];
        static const char *const header_[];

        segments* result;
        std::vector<segment_t> allSegs;
        int hints;

        SegChooser(segments* out, int h, const char* ttl)
            : chooser_multi_t(CH_MODAL | CH_KEEP, 4, widths_, header_, ttl),
              result(out), hints(h)
        {
            for (int i = 0; i < get_segm_qty(); i++)
            {
                if (segment_t* seg = getnseg(i))
                    allSegs.push_back(*seg);
            }
        }

        size_t idaapi get_count() const override { return allSegs.size(); }

        void idaapi get_row(qstrvec_t* cols, int* /*icon*/, chooser_item_attrs_t* /*attrs*/,
                            size_t n) const override
        {
            const segment_t& seg = allSegs[n];
            qstring name;
            get_segm_name(&name, &seg);

            (*cols)[0] = name;
            (*cols)[1].sprnt("%llX", (uint64_t)seg.start_ea);
            (*cols)[2].sprnt("%llX", (uint64_t)seg.end_ea);

            switch (seg.type)
            {
                case SEG_DATA: (*cols)[3] = "DATA"; break;
                case SEG_CODE: (*cols)[3] = "CODE"; break;
                case SEG_BSS:  (*cols)[3] = "BSS";  break;
                default:       (*cols)[3] = "OTHER"; break;
            }
        }
    };

    inline const int SegChooser::widths_[] = { 16, 16, 16, 8 };
    inline const char *const SegChooser::header_[] = { "Segment", "Start", "End", "Type" };

    inline void select(segments& segs, int hints, const char* title)
    {
        SegChooser ch(&segs, hints, title);

        // Build default selection based on hints
        sizevec_t deflt;
        for (size_t i = 0; i < ch.allSegs.size(); i++)
        {
            bool preSelect = false;
            if (hints & DATA_HINT)
                preSelect |= (ch.allSegs[i].type == SEG_DATA);
            if (hints & RDATA_HINT)
            {
                qstring name;
                get_segm_name(&name, &ch.allSegs[i]);
                qstrlwr(name.begin());
                preSelect |= (name.find("rdata") != qstring::npos);
            }
            if (preSelect)
                deflt.push_back(i);
        }

        ssize_t ret = ch.choose(deflt);
        if (ret > 0)
        {
            // deflt now contains the user's selection
            segs.clear();
            for (size_t idx : deflt)
            {
                if (idx < ch.allSegs.size())
                    segs.push_back(ch.allSegs[idx]);
            }
        }
    }
}

// ============================================================================
// OggPlay replacement (audio stubs - no audio on non-Windows)
// ============================================================================
namespace OggPlay
{
    inline void endPlay() {}
    inline void playFromMemory(const void*, size_t, bool) {}
}

// ============================================================================
// __unDName replacement using IDA's demangler
// ============================================================================

// Flags matching MSVC's undname constants
#ifndef UNDNAME_COMPLETE
#define UNDNAME_COMPLETE               0x00000
#define UNDNAME_NO_LEADING_UNDERSCORES 0x00001
#define UNDNAME_NO_MS_KEYWORDS         0x00002
#define UNDNAME_NO_FUNCTION_RETURNS    0x00004
#define UNDNAME_NO_ALLOCATION_MODEL    0x00008
#define UNDNAME_NO_ALLOCATION_LANGUAGE 0x00010
#define UNDNAME_NO_MS_THISTYPE         0x00020
#define UNDNAME_NO_CV_THISTYPE         0x00040
#define UNDNAME_NO_THISTYPE            0x00060
#define UNDNAME_NO_ACCESS_SPECIFIERS   0x00080
#define UNDNAME_NO_THROW_SIGNATURES    0x00100
#define UNDNAME_NO_MEMBER_TYPE         0x00200
#define UNDNAME_NO_RETURN_UDT_MODEL    0x00400
#define UNDNAME_32_BIT_DECODE          0x00800
#define UNDNAME_NAME_ONLY              0x01000
#define UNDNAME_TYPE_ONLY              0x02000
#define UNDNAME_HAVE_PARAMETERS        0x04000
#define UNDNAME_NO_ECSU                0x08000
#define UNDNAME_NO_IDENT_CHAR_CHECK    0x10000
#endif

typedef void* (*_Alloc)(uint32_t);
typedef void (*_Free)(void*);

inline void* mallocWrap(uint32_t size) { return malloc(size); }

// Decode MSVC type descriptor names (e.g. "?AVClassName@Namespace@@")
// These have the format: ?A[V|U|W4|T]name@scope@...@@
// Returns the decoded name in result, or false if not a type descriptor
static inline bool decodeMsvcTypeDescriptor(const char* name, qstring& result)
{
    if (!name || name[0] != '?' || name[1] != 'A')
        return false;

    const char* p = name + 2;

    // Skip type tag: V=class, U=struct, T=union, W4=enum
    if (*p == 'V' || *p == 'U' || *p == 'T')
        p++;
    else if (*p == 'W' && *(p+1) == '4')
        p += 2;
    else
        return false;

    // Parse name@scope@...@@ -> scope::...::name
    // Collect components separated by '@', terminated by '@@'
    std::vector<qstring> parts;
    while (*p && !(*p == '@' && *(p+1) == '@'))
    {
        const char* start = p;
        while (*p && *p != '@')
            p++;
        if (p > start)
            parts.push_back(qstring(start, p - start));
        if (*p == '@')
            p++;
    }

    if (parts.empty())
        return false;

    // Build result in reverse order (innermost scope last in mangled form)
    result.clear();
    for (int i = (int)parts.size() - 1; i >= 0; i--)
    {
        if (!result.empty())
            result.append("::");
        result.append(parts[i]);
    }
    return true;
}

// Cross-platform __unDName replacement
// Handles both full mangled names (via IDA's demangler) and MSVC type
// descriptors (via our own decoder, since IDA's demangler doesn't handle those)
inline char* __unDName(char* buffer, const char* name, int sizeBuffer,
                       _Alloc /*allocator*/, _Free /*_free*/, uint32_t flags)
{
    qstring result;
    bool decoded = false;

    // Try MSVC type descriptor format first (used with UNDNAME_TYPE_ONLY)
    if (flags & UNDNAME_TYPE_ONLY)
        decoded = decodeMsvcTypeDescriptor(name, result);

    // Fall back to IDA's demangler for full mangled names
    if (!decoded)
    {
        uint32_t inhibit = MNG_SHORT_FORM;
        if (demangle_name(&result, name, inhibit, DQT_FULL) < 0)
            return nullptr;
        decoded = true;
    }

    // If UNDNAME_NO_ECSU requested, strip "class ", "struct ", "union ", "enum " prefix
    if (decoded && (flags & UNDNAME_NO_ECSU))
    {
        const char* s = result.c_str();
        if (strncmp(s, "class ", 6) == 0) result.remove(0, 6);
        else if (strncmp(s, "struct ", 7) == 0) result.remove(0, 7);
        else if (strncmp(s, "union ", 6) == 0) result.remove(0, 6);
        else if (strncmp(s, "enum ", 5) == 0) result.remove(0, 5);
    }

    if (decoded && !result.empty())
    {
        if (buffer)
        {
            qstrncpy(buffer, result.c_str(), sizeBuffer);
            return buffer;
        }
        else
        {
            char* s = (char*)malloc(result.length() + 1);
            if (s) strcpy(s, result.c_str());
            return s;
        }
    }
    return nullptr;
}
