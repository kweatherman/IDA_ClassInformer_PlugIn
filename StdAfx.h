
// Common includes and defines
#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <tchar.h>
#include <crtdbg.h>
#include <intrin.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#ifdef _MSC_VER
#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)
#endif

// IDA SDK (must be included BEFORE Qt to avoid qstrlen/qstrncmp redefinition)
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4244) // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267) // conversion from 'size_t' to 'uint32', possible loss of data
#pragma warning(disable:4018) // warning C4018: '<': signed/unsigned mismatch
#endif
#include <ida.hpp>
// Until it actually happens
#undef DEPRECATED
#define DEPRECATED
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

// Rename Qt's qstr* functions to avoid conflict with IDA SDK's pro.h
#define qstrlen qt_qstrlen
#define qstrncmp qt_qstrncmp
#define qstrncpy qt_qstrncpy
#define qstrcmp qt_qstrcmp
#define qstrdup qt_qstrdup

// Qt SDK (after IDA SDK headers)
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QResource>

#undef qstrlen
#undef qstrncmp
#undef qstrncpy
#undef qstrcmp
#undef qstrdup

// Cross-platform compatibility layer
#include "Compat.h"

#include <vector>
#include <set>
typedef std::vector<ea_t> eaList;
typedef std::set<ea_t> eaSet;

// Note the path is hard coded in the .qss and dialog.ui files, so this dev define has limited use
//#define QT_RES_PATH "C:/Projects/IDA_Pro_Work/IDA_ClassInformer_PlugIn/res/"
#define QT_RES_PATH ":/res/"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 6, 0, 3)
