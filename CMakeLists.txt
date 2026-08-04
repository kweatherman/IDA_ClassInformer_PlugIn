cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(ida_class_informer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
set(CMAKE_AUTOMOC ON)

set(SOURCES
    Main.cpp
    MainDialog.cpp
    RTTI.cpp
    Vftable.cpp
)

set(HEADERS
    StdAfx.h
    Compat.h
    Main.h
    MainDialog.h
    RTTI.h
    Vftable.h
)

set(UI_FILES
    dialog.ui
)

set(QRC_FILES
    ClassInformerRes.qrc
)

qt6_wrap_ui(UI_HEADERS ${UI_FILES})
qt6_add_resources(QRC_SOURCES ${QRC_FILES} OPTIONS --no-zstd)

# Use Homebrew Qt for headers/moc/uic/rcc but link against IDA's namespaced Qt frameworks
set(IDA_APP_FRAMEWORKS "/Applications/IDA Professional 9.2.app/Contents/Frameworks")

ida_add_plugin(class_informer
    SOURCES
        ${SOURCES}
        ${QRC_SOURCES}
        ${UI_HEADERS}
    INCLUDES
        "${CMAKE_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}"
    LIBRARIES
        "${IDA_APP_FRAMEWORKS}/QtCore.framework/Versions/A/QtCore"
        "${IDA_APP_FRAMEWORKS}/QtGui.framework/Versions/A/QtGui"
        "${IDA_APP_FRAMEWORKS}/QtWidgets.framework/Versions/A/QtWidgets"
    DEFINES
        QT_NAMESPACE=QT
        QT_NO_VERSION_TAGGING
)

# Still need Qt header include paths from Homebrew
target_include_directories(class_informer PRIVATE
    ${Qt6Core_INCLUDE_DIRS}
    ${Qt6Widgets_INCLUDE_DIRS}
    ${Qt6Gui_INCLUDE_DIRS}
)

# On macOS, rewrite Qt framework paths and rpaths so IDA's bundled Qt is used at runtime
if(APPLE)
    add_custom_command(TARGET class_informer POST_BUILD
        COMMAND install_name_tool -change
            "/opt/homebrew/opt/qtbase/lib/QtWidgets.framework/Versions/A/QtWidgets"
            "@rpath/QtWidgets.framework/Versions/A/QtWidgets"
            "$<TARGET_FILE:class_informer>"
        COMMAND install_name_tool -change
            "/opt/homebrew/opt/qtbase/lib/QtGui.framework/Versions/A/QtGui"
            "@rpath/QtGui.framework/Versions/A/QtGui"
            "$<TARGET_FILE:class_informer>"
        COMMAND install_name_tool -change
            "/opt/homebrew/opt/qtbase/lib/QtCore.framework/Versions/A/QtCore"
            "@rpath/QtCore.framework/Versions/A/QtCore"
            "$<TARGET_FILE:class_informer>"
        COMMAND install_name_tool -delete_rpath
            "/opt/homebrew/opt/qt/lib"
            "$<TARGET_FILE:class_informer>" 2>/dev/null || true
        COMMAND install_name_tool -add_rpath
            "@loader_path/../Frameworks"
            "$<TARGET_FILE:class_informer>" || true
        COMMENT "Rewriting Qt framework paths to @rpath for IDA compatibility"
    )
endif()
