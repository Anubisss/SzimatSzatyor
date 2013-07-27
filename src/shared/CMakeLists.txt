set(SZIMAT_SZATYOT_SHARED_HEADERS ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "shared headers" FORCE)

add_library(shared STATIC
    HookEntryManager.cpp
)

target_link_libraries(shared
    Psapi
    shlwapi
    version
)