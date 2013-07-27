add_library(szimat SHARED
    main.cpp
    ConsoleManager.h
    HookManager.h
    PacketDump.h
)

target_link_libraries(szimat
    shared
    Psapi
    shlwapi
    version
)

include_directories(
    ${SZIMAT_SZATYOT_SHARED_HEADERS}
)