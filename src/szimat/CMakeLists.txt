add_library(szimat SHARED
    main.cpp
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