add_executable(szatyor
    main.cpp
)

include_directories(
    ${SZIMAT_SZATYOT_SHARED_HEADERS}
)

target_link_libraries(szatyor
    shared
    Psapi
    shlwapi
    version
)
