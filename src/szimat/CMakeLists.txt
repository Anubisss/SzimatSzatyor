#   This file is part of SzimatSzatyor.
#
#   SzimatSzatyor is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   SzimatSzatyor is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.

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
    ${SZIMAT_SZATYOR_SHARED_HEADERS}
)

# this condition is unnecessary but...
if(WIN32)
    # copies the README and COPYING files to the output directory (build/bin)
    add_custom_command(TARGET szimat POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/README
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$(ConfigurationName)/)
    add_custom_command(TARGET szimat POST_BUILD COMMAND
                       ${CMAKE_COMMAND} -E copy
                       ${PROJECT_SOURCE_DIR}/COPYING
                       ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$(ConfigurationName)/)
endif()
