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

set(SZIMAT_SZATYOR_SHARED_HEADERS ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "shared headers" FORCE)

add_library(shared STATIC
    HookEntryManager.cpp
    HookEntryManager.h
)

target_link_libraries(shared
    Psapi
    shlwapi
    version
)
