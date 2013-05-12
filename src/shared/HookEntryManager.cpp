/*
 * This file is part of SzimatSzatyor.
 *
 * SzimatSzatyor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * SzimatSzatyor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "HookEntryManager.h"

#include <psapi.h>

// static member initilization
std::map<WORD, HookEntryManager::HookEntry> HookEntryManager::_hookEntryMap;

/* static */
WORD HookEntryManager::GetBuildNumberFromProcess(HANDLE hProcess /* = NULL */)
{
    // will contain where the process is which will be injected
    char processExePath[MAX_PATH];

    // size of the path
    DWORD processExePathSize = 0;
    // gets the path of the current process' executable
    // param process should be NULL in the sniffer
    if (!hProcess)
        processExePathSize = GetModuleFileName(NULL, processExePath, MAX_PATH);
    // gets the path of an external process' executable
    // param process should NOT be NULL in the injector
    else
        processExePathSize = GetModuleFileNameEx(hProcess,
                                                 NULL,
                                                 processExePath,
                                                 MAX_PATH);
    if (!processExePathSize)
    {
        printf("ERROR: Can't get path of the process' exe, ErrorCode: %u\n",
               GetLastError());
        return 0;
    }
    printf("ExePath: %s\n", processExePath);

    // size of the file version info
    DWORD fileVersionInfoSize = GetFileVersionInfoSize(processExePath, NULL);
    if (!fileVersionInfoSize)
    {
        printf("ERROR: Can't get size of the file version info,");
        printf("ErrorCode: %u\n", GetLastError());
        return 0;
    }

    // allocates memory for file version info
    BYTE* fileVersionInfoBuffer = new BYTE[fileVersionInfoSize];
    // gets the file version info
    if (!GetFileVersionInfo(processExePath,
                            0,
                            fileVersionInfoSize,
                            fileVersionInfoBuffer))
    {
        printf("ERROR: Can't get file version info, ErrorCode: %u\n",
               GetLastError());
        delete [] fileVersionInfoBuffer;
        return 0;
    }

    // structure of file version info
    // actually this pointer will be pointed to a part of fileVersionInfoBuffer
    VS_FIXEDFILEINFO* fileInfo = NULL;
    // gets the needed info (root) from the file version info resource
    // \ means the root block (VS_FIXEDFILEINFO)
    // note: escaping needed so that's why \\ used
    if (!VerQueryValue(fileVersionInfoBuffer, "\\", (LPVOID*)&fileInfo, NULL))
    {
        printf("ERROR: File version info query is failed.\n");
        delete [] fileVersionInfoBuffer;
        return 0;
    }

    // last (low) 2 bytes
    WORD buildNumber = fileInfo->dwFileVersionLS & 0xFFFF;
    delete [] fileVersionInfoBuffer;
    return buildNumber;
}
