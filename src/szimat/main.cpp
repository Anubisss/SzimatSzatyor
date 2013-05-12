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

#include <Windows.h>
#include <Shlwapi.h>

#include <cstdio>

#include "ConsoleManager.h"
#include "HookEntryManager.h"
#include "HookManager.h"
#include "PacketDump.h"

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;



// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX register
// fastcall convention means that the first 2 parameters is passed
// via ECX and EDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR,
                          void* /* dummy */,
                          void* /* param1 */,
                          void* /* param2 */);
// this send prototype fits with the client's one
typedef DWORD (__thiscall *SendProto)(void*, void*, void*);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };


// this function will be called when recv called in the client
DWORD __fastcall RecvHook(void* thisPTR,
                          void* /* dummy */,
                          void* /* param1 */,
                          void* /* param2 */,
                          void* /* param3 */);
// this recv prototype fits with the client's one
typedef DWORD (__thiscall *RecvProto)(void*, void*, void*, void*);
// clients which has build number <= 8606 have different prototype
typedef DWORD (__thiscall *RecvProto8606)(void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };




// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendHookGood = false;
bool recvHookGood = false;

// location of the "user friendly" packet dump file
char logPath[MAX_PATH] = { 0 };
// location of the binary packet dump file
char binPath[MAX_PATH] = { 0 };

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)&MainThreadControl,
                     NULL,
                     0,
                     NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to SzimatSzatyor, a WoW injector sniffer.\n");
    printf("SzimatSzatyor is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("http://github.com/Anubisss/SzimatSzatyor\n\n");

    printf("Press CTRL-C (CTRL then c) to stop sniffing ");
    printf("(and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    // inits the HookManager
    HookEntryManager::FillHookEntries();

    // gets the build number
    buildNumber = HookEntryManager::GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!HookEntryManager::IsHookEntryExists(buildNumber))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }



    // gets time/date
    time_t rawTime;
    DWORD now = (DWORD)time(&rawTime);
    tm* date = localtime(&rawTime);

    char dllPath[MAX_PATH];
    // gets where is the DLL which injected into the client
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL,
                                          dllPath,
                                          MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n",  GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    // basic file name format:
    // wowsniff_buildNumber_unixTimeStamp_dateYear_dateMonth_dateDay_dateHour_dateMinute_dateSecond.[log/bin]
    char fileName[64];
    // the "user friendly" file, .log
    char fileNameUserFriendly[64];
    // the binary file, .bin
    char fileNameBinary[64];

    // fills the basic file name format
    sprintf(fileName,
            "wowsniff_%hu_%u_%dy%02dm%02dd%02dh%02di%02ds",
            buildNumber,
            now,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);
    // fills the specific file names
    sprintf(fileNameUserFriendly, "%s.log", fileName);
    sprintf(fileNameBinary, "%s.bin", fileName);

    // some info
    printf("User friendly dump: %s\n", fileNameUserFriendly);
    printf("Binary dump:        %s\n\n", fileNameBinary);

    // removes the DLL name from the path
    PathRemoveFileSpec(dllPath);

    // simply appends the file names to the DLL's location
    sprintf(logPath, "%s\\%s", dllPath, fileNameUserFriendly);
    sprintf(binPath, "%s\\%s", dllPath, fileNameBinary);



    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    // gets address of NetClient::Send2
    sendAddress =
    HookEntryManager::GetHookEntry(buildNumber).send2_AddressOffset;
    // plus the base address
    sendAddress += baseAddress;
    // hooks client's send function
    HookManager::Hook(sendAddress,
                      (DWORD)SendHook,
                      machineCodeHookSend,
                      defaultMachineCodeSend);

    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress =
    HookEntryManager::GetHookEntry(buildNumber).processMessage_AddressOffset;
    // plus the base address
    recvAddress += baseAddress;
    // hooks client's recv function
    HookManager::Hook(recvAddress,
                      (DWORD)RecvHook,
                      machineCodeHookRecv,
                      defaultMachineCodeRecv);

    printf("Recv is hooked.\n");

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice

    // unhooks functions
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

DWORD __fastcall SendHook(void* thisPTR,
                          void* /* dummy */,
                          void* param1,
                          void* param2)
{
    DWORD buffer = *(DWORD*)((DWORD)param1 + 4);
    WORD packetOcode = *(DWORD*)buffer;
    DWORD packetSize = *(DWORD*)((DWORD)param1 + 16); // totalLength, writePos

    // dumps the packet
    PacketDump::DumpPacket(logPath,
                           binPath,
                           PacketDump::PACKET_TYPE_C2S,
                           packetOcode,
                           packetSize - 4,
                           buffer);

    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server
    DWORD returnValue = SendProto(sendAddress)(thisPTR, param1, param2);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendHookGood)
    {
        printf("Send hook is working.\n");
        sendHookGood = true;
    }

    return 0;
}

DWORD __fastcall RecvHook(void* thisPTR,
                          void* /* dummy */,
                          void* param1,
                          void* param2,
                          void* param3)
{
    DWORD buffer = *(DWORD*)((DWORD)param2 + 4);
    WORD packetOcode = *(DWORD*)buffer;
    DWORD packetSize = *(DWORD*)((DWORD)param2 + 16); // totalLength, writePos

    // packet dump
    PacketDump::DumpPacket(logPath,
                           binPath,
                           PacketDump::PACKET_TYPE_S2C,
                           packetOcode,
                          packetSize - (buildNumber == WOW_CLASS_5875 ? 2 : 4),
                           buffer);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = 0;
    if (buildNumber <= WOW_TBC_8606) // different prototype
        returnValue = RecvProto8606(recvAddress)(thisPTR, param1, param2);
    else
        returnValue = RecvProto(recvAddress)(thisPTR, param1, param2, param3);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}
