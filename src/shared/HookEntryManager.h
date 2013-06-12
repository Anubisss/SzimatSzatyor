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

#pragma once

#include <wtypes.h>

#include <map>

// list of supported client build numbers
#define WOW_CLASS_5875  5875
#define WOW_TBC_8606    8606
#define WOW_WLK_12340   12340
#define WOW_CATA_13623  13623
#define WOW_CATA_15595  15595
#define WOW_MOP_16357   16357
#define WOW_MOP_16650   16650
#define WOW_MOP_16709   16709
#define WOW_MOP_16826   16826
#define WOW_MOP_16981   16981
#define WOW_MOP_16983   16983
#define WOW_MOP_16992   16992
#define WOW_MOP_17055   17055

// stores and manages hook entries
// this will be compiled into a static lib
// so both of the injector and the DLL too can use this class
class HookEntryManager
{
public:
    // hook entry structure
    // stores the offsets which are will be hooked
    // every different client version should has different offsets
    struct HookEntry
    {
        // default constructor is needed for std::map
        HookEntry()
        {
            send2_AddressOffset = 0;
            processMessage_AddressOffset = 0;
        }
        // constructor
        HookEntry(DWORD send2, DWORD processMessage)
        {
            send2_AddressOffset = send2;
            processMessage_AddressOffset = processMessage;
        }

        // offset of NetClient::Send2 to sniff client packets
        DWORD send2_AddressOffset;
        // offset of NetClient::ProcessMessage to sniff server packets
        DWORD processMessage_AddressOffset;
    };

    // returns the build number of the client
    // returns 0 if an error occurred
    // (gets this from file version info of client's exe)
    //
    // param should be NULL when would like to get the
    // path of the _current_ process' executable
    // this means the sniffer should call this with NULL because
    // the sniffer is just a "thread" which running in WoW
    //
    // param should NOT be NULL when would like to get the
    // path of an _external_ process' executable
    // so in the injector the param should contain the handle of a WoW process
    static WORD GetBuildNumberFromProcess(HANDLE hProcess = NULL);

    // just fills manually all the avaiable hook entries
    // this is some kind of initialization of the class
    static void FillHookEntries()
    {
        FillHookEntry5875();
        FillHookEntry8606();
        FillHookEntry12340();
        FillHookEntry13623();
        FillHookEntry15595();
        FillHookEntry16357();
        FillHookEntry16650();
        FillHookEntry16709();
        FillHookEntry16826();
        FillHookEntry16981();
        FillHookEntry16983();
        FillHookEntry16992();
        FillHookEntry17055();
    }

    // returns true if hook entry exists for this specified build number
    // otherwise false
    static bool IsHookEntryExists(WORD buildNumber)
    {
        return _hookEntryMap.find(buildNumber) != _hookEntryMap.end();
    }

    static HookEntry const& GetHookEntry(WORD buildNumber)
    {
        return _hookEntryMap[buildNumber];
    }

private:
    // address offsets for CLASSIC, 5875
    static void FillHookEntry5875()
    {
        HookEntry hookEntry5875 = HookEntry(0x1B5630, 0x137AA0);
        _hookEntryMap[WOW_CLASS_5875] = hookEntry5875;
    }

    // address offsets for TBC, 8606
    static void FillHookEntry8606()
    {
        HookEntry hookEntry8606 = HookEntry(0x203B0, 0x15F440);
        _hookEntryMap[WOW_TBC_8606] = hookEntry8606;
    }

    // address offsets for WLK, 12340
    static void FillHookEntry12340()
    {
        HookEntry hookEntry12340 = HookEntry(0x675F0, 0x231FE0);
        _hookEntryMap[WOW_WLK_12340] = hookEntry12340;
    }

    // address offsets for CATA, 13623
    static void FillHookEntry13623()
    {
        HookEntry hookEntry13623 = HookEntry(0x15EF20, 0x90360);
        _hookEntryMap[WOW_CATA_13623] = hookEntry13623;
    }

    // address offsets for CATA, 15595
    static void FillHookEntry15595()
    {
        HookEntry hookEntry16357 = HookEntry(0x89590, 0x873D0);
        _hookEntryMap[WOW_CATA_15595] = hookEntry16357;
    }

    // address offsets for MOP, 16357
    static void FillHookEntry16357()
    {
        HookEntry hookEntry16357 = HookEntry(0x40C5D0, 0x40A210);
        _hookEntryMap[WOW_MOP_16357] = hookEntry16357;
    }

    // address offsets for MOP, 16650
    static void FillHookEntry16650()
    {
        HookEntry hookEntry166550 = HookEntry(0x448D10, 0x446720);
        _hookEntryMap[WOW_MOP_16650] = hookEntry166550;
    }

    // address offsets for MOP, 16709
    static void FillHookEntry16709()
    {
        HookEntry hookEntry16709 = HookEntry(0x448FB0, 0x446A00);
        _hookEntryMap[WOW_MOP_16709] = hookEntry16709;
    }

    // address offsets for MOP, 16826
    static void FillHookEntry16826()
    {
        HookEntry hookEntry16826 = HookEntry(0x448E40, 0x446880);
        _hookEntryMap[WOW_MOP_16826] = hookEntry16826;
    }

    // address offsets for MOP, 16981
    static void FillHookEntry16981()
    {
        HookEntry hookEntry16981 = HookEntry(0x363B57, 0x361C6D);
        _hookEntryMap[WOW_MOP_16981] = hookEntry16981;
    }

    // address offsets for MOP, 16983
    static void FillHookEntry16983()
    {
        HookEntry hookEntry16983 = HookEntry(0x36400D, 0x362123);
        _hookEntryMap[WOW_MOP_16983] = hookEntry16983;
    }

    // address offsets for MOP, 16992
    static void FillHookEntry16992()
    {
        HookEntry hookEntry16992 = HookEntry(0x36424A, 0x362360);
        _hookEntryMap[WOW_MOP_16992] = hookEntry16992;
    }

    // address offsets for MOP, 17055
    static void FillHookEntry17055()
    {
        HookEntry hookEntry17055 = HookEntry(0x363F76, 0x36206E);
        _hookEntryMap[WOW_MOP_17055] = hookEntry17055;
    }

    // type for storing hook entries
    typedef std::map<WORD /* buildNumber */, HookEntry> HookEntryMap;
    // stores hook entries
    // key for the hook entry is the build number of the client
    static HookEntryMap _hookEntryMap;
};
