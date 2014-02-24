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
#define WOW_MOP_16135   16135
#define WOW_MOP_16357   16357
#define WOW_MOP_16650   16650
#define WOW_MOP_16709   16709
#define WOW_MOP_16826   16826
#define WOW_MOP_16981   16981
#define WOW_MOP_16983   16983
#define WOW_MOP_16992   16992
#define WOW_MOP_17055   17055
#define WOW_MOP_17056   17056
#define WOW_MOP_17093   17093
#define WOW_MOP_17116   17116
#define WOW_MOP_17124   17124
#define WOW_MOP_17128   17128
#define WOW_MOP_17359   17359
#define WOW_MOP_17371   17371
#define WOW_MOP_17399   17399
#define WOW_MOP_17538   17538
#define WOW_MOP_17658   17658
#define WOW_MOP_17688   17688
#define WOW_MOP_17859   17859
#define WOW_MOP_17889   17889
#define WOW_MOP_17898   17898
#define WOW_MOP_17930   17930

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
        FillHookEntry16135();
        FillHookEntry16357();
        FillHookEntry16650();
        FillHookEntry16709();
        FillHookEntry16826();
        FillHookEntry16981();
        FillHookEntry16983();
        FillHookEntry16992();
        FillHookEntry17055();
        FillHookEntry17056();
        FillHookEntry17093();
        FillHookEntry17116();
        FillHookEntry17124();
        FillHookEntry17128();
        FillHookEntry17359();
        FillHookEntry17371();
        FillHookEntry17399();
        FillHookEntry17538();
        FillHookEntry17658();
        FillHookEntry17688();
        FillHookEntry17859();
        FillHookEntry17889();
        FillHookEntry17898();
        FillHookEntry17930();
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

    // address offsets for MOP, 16135
    static void FillHookEntry16135()
    {
        HookEntry hookEntry16135 = HookEntry(0x3F9AE0, 0x3F7710);
        _hookEntryMap[WOW_MOP_16135] = hookEntry16135;
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

    // address offsets for MOP, 17056
    static void FillHookEntry17056()
    {
        HookEntry hookEntry17056 = HookEntry(0x3E43D9, 0x3E1ECC);
        _hookEntryMap[WOW_MOP_17056] = hookEntry17056;
    }

    // address offsets for MOP, 17093
    static void FillHookEntry17093()
    {
        HookEntry hookEntry17093 = HookEntry(0x3EED60, 0x3EC853);
        _hookEntryMap[WOW_MOP_17093] = hookEntry17093;
    }

    // address offsets for MOP, 17116
    static void FillHookEntry17116()
    {
        HookEntry hookEntry17116 = HookEntry(0x364654, 0x36276A);
        _hookEntryMap[WOW_MOP_17116] = hookEntry17116;
    }

    // address offsets for MOP, 17124
    static void FillHookEntry17124()
    {
        HookEntry hookEntry17124 = HookEntry(0x3F3B0F, 0x3F1490);
        _hookEntryMap[WOW_MOP_17124] = hookEntry17124;
    }

    // address offsets for MOP, 17128
    static void FillHookEntry17128()
    {
        HookEntry hookEntry17128 = HookEntry(0x363C88, 0x361D9B);
        _hookEntryMap[WOW_MOP_17128] = hookEntry17128;
    }

    // address offsets for MOP, 17359
    static void FillHookEntry17359()
    {
        HookEntry hookEntry17359 = HookEntry(0x391942, 0x38F9C5);
        _hookEntryMap[WOW_MOP_17359] = hookEntry17359;
    }

    // address offsets for MOP, 17371
    static void FillHookEntry17371()
    {
        HookEntry hookEntry17371 = HookEntry(0x39192A, 0x38F9AD);
        _hookEntryMap[WOW_MOP_17371] = hookEntry17371;
    }

    // address offsets for MOP, 17399
    static void FillHookEntry17399()
    {
        HookEntry hookEntry17399 = HookEntry(0x39199E, 0x38FA21);
        _hookEntryMap[WOW_MOP_17399] = hookEntry17399;
    }

    // address offsets for MOP, 17538
    static void FillHookEntry17538()
    {
        HookEntry hookEntry17538 = HookEntry(0x38F1A9, 0x38D225);
        _hookEntryMap[WOW_MOP_17538] = hookEntry17538;
    }

    // address offsets for MOP, 17658
    static void FillHookEntry17658()
    {
        HookEntry hookEntry17658 = HookEntry(0x3988D7, 0x3965BB);
        _hookEntryMap[WOW_MOP_17658] = hookEntry17658;
    }

    // address offsets for MOP, 17688
    static void FillHookEntry17688()
    {
        HookEntry hookEntry17688 = HookEntry(0x3988D7, 0x3965BB);
        _hookEntryMap[WOW_MOP_17688] = hookEntry17688;
    }

    // address offsets for MOP, 17859
    static void FillHookEntry17859()
    {
        HookEntry hookEntry17859 = HookEntry(0x399711, 0x397559);
        _hookEntryMap[WOW_MOP_17859] = hookEntry17859;
    }

    // address offsets for MOP, 17889
    static void FillHookEntry17889()
    {
        HookEntry hookEntry17889 = HookEntry(0x399B6A, 0x3979B2);
        _hookEntryMap[WOW_MOP_17889] = hookEntry17889;
    }

    // address offsets for MOP, 17898
    static void FillHookEntry17898()
    {
        HookEntry hookEntry17898 = HookEntry(0x399B6A, 0x3979B2);
        _hookEntryMap[WOW_MOP_17898] = hookEntry17898;
    }

    // address offsets for MOP, 17930
    static void FillHookEntry17930()
    {
        HookEntry hookEntry17930 = HookEntry(0x39993E, 0x397786);
        _hookEntryMap[WOW_MOP_17930] = hookEntry17930;
    }

    // type for storing hook entries
    typedef std::map<WORD /* buildNumber */, HookEntry> HookEntryMap;
    // stores hook entries
    // key for the hook entry is the build number of the client
    static HookEntryMap _hookEntryMap;
};
