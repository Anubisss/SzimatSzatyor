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

// size of the "JMP <displacement>" instruction
// JMP is 1 byte and displacement is 4 bytes
#define JMP_INSTRUCTION_SIZE 5

// stores the x86 machine code (JMP assembly opcode) which
// makes the hooking happen
// basically this code means that when the CPU reaches this code
// it will jump relatively forward (or backward if minus) in the code
// by the value of the displacement and on that address there is our function
// JMP <displacement>
BYTE jumpMachineCode[JMP_INSTRUCTION_SIZE] = { 0xE9,
                                               0x00,
                                               0x00,
                                               0x00,
                                               0x00 };

// functions which can hook/unhook functions
class HookManager
{
public:
    // hooks a function located at hookedFunctionAddress
    // hookedFunctionAddress - the function on this address will be hooked so
    // the WoW contains this function
    // hookFunctionAddress - this is the user defined "callback" function
    // which will be called on hook
    static void Hook(DWORD hookedFunctionAddress,
                     DWORD hookFunctionAddress,
                     BYTE* hookMachineCode,
                     BYTE* defaultMachineCode)
    {
        // be nice and nulls the displacement
        memset(&jumpMachineCode[1], 0x00, 4);

        // copies the "default" (no displacement yet) instruction
        memcpy(hookMachineCode, jumpMachineCode, JMP_INSTRUCTION_SIZE);
        // calculates the displacement
        DWORD jmpDisplacement = hookFunctionAddress -
                                hookedFunctionAddress -
                                JMP_INSTRUCTION_SIZE;
        // copies the calculated value of the displacement
        memcpy(&hookMachineCode[1], &jmpDisplacement, 4);

        // stores the previous access protection
        DWORD oldProtect;
        // changes the protection on a region of committed pages in
        // the virtual address space of the calling process
        // so now we can surely read/write the memory region where
        // the hookedFunctionAddress is
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       PAGE_EXECUTE_READWRITE,
                       &oldProtect);

        // just dumps the default machine code in the address
        // so later the sniffer can restore it
        memcpy(defaultMachineCode,
               (LPVOID)hookedFunctionAddress,
               JMP_INSTRUCTION_SIZE);

        // now just writes the new generated machine code to the address
        memcpy((LPVOID)hookedFunctionAddress,
                hookMachineCode,
                JMP_INSTRUCTION_SIZE);

        // flushes the instruction cache
        // Applications should call this if they modify code in memory.
        // Without this, the CPU can't detect the change and
        // _may_ execute the old code it cached.
        FlushInstructionCache(GetCurrentProcess(),
                              (LPVOID)hookedFunctionAddress,
                              JMP_INSTRUCTION_SIZE);

        // restores the stored access protection
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       oldProtect,
                       NULL);
    }

    // restores the original machine code
    static void UnHook(DWORD hookedFunctionAddress, BYTE* defaultMachineCode)
    {
        // stores the old protection
        DWORD oldProtect;

        // changes the protection and gets the old one
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       PAGE_EXECUTE_READWRITE,
                       &oldProtect);

        // writes the original machine code to the address
        memcpy((LPVOID)hookedFunctionAddress,
               defaultMachineCode,
               JMP_INSTRUCTION_SIZE);

        // flushes the cache
        FlushInstructionCache(GetCurrentProcess(),
                              (LPVOID)hookedFunctionAddress,
                              JMP_INSTRUCTION_SIZE);

        // restores the old protection
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       oldProtect,
                       NULL);
    }

    // restores the hook
    static void ReHook(DWORD hookedFunctionAddress, BYTE* hookMachineCode)
    {
        // stores the previous access protection
        DWORD oldProtect;

        // changes the protection and retrieves the previous one
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       PAGE_EXECUTE_READWRITE,
                       &oldProtect);

        // writes the "hook machine code" to the address
        memcpy((LPVOID)hookedFunctionAddress,
               hookMachineCode,
               JMP_INSTRUCTION_SIZE);

        // flushes CPU's cache
        FlushInstructionCache(GetCurrentProcess(),
                              (LPVOID)hookedFunctionAddress,
                              JMP_INSTRUCTION_SIZE);

        // restores the previous one
        VirtualProtect((LPVOID)hookedFunctionAddress,
                       JMP_INSTRUCTION_SIZE,
                       oldProtect,
                       NULL);
    }
};
