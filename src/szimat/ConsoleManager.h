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

// manages the console
// console should be accessed, created and destroyed through this class
class ConsoleManager
{
public:
    // creates the console
    static bool Create(volatile bool* sniffingLoopCondition)
    {
        // basically creates the console
        if (!AllocConsole())
            return false;

        // gets the window handle used by the console 
        HWND consoleWindowHandler = GetConsoleWindow();
        // disables the "close button" on the console
        // console shutdown should work via SIGINT
        EnableMenuItem(GetSystemMenu(consoleWindowHandler, FALSE),
                       SC_CLOSE,
                       MF_GRAYED);
        // just be sure to display the grayed (and disabled) close button
        DrawMenuBar(consoleWindowHandler); // re-draw

        // registers a handler which handles SIGINT (CTRL-C) signal
        // basically the handler routine will be called when
        // CTRL-C (exit) will be pressed
        if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)
                                    ConsoleManager::SignalHandler_SIGINT,
                                   TRUE))
            return false;

        // just be sure there's a STDOUT
        HANDLE standardOutputHandler = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!standardOutputHandler ||
            standardOutputHandler == INVALID_HANDLE_VALUE)
            return false;

        // nice title again :)
        SetConsoleTitle("SzimatSzatyor, WoW injector sniffer");

        // re-opens STDOUT handle as a console window output
        freopen("CONOUT$", "w", stdout);

        // "sniffing loop" is only looping when this boolean is true
        // so just set this to false to stop it
        _sniffingLoopCondition = sniffingLoopCondition;

        return true;
    }

    // destroys the console
    static void Destroy() { FreeConsole(); }

    // this method will be called when a CTRL-C event occures
    // should stop the sniffing loop, so the sniffer will be stopped
    static BOOL SignalHandler_SIGINT(DWORD type)
    {
        // SIGINT
        if (type == CTRL_C_EVENT)
        {
            printf("\nQuiting...\n");
            // stops the sniffing loop
            *_sniffingLoopCondition = true;
            return TRUE;
        }
        // other events not handled
        return FALSE;
    }

private:
    // pointer to a boolean which is true when sniffing is still in progress
    // and false when sniffing should stop
    static volatile bool* _sniffingLoopCondition;
};
