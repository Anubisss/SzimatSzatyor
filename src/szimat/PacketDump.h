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

#include <ctime>

// this class encapsulates functions which logging the packets
class PacketDump
{
public:
    enum PacketType
    {
        PACKET_TYPE_C2S = 0, // client to server, CMSG
        PACKET_TYPE_S2C = 1  // server to client, SMSG
    };

    enum UserFiendlyLogStatus
    {
        USER_FRIENDLY_LOG_NOT_CHECKED,
        USER_FRIENDLY_LOG_DISABLED,
        USER_FRIENDLY_LOG_ENABLED
    };

    // name of the file which enables the "user friendly" log format
    static char enableUserFriendlyFileName[];
    // path of the file which enables the "user friendly" log format
    static char enableUserFriendlyPath[MAX_PATH];

    static FILE* userFriendlyDumpFile;
    static FILE* binaryDumpFile;

private:
    static UserFiendlyLogStatus _userFiendlyLogStatus;

public:
    static bool IsUserFriendlyLogEnabled()
    {
        return _userFiendlyLogStatus == USER_FRIENDLY_LOG_ENABLED;
    }

    // just this method should be used "globally"
    // basically logs the packets via other private functions
    static void DumpPacket(const char* userFriendlyDumpFileName,
                           const char* binaryDumpFileName,
                           PacketType packetType,
                           DWORD packetOpcode,
                           DWORD packetSize,
                           DWORD buffer,
                           WORD initialReadOffset)
    {
        // gets the time
        time_t rawTime;
        time(&rawTime);

        // only dumps "user friendly" format if
        // "dump_user_friendly" file exists
        if (_userFiendlyLogStatus == USER_FRIENDLY_LOG_NOT_CHECKED)
        {
            if (PathFileExists(enableUserFriendlyPath))
                _userFiendlyLogStatus = USER_FRIENDLY_LOG_ENABLED;
            else
                _userFiendlyLogStatus = USER_FRIENDLY_LOG_DISABLED;
        }

        if (IsUserFriendlyLogEnabled())
        {
            if (!userFriendlyDumpFile)
            {
                userFriendlyDumpFile = fopen(userFriendlyDumpFileName, "w");
                if (!userFriendlyDumpFile)
                {
                    printf("Cannot open file: %s, error code: %d - %s",
                           userFriendlyDumpFileName, errno, strerror(errno));
                    return;
                }
            }

            // dumps the "user friendly" format of the packet
            DumpPacketUserFriendly(userFriendlyDumpFile,
                                   packetType,
                                   packetOpcode,
                                   packetSize,
                                   buffer,
                                   rawTime,
                                   initialReadOffset);
            fflush(userFriendlyDumpFile);
        }

        if (!binaryDumpFile)
        {
            binaryDumpFile = fopen(binaryDumpFileName, "wb"); // binary mode
            if (!binaryDumpFile)
            {
                printf("Cannot open file: %s, error code: %d - %s",
                       binaryDumpFileName, errno, strerror(errno));
                return;
            }
        }
        // dumps the binary format of the packet
        DumpPacketBinary(binaryDumpFile,
                         packetType,
                         packetOpcode,
                         packetSize,
                         buffer,
                         rawTime,
                         initialReadOffset);
        fflush(binaryDumpFile);
    }

private:
    static void DumpPacketUserFriendly(FILE* file, PacketType packetType, DWORD packetOpcode, DWORD packetSize, DWORD buffer, time_t timestamp, WORD initialReadOffset)
    {

        // writes a header and a ruler
        WriteUserFriendlyHeader(file, packetType, packetOpcode, packetSize, timestamp);
        WriteUserFriendlyRuler(file);

        // really dumps the packet's data
        WriteUserFriendlyPacketDump(file, packetType, buffer, packetSize, initialReadOffset);

        // ruler again
        WriteUserFriendlyRuler(file);
        fprintf(file, "\n\n");
    }

    // a header which contains some details about the packet
    // packet direction, opcode, size, timestamp, date
    static void WriteUserFriendlyHeader(FILE* file, PacketType packetType, DWORD packetOpcode, DWORD packetSize, time_t timestamp)
    {
        // packet direction string
        char* packetTypeString = "";
        if (packetType == PACKET_TYPE_C2S)
            packetTypeString = "CMSG";
        else
            packetTypeString = "SMSG";

        tm* date = localtime(&timestamp);
        // date format
        char dateStr[32];
        // fills the date, format: YYYY. mm. dd. - HH:ii:ss
        _snprintf(dateStr,
                  32,
                  "%d. %02d. %02d. - %02d:%02d:%02d",
                  date->tm_year + 1900,
                  date->tm_mon + 1,
                  date->tm_mday,
                  date->tm_hour,
                  date->tm_min,
                  date->tm_sec);

        // the 2 rows header
        fprintf(file,
                "Packet type: %s, Opcode: 0x%04X, Packet size: %u bytes\n"
                "Timestamp: %u, Date: %s\n",
                packetTypeString,
                packetOpcode,
                packetSize,
                (DWORD)timestamp,
                dateStr);
    }

    // a "ruler" which makes easier to read the "user friendly" dump
    static void WriteUserFriendlyRuler(FILE* file)
    {
        char* ruler =
        "|--------|-------------------------------------------------|---------------------------------|\n"
        "|        | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | 0 1 2 3 4 5 6 7 8 9 A B C D E F |\n"
        "|--------|-------------------------------------------------|---------------------------------|\n";
        fprintf(file, ruler);
    }

    // the real work of the "user friendly" packet
    static void WriteUserFriendlyPacketDump(FILE* file, PacketType packetType, DWORD buffer, DWORD packetSize, WORD initialReadOffset)
    {
        // empty packet
        if (packetSize == 0)
        {
            fprintf(file, "|        |                   EMPTY PACKET                  |           EMPTY PACKET          |\n");
            return;
        }

        // some magic to get the proper, nice format
        // should be hard to comment that... :)
        DWORD readOffset1 = initialReadOffset;
        DWORD readOffset2 = initialReadOffset;
        for (DWORD i = 0; i < packetSize; ++i)
        {
            if (i % 0x10 != 0)
                continue;
            fprintf(file, "| 0x%04X | ", i + 1);
            for (DWORD j = 0; j < 0x10; ++j)
            {
                if ((i + j) > packetSize - 1)
                    break;
                BYTE byte = *(BYTE*)(buffer + readOffset1++);
                fprintf(file, "%02X ", byte);
            }
            if (i + 0x0F > packetSize - 1)
                for (DWORD j = 0; j < i + 0x10 - packetSize; ++j)
                    fprintf(file, "%s", "   ");
            fprintf(file, "%s ", "|");
            for (DWORD j = 0; j < 0x10; ++j)
            {
                if ((i + j) > packetSize - 1)
                    break;
                BYTE byte = *(BYTE*)(buffer + readOffset2++);
                if (byte >= 0x20 && byte < 0x7F)
                    fprintf(file, "%c ", (char)byte);
                else
                    fprintf(file, "%s ", ".");
            }
            if (i + 0x0F > packetSize - 1)
                for (DWORD j = 0; j < i + 0x10 - packetSize; ++j)
                    fprintf(file, "%s", "  ");
            fprintf(file, "%s\n", "|");
        }
    }

    // saves the packet in Trinity's WPP format
    // https://github.com/TrinityCore/WowPacketParser
    static void DumpPacketBinary(FILE* file,
                                 PacketType packetType,
                                 DWORD packetOpcode,
                                 DWORD packetSize,
                                 DWORD buffer,
                                 time_t timestamp,
                                 WORD initialReadOffset)
    {
        fwrite(&packetOpcode,       4, 1, file); // opcode
        fwrite(&packetSize,         4, 1, file); // size of the packet
        fwrite((DWORD*)&timestamp,  4, 1, file); // timestamp of the packet
        fwrite((BYTE*)&packetType,  1, 1, file); // direction of the packet

        // loops over the packet and saves the data
        for (DWORD i = 0; i < packetSize; ++i)
        {
            BYTE byte = *(BYTE*)(buffer + initialReadOffset + i);
            fwrite(&byte, 1, 1, file);
        }
    }
};
