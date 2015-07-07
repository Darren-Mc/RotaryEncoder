#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <chrono>
#include <stdint.h>

#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const DWORD port_name_max_length = 256;
static const DWORD friendly_name_max_length = 256;
static const DWORD hardware_id_max_length = 256;

int numDigits(int32_t x)
{
	//if (x == MIN_INT) return 10 + 1;
	if (x < 0) return numDigits(-x) + 1;

	if (x >= 10000) {
		if (x >= 10000000) {
			if (x >= 100000000) {
				if (x >= 1000000000)
					return 10;
				return 9;
			}
			return 8;
		}
		if (x >= 100000) {
			if (x >= 1000000)
				return 7;
			return 6;
		}
		return 5;
	}
	if (x >= 100) {
		if (x >= 1000)
			return 4;
		return 3;
	}
	if (x >= 10)
		return 2;
	return 1;
}

void system_error(char *name) {
	// Retrieve, format, and print out a message from the last error.  The 
	// `name' that's passed should be in the form of a present tense noun 
	// (phrase) such as "opening file".
	//
	char *ptr = NULL;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		0,
		GetLastError(),
		0,
		(char *)&ptr,
		1024,
		NULL);

	fprintf(stderr, "\nError %s: %s\n", name, ptr);
	LocalFree(ptr);
}

int main(int argc, char **argv) {

	int ch;
	char buffer[1];
	HANDLE file;
	//HANDLE doc;
	COMMTIMEOUTS timeouts;
	DWORD read, written;
	DCB port;
	HANDLE keyboard = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE screen = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode;
	char port_id[128] = "\\\\.\\COM4"; // Default port
	char init[] = ""; // e.g., "ATZ" to completely reset a modem.
	std::ofstream doc;

	if (argc > 2)
		sprintf_s(port_id, "\\\\.\\COM%c", argv[1][0]);

	HDEVINFO device_info_set = SetupDiGetClassDevs(
		(const GUID *)&GUID_DEVCLASS_PORTS,
		NULL,
		NULL,
		DIGCF_PRESENT);

	unsigned int device_info_set_index = 0;
	SP_DEVINFO_DATA device_info_data;

	device_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

	while (SetupDiEnumDeviceInfo(device_info_set, device_info_set_index, &device_info_data))
	{
		device_info_set_index++;

		// Get port name

		HKEY hkey = SetupDiOpenDevRegKey(
			device_info_set,
			&device_info_data,
			0x00000001,
			0,
			0x00000001,
			KEY_READ);

		TCHAR port_name[port_name_max_length];
		DWORD port_name_length = port_name_max_length;

		LONG return_code = RegQueryValueEx(
			hkey,
			_T("PortName"),
			NULL,
			NULL,
			(LPBYTE)port_name,
			&port_name_length);

		RegCloseKey(hkey);

		if (return_code != EXIT_SUCCESS)
			continue;

		if (port_name_length > 0 && port_name_length <= port_name_max_length)
			port_name[port_name_length - 1] = '\0';
		else
			port_name[0] = '\0';

		// Ignore parallel ports

		if (_tcsstr(port_name, _T("LPT")) != NULL)
			continue;

		// Get port friendly name

		TCHAR friendly_name[friendly_name_max_length];
		DWORD friendly_name_actual_length = 0;

		BOOL got_friendly_name = SetupDiGetDeviceRegistryProperty(
			device_info_set,
			&device_info_data,
			SPDRP_FRIENDLYNAME,
			NULL,
			(PBYTE)friendly_name,
			friendly_name_max_length,
			&friendly_name_actual_length);

		if (got_friendly_name == TRUE && friendly_name_actual_length > 0)
			friendly_name[friendly_name_actual_length - 1] = '\0';
		else
			friendly_name[0] = '\0';

		if (strstr(friendly_name, "Arduino"))
		{
			sprintf_s(port_id, "\\\\.\\%s", port_name);
			break;
		}
	}

	SetupDiDestroyDeviceInfoList(device_info_set);

	// open the comm port.
	file = CreateFile(port_id,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (INVALID_HANDLE_VALUE == file) {
		system_error("opening file");
		return 1;
	}

	/*doc = CreateFile("test.txt",                // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	if (INVALID_HANDLE_VALUE == doc) {
		system_error("opening doc");
		return 1;
	}*/

	/*fptr = fopen_s("data.txt", "w");

	if (fptr == NULL) {
		system_error("opening text file");
		return 1;
	}*/

	doc.open("data.txt", std::ios::out | std::ios::trunc );

	// get the current DCB, and adjust a few bits to our liking.
	memset(&port, 0, sizeof(port));
	port.DCBlength = sizeof(port);
	if (!GetCommState(file, &port))
		system_error("getting comm state");
	if (!BuildCommDCB("baud=115200 parity=n data=8 stop=1", &port))
		system_error("building comm DCB");
	if (!SetCommState(file, &port))
		system_error("adjusting port settings");

	// set short timeouts on the comm port.
	timeouts.ReadIntervalTimeout = 1;
	timeouts.ReadTotalTimeoutMultiplier = 1;
	timeouts.ReadTotalTimeoutConstant = 1;
	timeouts.WriteTotalTimeoutMultiplier = 1;
	timeouts.WriteTotalTimeoutConstant = 1;
	if (!SetCommTimeouts(file, &timeouts))
		system_error("setting port time-outs.");

	// set keyboard to raw reading.
	if (!GetConsoleMode(keyboard, &mode))
		system_error("getting keyboard mode");
	mode &= ~ENABLE_PROCESSED_INPUT;
	if (!SetConsoleMode(keyboard, mode))
		system_error("setting keyboard mode");

	if (!EscapeCommFunction(file, CLRDTR))
		system_error("clearing DTR");
	Sleep(200);
	if (!EscapeCommFunction(file, SETDTR))
		system_error("setting DTR");

	if (!WriteFile(file, init, sizeof(init), &written, NULL))
		system_error("writing data to port");

	if (written != sizeof(init))
		system_error("not all data written to port");

	Sleep(2000);

	do {
		ReadFile(file, buffer, sizeof(buffer), &read, NULL);
	} while (read);

	//FlushFileBuffers(file);

	WriteFile(file, &ch, 1, &written, NULL);

	auto start = std::chrono::high_resolution_clock::now();

	// basic terminal loop:
	do {
		// check for data on port and display it on screen.
		ReadFile(file, buffer, sizeof(buffer), &read, NULL);
		if (read)
		{
			
			if (buffer[0] == '\n') {
				uint32_t time = (uint32_t)(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count());
				//int length = numDigits(time);
				//char times[10];
				//sprintf_s(times, "%d", time);
				//doc.write(times, length);
				doc << time << '\n';
				std::cout << '\n';
			}
			else
			{
				std::cout << buffer[0];
				//WriteFile(screen, buffer, read, &written, NULL);
				//WriteFile(doc, buffer, read, &written, NULL);
				//fputs(buffer, fptr);
				doc << buffer[0] << ' ';
				//doc.write(buffer, read);
			}
		}

		// check for keypress, and write any out the port.
		if (_kbhit()) {
			ch = _getch();
			WriteFile(file, &ch, 1, &written, NULL);
		}
		// until user hits ctrl-backspace.
	} while (ch != 127);// && time < 0xfffffff0 );

	// close up and go home.
	CloseHandle(keyboard);
	CloseHandle(file);
	//CloseHandle(doc);
	//fclose(fptr);
	doc.close();
	return 0;
}