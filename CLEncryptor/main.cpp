#include <iostream>
#include "EncryptedFile.h"
#include "Cryptography.h"

#define VERSION_ID "Build 1"
#define VERSION_ID_VERBOSE ("CLEncryptor " VERSION_ID " (C) Lily Young")

int MainLoop();

int main(int argc, char* argv[]) {

	//loop through each arg
	for (int x = 1; x < argc; x++) {
		//other
		//...
	}

	//start program
	return MainLoop();
}

#define COMMANDMODE 0
#define DATAMODE 1
int interpretermode = COMMANDMODE;

#define MAX_COMMAND_LEN 512 
char commandbuf[MAX_COMMAND_LEN] = {0};
uint32_t commandlen = 0;
const char eoldelimiter = '\n';
int ProcessCommand();

std::vector<uint8_t> rawdata;
uint64_t readlengthremaining = 0;
std::string tempfilename = "";
std::string temppassword = "";
int ProcessRawbuffer();

//Commands implemented
//LoadFile %s %s => SUCCUESS/FAILURE %d\n{%d bytes}
//SaveFile %s %s %d\n{%d bytes} => SUCCESS/FAILURE
//Exit
//Version

int MainLoop() {
	rawdata.clear();
	readlengthremaining = 0;

	//read data from commandline
	bool running = 1;
	while (running) {
		int character = getc(stdin);
		if (character == EOF) return -1; //error

		switch (interpretermode) {
		case COMMANDMODE:
			//read character for command
			if (character != eoldelimiter) {
				if (commandlen == MAX_COMMAND_LEN) return -3; //overrun
				commandbuf[commandlen++] = character;
			}
			else running = ProcessCommand() ? 0 : 1;
			break;

		case DATAMODE:
			rawdata.push_back(character);
			if (--readlengthremaining == 0) running = ProcessRawbuffer() ? 0 : 1;
			break;
		
		default:
			return -2;
			break;
		}

	}

	return 0;
}

std::vector<std::string> tokenize(const char* string, uint64_t length){
	std::vector<std::string> ret;
	ret.clear();

	std::string working = "";
	
	uint8_t inquotes = 0;
	for (int x = 0; x < length; x++) {
		//if new whitespace, push token back else pass
		if (isspace(string[x]) && !inquotes) {
			if (working.length() != 0) {
				ret.push_back(working);
				working = "";
			}
			else continue;
		}
		else {
			if (string[x] == '\"') inquotes = ~inquotes;
			else working.push_back(string[x]);
		}
	}
	if (working.length()) ret.push_back(working);

	return ret;
}

const char* errorvals[] = {
	"FILE DOES NOT EXIST",
	"BAD PASSWORD",
	"BAD CHECKSUM",
	"WRITE FAILED"
};

int ProcessCommand() {
	auto tokens = tokenize(commandbuf, commandlen);
	commandlen = 0;

	if (tokens.size() == 0) return 0; //no command, pass
	
	//load file command
	if (tokens[0] == "LoadFile") {
		if (tokens.size() != 3) {
			std::cout << "FAILURE BAD ARGUMENTS\n";
		}
		else {
			uint32_t errorcode = 0;
			if (!(errorcode = LoadEncryptedFile(tokens[2], tokens[1], rawdata))) {
				std::cout << "SUCCESS " << rawdata.size() << "\n";
				std::fwrite(rawdata.data(), 1, rawdata.size(), stdout);
			}
			else {
				std::cout << "FAILURE " << errorvals[errorcode - 1] << "\n";
			}
		}
	}

	//start savefile command
	if (tokens[0] == "SaveFile") {
		if (tokens.size() != 4) {
			std::cout << "FAILURE BAD ARGUMENTS\n";
		}
		else {
			readlengthremaining = strtoull(tokens[3].c_str(), nullptr, 10);
			if (readlengthremaining == 0) {
				std::cout << "FAILURE BAD LENGTH\n";
			}
			else {
				tempfilename = tokens[2];
				temppassword = tokens[1];
				interpretermode = DATAMODE;
				rawdata.clear();
				rawdata.reserve(readlengthremaining);
			}
		}
	}

	//version
	if (tokens[0] == "Version") {
		if (tokens.size() > 1 && tokens[1] == "-V") std::cout << "SUCCESS " << VERSION_ID_VERBOSE << "\n";
		else std::cout << "SUCCESS " << VERSION_ID << "\n";
	}

	//exit
	if (tokens[0] == "Exit") {
		return 1;
	}

	return 0;
}

int ProcessRawbuffer(){
	uint32_t errorcode = SaveEncryptedFile(tempfilename, temppassword, rawdata);
	if (errorcode) {
		std::cout << "FAILURE " << errorvals[errorcode - 1] << "\n";
	}else {
		std::cout << "SUCCESS\n";
	}

	tempfilename = "";
	temppassword = "";
	rawdata.clear();
	interpretermode = COMMANDMODE;

	return 0;
}

