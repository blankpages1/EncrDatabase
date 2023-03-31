#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <conio.h>
#include "Cryptography.h"
#include "EncryptedFile.h"

struct databaseEntry {
	std::string service;
	std::string username;
	std::string password;
	databaseEntry(std::string l, std::string u, std::string p) :service(l), username(u), password(p) {};
};

std::vector<databaseEntry> parseData(const std::vector<char>& data) {
	std::vector<std::string> strings;
	strings.push_back("");

	//convert char[] into strings
	uint64_t index = 0;
	bool newLine = false;
	for (char c : data) {
		if (newLine) {
			newLine = false;
			index++;
			strings.push_back("");
		}
		if (c != 0x0) {
			strings[index].push_back(c);
		}
		else {
			newLine = true;
		}
	}
	
	//load strings into structure
	std::vector<databaseEntry> ret;
	for (uint64_t i = 0; i < strings.size() / 3; i++)
		ret.push_back(databaseEntry(strings[i * 3], strings[i * 3 + 1], strings[i * 3 + 2]));

	return ret;
}

void loadData(const std::vector<databaseEntry>& data, EncryptedFile& file) {
	file.getData().clear();

	//load data into vector
	for (const databaseEntry& d : data) {
		for (const char& c : d.service) {
			file.getData().push_back(c);
		}
		file.getData().push_back(0);

		for (const char& c : d.username) {
			file.getData().push_back(c);
		}
		file.getData().push_back(0);

		for (const char& c : d.password) {
			file.getData().push_back(c);
		}
		file.getData().push_back(0);
	}
}

void renderData(std::vector<databaseEntry> data) {
	std::cout << "Service | Username | Password\n";
	if (data.size() == 0)
		std::cout << "NO ENTRIES\n";
	for (int i = 0; i < data.size(); i++)
		std::cout << i << ": " << data[i].service << " | " << data[i].username << " | " << data[i].password << "\n";
}

void proc(std::string password) {
	EncryptedFile file("./database.bin", password);
	uint32_t fileError = file.getError();
	
	if (!fileError) {
		std::vector<databaseEntry> data = parseData(file.getData());

		std::string input;
		while (1) {

			std::cout << "---------------------------------------------------\n";
			renderData(data);
			std::cout << "\n";

			std::cout << "1) Create Entry\n2) Delete Entry\n3) Exit\n";
			std::cout << "Choice> ";
			std::getline(std::cin, input);

			if (input == "1") {
				//create entry at end of vector
				databaseEntry newEntry("", "", "");

				std::cout << "Service Name> ";
				std::getline(std::cin, input);
				newEntry.service = input;

				std::cout << "Username> ";
				std::getline(std::cin, input);
				newEntry.username = input;

				std::cout << "Password> ";
				std::getline(std::cin, input);
				newEntry.password = input;

				data.push_back(newEntry);
				//end
			}
			else if (input == "2") {
				//delete entry at index
				std::cout << "Select Entry #> ";
				std::getline(std::cin, input);
				try {
					uint64_t index = std::stoi(input);
					if (index >= data.size())
						std::cout << "Data Out of Range: " << index << "\n";
					else {
						data.erase(data.begin() + index);
					}
				}
				catch(...){
					std::cout << "Invalid Data Entered\n";
				}
				//end
			}
			else if (input == "3") {
				break;
			}
			else {
				std::cout << "Invalid Input Code\n";
			}

			std::cout << "\n";
		}

		//ask user whether to save file
		std::string selectSave;
		while (true) {
			std::cout << "Save File (y/n)> ";
			std::getline(std::cin, selectSave);
			if (selectSave == "y" || selectSave == "Y") {
				std::cout << "Saving File\n";
				loadData(data, file);
				file.writeFile();
				break;
			}
			else if(selectSave == "n" || selectSave == "N") {
				std::cout << "Changes Discarded\n";
				break;
			}
		}
	}
	//if the file has an error
	else {
		if (fileError == file.EF_BAD_CHECKSUM) {
			std::cout << "Checksum does not match\n";
		}
		else if (fileError == file.EF_BAD_PASSWORD) {
			std::cout << "Incorrect password\n";
		}
		else if (fileError == file.EF_DOES_NOT_EXIST) {
			std::cout << "File created\n";
			file.writeFile();
		}
	}
}

void main(int argc, char** argv) {
	std::string password;

	if (argc == 1) {

		//read password from console
		std::cout << "Input Password> ";
		std::string password;
		char input = 0;
		while ((input = _getch()) != '\r') {
			if (input == '\b') {
				if (password.size() != 0) {
					password.pop_back();
					std::cout << "\b \b";
				}
			}
			else {
				password.push_back(input);
				std::cout << "*";
			}
		}
		std::cout << "\n";

		proc(password);
	}
	else {
		std::cout << "Bad Arguments\n";
	}

	std::cout << "Press any key to exit\n";
	_getch();
}