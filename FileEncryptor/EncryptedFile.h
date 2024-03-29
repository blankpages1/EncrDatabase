#pragma once
#include <fstream>
#include <vector>

//Class based interface
class EncryptedFile{
public:
	EncryptedFile(const std::string& filelocation, const std::string& password);
	~EncryptedFile();

	void writeFile();
	std::vector<char>& getData() { return data; };

	uint32_t getError();
	enum EF_ERROR : uint32_t {
		EF_NO_ERROR = 0,
		EF_DOES_NOT_EXIST = 1,
		EF_BAD_PASSWORD = 2,
		EF_BAD_CHECKSUM = 3
	};

private:
	uint32_t error;

	uint32_t checksum;
	uint64_t datasize;

	std::vector<char> data;

	std::string fileLocation;
	std::string password;
};

//functional interface
enum : uint32_t {
	EF_NO_ERROR = 0,
	EF_DOES_NOT_EXIST = 1,
	EF_BAD_PASSWORD = 2,
	EF_BAD_CHECKSUM = 3,
	EF_WRITE_FAILED = 4
};

uint32_t LoadEncryptedFile(const std::string& filename, const std::string& password, std::vector<uint8_t>& buffer);
uint32_t SaveEncryptedFile(const std::string& filename, const std::string& password, std::vector<uint8_t> buffer);
