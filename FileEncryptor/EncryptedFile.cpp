#include "EncryptedFile.h"
#include "Cryptography.h"
#include <iostream>

//Not Used Anymore
/*
void createFileEF(const std::string& filelocation, const std::string& password) {
	std::fstream file(filelocation, std::ios::out | std::ios::binary);

	uint32_t checksum = 0;
	uint64_t datasize = 0;

	uint8_t data[16] = {};
	data[0] = 'E';
	data[1] = 'F';
	data[2] = 'D';
	data[3] = 'T';
	*((uint32_t*)(&data[4])) = checksum;
	*((uint64_t*)(&data[8])) = datasize;

	INT256 hash;
	crypto::SHA2_256(password, hash);
	std::vector<__m128i> keys;
	keys = crypto::AESKeySchedule_128(INT128(hash));

	INT128 filedata;
	crypto::AESEncrypt_128(keys, *(INT128*)data, filedata);
	file.write((char*)filedata.data, 16);
	file.close();
}
*/

EncryptedFile::EncryptedFile(const std::string& filelocation, const std::string& passIn):error(EF_NO_ERROR),checksum(0), datasize(0), data(), fileLocation(filelocation), password(passIn){
	std::fstream file(fileLocation, std::ios::in | std::ios::binary);
	if (file.is_open()) {
		INT128 encryptedHeader;
		file.read((char*)encryptedHeader.data, 16);

		INT256 hash;
		crypto::SHA2_256(password, hash);
		std::vector<__m128i> keys;
		keys = crypto::AESKeySchedule_128(INT128(hash));

		INT128 decryptedHeader;
		crypto::AESDecrypt_128(keys, encryptedHeader, decryptedHeader);

		if (!memcmp(decryptedHeader.data, "EFDT", 4)) {
			checksum = *(uint32_t*)(&decryptedHeader.data[4]);
			datasize = *(uint64_t*)(&decryptedHeader.data[8]);
			
			data.reserve(datasize);

			INT128 encRead, encPrev = encryptedHeader;
			INT128 decRead;
			for(int i = 0; i < std::ceil(double(datasize)/16); i++) {
				file.read((char*)encRead.data, 16);
				crypto::AESDecrypt_128(keys, encRead, decRead);
				decRead = decRead ^ encPrev;
				encPrev = encRead;
				for (int i = 0; i < 16; i++)
					data.push_back(decRead.data[i]);
			}

			uint32_t workingSum = 0;
			for (uint64_t i = 0; i < data.size() / 4; i++) {
				workingSum += *(uint32_t*)(&data[i * 4]);
			}

			while(datasize - data.size())
				data.pop_back();

			if (workingSum ^ checksum) {
				error = EF_BAD_CHECKSUM;
			}
		}
		else {
			error = EF_BAD_PASSWORD;
		}
	}
	else {
		error = EF_DOES_NOT_EXIST;
	}
	file.close();
}

EncryptedFile::~EncryptedFile(){
}

void EncryptedFile::writeFile() {
	datasize = data.size();

	if (data.size() % 16) {
		uint32_t loops = (16 - (data.size() % 16));
		for (int i = 0; i < loops; i++)
			data.push_back(0);
	}

	uint32_t workingSum = 0;
	for (uint64_t i = 0; i < data.size() / 4; i++) {
		workingSum += *(uint32_t*)(&data[i * 4]);
	}
	checksum = workingSum;

	uint8_t header[16] = {};
	header[0] = 'E';
	header[1] = 'F';
	header[2] = 'D';
	header[3] = 'T';
	*((uint64_t*)(&header[8])) = datasize;
	*((uint32_t*)(&header[4])) = checksum;

	std::fstream file(fileLocation, std::ios::out | std::ios::binary);

	INT256 hash;
	crypto::SHA2_256(password, hash);
	std::vector<__m128i> keys;
	keys = crypto::AESKeySchedule_128(INT128(hash));

	INT128 encData;
	crypto::AESEncrypt_128(keys, *(INT128*)header, encData);
	file.write((char*)encData.data, 16);
	for (uint64_t i = 0; i < data.size() / 16; i++) {
		INT128 toenc = *(INT128*)(&data[i * 16]) ^ encData;
		crypto::AESEncrypt_128(keys, toenc, encData);
		file.write((char*)encData.data, 16);
	}
	
	file.close();
}

uint32_t EncryptedFile::getError(){
	return error;
}

uint32_t LoadEncryptedFile(const std::string& filename, const std::string& password, std::vector<uint8_t>& buffer){
	uint32_t error = EF_NO_ERROR;
	uint32_t checksum;
	uint64_t datasize;

	//open file
	std::fstream file(filename, std::ios::in | std::ios::binary);

	if (!file.fail()) {
		//hash password and get AES 128 keys
		INT256 hash;
		crypto::SHA2_256(password, hash);
		std::vector<__m128i> keys;
		keys = crypto::AESKeySchedule_128(INT128(hash));

		//read encrypted header and decrypt
		INT128 encryptedHeader;
		file.read((char*)encryptedHeader.data, 16);

		INT128 decryptedHeader;
		crypto::AESDecrypt_128(keys, encryptedHeader, decryptedHeader);

		//check that header is valid
		if (!memcmp(decryptedHeader.data, "EFDT", 4)) {

			//get stored checksum and datasize
			checksum = *(uint32_t*)(&decryptedHeader.data[4]);
			datasize = *(uint64_t*)(&decryptedHeader.data[8]);

			//reserve buffer with extra for padding bits at end
			buffer.clear();
			buffer.reserve(datasize + 16);

			//decrypt file block by block
			INT128 encRead, encPrev = encryptedHeader;
			INT128 decRead;
			for (int i = 0; i < std::ceil(double(datasize) / 16); i++) {
				//read block from file
				file.read((char*)encRead.data, 16);

				//decrypt block
				crypto::AESDecrypt_128(keys, encRead, decRead);
				
				//xor with previous code for cypher block chaining
				decRead = decRead ^ encPrev;
				encPrev = encRead;

				//add decrypted data to output 
				for (int i = 0; i < 16; i++)
					buffer.push_back(decRead.data[i]);
			}

			//calculate checksum of entire message
			uint32_t workingSum = 0;
			for (uint64_t i = 0; i < buffer.size() / 4; i++) {
				workingSum += *(uint32_t*)(&buffer[i * 4]);
			}

			//remove 'padding' bytes
			while (datasize - buffer.size())
				buffer.pop_back();

			if (workingSum ^ checksum) {
				error = EF_BAD_CHECKSUM; //checksum didnt match
			}
		}
		else {
			error = EF_BAD_PASSWORD; //unexpected header values
		}
	}
	else {
		error = EF_DOES_NOT_EXIST; //file does not exist
	}

	file.close();

	return error;
}

uint32_t SaveEncryptedFile(const std::string& filename, const std::string& password, std::vector<uint8_t> buffer){
	uint32_t error = EF_NO_ERROR;
	uint32_t checksum = 0;
	uint64_t datasize = 0;
	
	//get datasize for header
	datasize = buffer.size();

	//add padding to make blocksize
	if (buffer.size() % 16) {
		uint32_t loops = (16 - (buffer.size() % 16));
		for (int i = 0; i < loops; i++)
			buffer.push_back(0);
	}

	//calculate checksum
	for (uint64_t i = 0; i < buffer.size() / 4; i++) {
		checksum += *(uint32_t*)(&buffer[i * 4]);
	}

	//define header data
	uint8_t header[16] = {};
	header[0] = 'E';
	header[1] = 'F';
	header[2] = 'D';
	header[3] = 'T';
	*((uint64_t*)(&header[8])) = datasize;
	*((uint32_t*)(&header[4])) = checksum;

	//open file
	std::fstream file(filename, std::ios::out | std::ios::binary);
	if (!file.fail()) {

		//get password hash and AES KEYS
		INT256 hash;
		crypto::SHA2_256(password, hash);
		std::vector<__m128i> keys;
		keys = crypto::AESKeySchedule_128(INT128(hash));

		INT128 encData;

		//encrypt header and write
		crypto::AESEncrypt_128(keys, *(INT128*)header, encData);
		file.write((char*)encData.data, 16);
		
		//encrypt each block and write
		for (uint64_t i = 0; i < buffer.size() / 16; i++) {
			//xor raw data with previous encrypted data for cypher block chaining
			INT128 toenc = *(INT128*)(&buffer[i * 16]) ^ encData;
			
			//encrypt and write
			crypto::AESEncrypt_128(keys, toenc, encData);
			file.write((char*)encData.data, 16);
		}

	}
	else {
		error = EF_WRITE_FAILED; //file could not be written
	}

	file.close();

	return error;
}
