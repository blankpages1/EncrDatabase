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

			INT128 encRead;
			INT128 decRead;
			for(int i = 0; i < std::ceil(double(datasize)/16); i++) {
				file.read((char*)encRead.data, 16);
				crypto::AESDecrypt_128(keys, encRead, decRead);
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
		crypto::AESEncrypt_128(keys, *(INT128*)(&data[i * 16]), encData);
		file.write((char*)encData.data, 16);
	}
	
	file.close();
}

uint32_t EncryptedFile::getError(){
	return error;
}
