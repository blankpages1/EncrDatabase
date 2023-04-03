#pragma once
#include <immintrin.h>
#include <string>
#include <vector>

struct INT256;
struct INT128;

struct INT256 {
	INT256();
	INT256(const INT128& otherA, const INT128& otherB);
	INT256(const __m256i& other);
	operator INT128();
	__m256i getData() const;
	uint8_t data[32] = {};
};
struct INT128 {
	INT128();
	INT128(const INT256& other);
	INT128(const INT128& other);
	INT128(const __m128i& other);
	INT128 operator^(const INT128& other);
	__m128i getData() const;
	uint8_t data[16] = {};
};

namespace crypto {
	void SHA2_256(std::string message, INT256& data);
	
	std::vector<__m128i> AESKeySchedule_128(const INT128& key);
	void AESEncrypt_128(const std::vector<__m128i>& keys, INT128& data, INT128& proc);
	void AESDecrypt_128(const std::vector<__m128i>& keys, INT128& data, INT128& proc);
}
