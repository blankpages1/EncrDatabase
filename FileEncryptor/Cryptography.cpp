#include "Cryptography.h"
#include <iostream>
#include <wmmintrin.h>

INT256::INT256(){
	std::memset(data, 0, 32);
}
INT256::INT256(const INT128& otherA, const INT128& otherB){
	for (int i = 0; i < 16; i++)
		data[i] = otherA.data[i];
	for (int i = 0; i < 16; i++)
		data[16 + i] = otherB.data[i];
}
INT256::INT256(const __m256i& other){
	_mm256_storeu_si256((__m256i*)data, other);
}
INT256::operator INT128(){
	return INT128(*this);
}
__m256i INT256::getData() const{
	return _mm256_loadu_si256((__m256i*)data);
}

INT128::INT128(){
	std::memset(data, 0, 16);
}
INT128::INT128(const INT256& other){
	for (int i = 0; i < 16; i++)
		data[i] = other.data[i];
}
INT128::INT128(const INT128& other){
	for (int i = 0; i < 16; i++)
		data[i] = other.data[i];
}
INT128::INT128(const __m128i& other){
	_mm_storeu_si128((__m128i*)data, other);
}
__m128i INT128::getData() const{
	return _mm_loadu_si128((__m128i*)data);
}

//sha256 specific
uint32_t add(uint64_t ri, uint64_t le) {
	return (ri + le) % uint64_t(0x100000000);
}
uint32_t rotl(uint32_t data, uint32_t n) {
	return (data << n) | (data >> 32 - n);
}
uint32_t rotr(uint32_t data, uint32_t n) {
	return (data >> n) | (data << 32 - n);
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ ((~x) & z);
}
uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sum0(uint32_t x) {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
uint32_t sum1(uint32_t x) {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t o0(uint32_t x) {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
uint32_t o1(uint32_t x) {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void crypto::SHA2_256(std::string message, INT256& container){
	
	uint64_t messageSizeB = message.size();
	uint64_t finalBytes = std::ceill(double(messageSizeB + 9) / 64) * 64;
	std::vector<uint8_t> data;
	for (int i = 0; i < finalBytes; i++)
		data.push_back(0);

	for (int i = 0; i < message.size(); i++)
		data[i] = message[i];
	data[message.size()] = 1 << 7;
	
	uint64_t messageSizeb = messageSizeB * 8;
	for (int i = 0; i < 8; i++) {
		data[data.size() - 1 - i] = ((uint8_t*)&messageSizeb)[i];
	}

#ifdef _DEBUG
	for (int x = 0; x < finalBytes * 8; x++) {
		if (!(x % 8))
			std::cout << "\n";
		std::cout << (((data[floor(x / 8)] >> (7 - (x % 8))) & 1) ? "1" : "0");
	}
	std::cout << "\n";
#endif

	//array of constants
	const uint32_t const CONSTANTS[] = { 
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	uint32_t hashValues[8] = {0x6a09e667, 0xbb67ae85 , 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	uint64_t fSizeb = data.size() * uint64_t(8);
	for (uint64_t i = 0; i < (fSizeb / 512); i++) {
		uint32_t W[64];
		std::memset(W, 0, 256);

		for (uint64_t t = 0; t < 16; t++) {
			W[t] = data[(t * 4) + (i * uint64_t(64))] << 24 | data[(t * 4) + 1 + (i * uint64_t(64))] << 16 | data[(t * 4) + 2 + (i * uint64_t(64))] << 8 | data[(t * 4) + 3 + (i * uint64_t(64))];

#ifdef _DEBUG
			std::cout << W[t] << "\n";
#endif
		}
		for (int t = 16; t < 64; t++) {
			uint32_t t1 = o1(W[t - 2]);
			uint32_t t2 = W[t - 7];
			uint32_t t3 = o0(W[t -15]);
			uint32_t t4 = W[t - 16];
			W[t] = add(add(t1, t2), add(t3, t4));
		}

		//initialize working variables
		uint32_t a = hashValues[0];
		uint32_t b = hashValues[1];
		uint32_t c = hashValues[2];
		uint32_t d = hashValues[3];
		uint32_t e = hashValues[4];
		uint32_t f = hashValues[5];
		uint32_t g = hashValues[6];
		uint32_t h = hashValues[7];

		for (int t = 0; t < 64; t++) {
			uint32_t t1 = add(add(add(h, sum1(e)), add(ch(e, f, g), CONSTANTS[t])), W[t]);
			uint32_t t2 = add(sum0(a), maj(a, b, c));
			h = g;
			g = f;
			f = e;
			e = add(d, t1);
			d = c;
			c = b;
			b = a;
			a = add(t1, t2);
		}

		hashValues[0] = add(a, hashValues[0]);
		hashValues[1] = add(b, hashValues[1]);
		hashValues[2] = add(c, hashValues[2]);
		hashValues[3] = add(d, hashValues[3]);
		hashValues[4] = add(e, hashValues[4]);
		hashValues[5] = add(f, hashValues[5]);
		hashValues[6] = add(g, hashValues[6]);
		hashValues[7] = add(h, hashValues[7]);
	}

#ifdef  _DEBUG
	printf("0x%x%x%x%x%x%x%x%x\n", hashValues[0], hashValues[1], hashValues[2], hashValues[3], hashValues[4], hashValues[5], hashValues[6], hashValues[7]);
#endif
	
	for (int x = 0; x < 8; x++) {
		container.data[0 + (4 * x)] = uint8_t(hashValues[x] >> 24);
		container.data[1 + (4 * x)] = uint8_t(hashValues[x] >> 16);
		container.data[2 + (4 * x)] = uint8_t(hashValues[x] >> 8);
		container.data[3 + (4 * x)] = uint8_t(hashValues[x]);
	}
}

#define AESKEYEXPAND(k, e) aesKeyExpansion(k, _mm_aeskeygenassist_si128(k, e))
__m128i aesKeyExpansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}
std::vector<__m128i> crypto::AESKeySchedule_128(const INT128& data){
	std::vector<__m128i> ret;
	ret.push_back(data.getData());
	ret.push_back(AESKEYEXPAND(ret[0], 0x01));
	ret.push_back(AESKEYEXPAND(ret[1], 0x02));
	ret.push_back(AESKEYEXPAND(ret[2], 0x04));
	ret.push_back(AESKEYEXPAND(ret[3], 0x08));
	ret.push_back(AESKEYEXPAND(ret[4], 0x10));
	ret.push_back(AESKEYEXPAND(ret[5], 0x20));
	ret.push_back(AESKEYEXPAND(ret[6], 0x40));
	ret.push_back(AESKEYEXPAND(ret[7], 0x80));
	ret.push_back(AESKEYEXPAND(ret[8], 0x1B));
	ret.push_back(AESKEYEXPAND(ret[9], 0x36));
	ret.push_back(_mm_aesimc_si128(ret[9]));
	ret.push_back(_mm_aesimc_si128(ret[8]));
	ret.push_back(_mm_aesimc_si128(ret[7]));
	ret.push_back(_mm_aesimc_si128(ret[6]));
	ret.push_back(_mm_aesimc_si128(ret[5]));
	ret.push_back(_mm_aesimc_si128(ret[4]));
	ret.push_back(_mm_aesimc_si128(ret[3]));
	ret.push_back(_mm_aesimc_si128(ret[2]));
	ret.push_back(_mm_aesimc_si128(ret[1]));
	return ret;
}

void crypto::AESEncrypt_128(const std::vector<__m128i>& keys, INT128& data, INT128& proc){
	__m128i m = data.getData();
	m = _mm_xor_si128(m, keys[0]);
	m = _mm_aesenc_si128(m, keys[1]);
	m = _mm_aesenc_si128(m, keys[2]);
	m = _mm_aesenc_si128(m, keys[3]);
	m = _mm_aesenc_si128(m, keys[4]);
	m = _mm_aesenc_si128(m, keys[5]);
	m = _mm_aesenc_si128(m, keys[6]);
	m = _mm_aesenc_si128(m, keys[7]);
	m = _mm_aesenc_si128(m, keys[8]);
	m = _mm_aesenc_si128(m, keys[9]);
	m = _mm_aesenclast_si128(m, keys[10]);
	proc = INT128(m);
}

void crypto::AESDecrypt_128(const std::vector<__m128i>& keys, INT128& data, INT128& proc){
	__m128i m = data.getData();
	m = _mm_xor_si128(m, keys[10]);
	m = _mm_aesdec_si128(m, keys[11]);
	m = _mm_aesdec_si128(m, keys[12]);
	m = _mm_aesdec_si128(m, keys[13]);
	m = _mm_aesdec_si128(m, keys[14]);
	m = _mm_aesdec_si128(m, keys[15]);
	m = _mm_aesdec_si128(m, keys[16]);
	m = _mm_aesdec_si128(m, keys[17]);
	m = _mm_aesdec_si128(m, keys[18]);
	m = _mm_aesdec_si128(m, keys[19]);
	m = _mm_aesdeclast_si128(m, keys[0]);
	proc = INT128(m);
}
