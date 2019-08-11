#include "AesCrypto.h"

namespace my_cryptoAes {

	void AesCrypto::printBlock(u_char** b)
	{
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
				std::cout << std::hex << (((int)b[i][j]) & 0xff) << ' ';
			std::cout << '\n';
		}
	}

	void AesCrypto::printWord(u_char* w)
	{
		for (int i = 0; i < 4; i++)
			std::cout << std::hex << (((int)w[i]) & 0xff) << ' ';
		std::cout << '\n';
	}

	void AesCrypto::SubBytes(u_char** block)
	{
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
			{
				int x = (block[i][j] & 0xf0) >> 4;
				int y = block[i][j] & 0x0f;
				block[i][j] = (*this).s_box[x][y];
			}
	}

	void AesCrypto::invSubBytes(u_char** block)
	{
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
			{
				int x = (block[i][j] & 0xf0) >> 4;
				int y = block[i][j] & 0x0f;
				block[i][j] = (*this).invs_box[x][y];
			}
	}

	void AesCrypto::ShiftRows(u_char** block)
	{
		for (int i = 1; i < 4; i++)
		{
			u_char tmp[4] = { block[i][0], block[i][1], block[i][2], block[i][3] };
			int j = i, pointer = 0;
			for (j; j < 4; j++)
				block[i][pointer++] = tmp[j];
			for (j = 0; j < i; j++)
				block[i][pointer++] = tmp[j];
		}
	}

	void AesCrypto::invShiftRows(u_char** block)
	{
		for (int i = 1; i < 4; i++)
		{
			u_char tmp[4] = { block[i][0], block[i][1], block[i][2], block[i][3] };
			int j = 4 - i, pointer = 0;
			for (j; j < 4; j++)
				block[i][pointer++] = tmp[j];
			for (j = 0; j < 4 - i; j++)
				block[i][pointer++] = tmp[j];
		}
	}

	u_char gmul_x(u_char a)
	{
		int check = 0x80;
		return (check & a) ? (u_char)(((a << 1) ^ 0x1b) & 0xff) : (u_char)((a << 1) & 0xff);
	}

	u_char* mul_on_row(u_char* row)
	{
		u_char* res = (u_char*)malloc(sizeof(u_char) * 4);
		if (res)
		{
			memset(res, 0, sizeof(u_char) * 4);

			res[0] = gmul_x(row[0]) ^ (gmul_x(row[1]) ^ row[1]) ^ row[2] ^ row[3];
			res[1] = row[0] ^ gmul_x(row[1]) ^ (gmul_x(row[2]) ^ row[2]) ^ row[3];
			res[2] = row[0] ^ row[1] ^ gmul_x(row[2]) ^ (gmul_x(row[3]) ^ row[3]);
			res[3] = (gmul_x(row[0]) ^ row[0]) ^ row[1] ^ row[2] ^ gmul_x(row[3]);
			return res;
		}
		return NULL;
	}

	void AesCrypto::MixColumns(u_char** block)
	{
		for (int i = 0; i < 4; i++)
		{
			u_char* tmp = (u_char*)malloc(sizeof(u_char) * 4);
			if (tmp)
			{
				for (int j = 0; j < 4; j++)
					tmp[j] = block[j][i];

				tmp = mul_on_row(tmp);

				for (int j = 0; j < 4; j++)
					block[j][i] = tmp[j];

				free(tmp);
			}
			else
			{
				system("break");
			}
		}
	}

	// invMixColumns
	inline u_char mulE(u_char a)
	{
		// a * 0x0e = {a * 0x02 * 0x02 * 0x02} + {a * 0x02 * 0x02} + {a * 0x02}
		return ((gmul_x(gmul_x(gmul_x(a)))) ^ (gmul_x(gmul_x(a))) ^ gmul_x(a));
	}

	inline u_char mulB(u_char a)
	{
		return ((gmul_x(gmul_x(gmul_x(a)))) ^ gmul_x(a) ^ a);
	}

	inline u_char mulD(u_char a)
	{
		return ((gmul_x(gmul_x(gmul_x(a)))) ^ gmul_x(gmul_x(a)) ^ a);
	}

	inline u_char mul9(u_char a)
	{
		return (gmul_x(gmul_x(gmul_x(a))) ^ a);
	}

	u_char* inv_mul_on_row(u_char* row)
	{
		u_char* res = (u_char*)malloc(sizeof(u_char) * 4);
		assert(res);
		res[0] = mulE(row[0]) ^ mulB(row[1]) ^ mulD(row[2]) ^ mul9(row[3]);
		res[1] = mul9(row[0]) ^ mulE(row[1]) ^ mulB(row[2]) ^ mulD(row[3]);
		res[2] = mulD(row[0]) ^ mul9(row[1]) ^ mulE(row[2]) ^ mulB(row[3]);
		res[3] = mulB(row[0]) ^ mulD(row[1]) ^ mul9(row[2]) ^ mulE(row[3]);
		return res;
	}

	void AesCrypto::invMixColumns(u_char** block)
	{
		for (int i = 0; i < 4; i++)
		{
			u_char* tmp = (u_char*)malloc(sizeof(u_char) * 4);
			assert(tmp);
			for (int j = 0; j < 4; j++)
				tmp[j] = block[j][i];

			tmp = inv_mul_on_row(tmp);

			for (int j = 0; j < 4; j++)
				block[j][i] = tmp[j];

			free(tmp);
		}
	}

	// Key exec
	void AesCrypto::RotWord(u_char* word)
	{
		u_char cWord[4] = { word[0], word[1], word[2], word[3] }; // copy
		for (int i = 1, j = 0; i < 4; i++, j++)
			word[j] = cWord[i];
		word[3] = cWord[0];
	}

	void AesCrypto::WordSubBytes(u_char* word)
	{
		for (int i = 0; i < 4; i++)
		{
			int x = (word[i] & 0xf0) >> 4;
			int y = word[i] & 0x0f;
			word[i] = (*this).s_box[x][y];
		}
	}

	void AesCrypto::ExecCurRoundKey(u_char** key, int round)
	{
		u_char* word3 = (u_char*)malloc(sizeof(u_char) * 4);
		assert(word3);
		for (int i = 0; i < 4; i++)
			word3[i] = key[i][3];
		RotWord(word3);
		WordSubBytes(word3);

		key[0][0] = key[0][0] ^ word3[0] ^ (*this).Rcon[round][0];
		key[1][0] = key[1][0] ^ word3[1] ^ (*this).Rcon[round][1];
		key[2][0] = key[2][0] ^ word3[2] ^ (*this).Rcon[round][2];
		key[3][0] = key[3][0] ^ word3[3] ^ (*this).Rcon[round][3];

		for (int i = 1; i < 4; i++) // columns
			for (int j = 0; j < 4; j++) // rows
			{
				key[j][i] = key[j][i] ^ key[j][i - 1];
			}

		free(word3);
	}

	void AesCrypto::AddRoundKey(u_char** block, u_char** key)
	{
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				block[i][j] ^= key[i][j];
	}

	u_char* AesCrypto::encrypt(u_char* block, u_char* key)
	{
		/*u_char test1[4][4] = { 
			{ 0x2b, 0x28, 0xab, 0x09 },
			{ 0x7e, 0xae, 0xf7, 0xcf },
			{ 0x15, 0xd2, 0x15, 0x4f },
			{ 0x16, 0xa6, 0x88, 0x3c }
		};*/

		u_char** mBlock = (u_char**)malloc(sizeof(u_char*) * 4);
		u_char** bKey = (u_char * *)malloc(sizeof(u_char*) * 4);
		assert(mBlock);
		assert(bKey);
		for (int i = 0; i < 4; i++)
		{
			mBlock[i] = (u_char*)malloc(sizeof(u_char) * 4);
			bKey[i] = (u_char*)malloc(sizeof(u_char) * 4);
			assert(mBlock[i]);
			assert(bKey[i]);
			assert(memcpy(mBlock[i], block + (4 * i), 4));
			assert(memcpy(bKey[i], key + (4 * i), 4));
		}

		// START
		AddRoundKey(mBlock, bKey);

		// Rounds (1..9)
		for (int i = 1; i < 10; i++)
		{
			SubBytes(mBlock);
			ShiftRows(mBlock);
			MixColumns(mBlock);

			ExecCurRoundKey(bKey, i);
			AddRoundKey(mBlock, bKey);
		}

		// Last round
		SubBytes(mBlock);
		ShiftRows(mBlock);

		ExecCurRoundKey(bKey, 10);
		AddRoundKey(mBlock, bKey);

		// structuring result
		u_char* res = (u_char*)malloc(sizeof(u_char) * 16);
		assert(res);
		for (int i = 0; i < 4; i++)
			assert(memcpy(res + (4 * i), mBlock[i], 4));

		// free memory
		for (int i = 0; i < 4; i++)
		{
			free(mBlock[i]);
			free(bKey[i]);
		}

		return res;
	}

	u_char* AesCrypto::decrypt(u_char* block, u_char* key)
	{
		u_char** mBlock = (u_char * *)malloc(sizeof(u_char*) * 4);
		u_char** bKey = (u_char * *)malloc(sizeof(u_char*) * 4);
		assert(mBlock);
		assert(bKey);
		for (int i = 0; i < 4; i++)
		{
			mBlock[i] = (u_char*)malloc(sizeof(u_char) * 4);
			bKey[i] = (u_char*)malloc(sizeof(u_char) * 4);
			assert(mBlock[i]);
			assert(bKey[i]);
			assert(memcpy(mBlock[i], block + (4 * i), 4));
			assert(memcpy(bKey[i], key + (4 * i), 4));
		}

		// keys for every round
		u_char*** keys = (u_char ***)malloc(sizeof(u_char**) * 11);
		assert(keys);

		//Original key
		keys[0] = (u_char**)malloc(sizeof(u_char*) * 4); // u_char**
		assert(keys[0]);
		for (int i = 0; i < 4; i++)
		{
			keys[0][i] = (u_char*)malloc(sizeof(u_char) * 4);
			assert(keys[0][i]);
			assert(memcpy(keys[0][i], bKey[i], 4));
		}

		// others keys
		for (int i = 1; i < 11; i++)
		{
			keys[i] = (u_char * *)malloc(sizeof(u_char*) * 4); // u_char**
			assert(keys[i]);
			ExecCurRoundKey(bKey, i);
			for (int j = 0; j < 4; j++)
			{
				keys[i][j] = (u_char*)malloc(sizeof(u_char) * 4);
				assert(keys[i][j]);
				assert(memcpy(keys[i][j], bKey[j], 4));
			}
		}

		// START
		AddRoundKey(mBlock, keys[10]);

		// Rounds 1..9
		for (int i = 1; i < 10; i++)
		{
			invShiftRows(mBlock);
			invSubBytes(mBlock);
			AddRoundKey(mBlock, keys[10 - i]);
			invMixColumns(mBlock);
		}

		// last round
		invShiftRows(mBlock);
		invSubBytes(mBlock);
		AddRoundKey(mBlock, keys[0]);

		// structuring result
		u_char* res = (u_char*)malloc(sizeof(u_char) * 16);
		assert(res);
		for (int i = 0; i < 4; i++)
			assert(memcpy(res + (4 * i), mBlock[i], 4));


		// free memory
		for (int i = 0; i < 4; i++)
		{
			free(mBlock[i]);
			free(bKey[i]);
		}
		for (int i = 0; i < 11; i++)
			for (int j = 0; j < 4; j++)
				free(keys[i][j]);


		return res;
	}

}