#include"main.h"

#define memzero(buf, n) (void)memset(buf, 0, n)

typedef unsigned long u_long;
typedef unsigned char u_char;
typedef struct
{
	uint64_t bytes;
	uint32_t A, B, C, D;
	u_char buffer[64];
} md5_t;

// если через хидер выкидывал странные ворнинги..
// поэтому немножко костылим..

void md5_init(md5_t *ctx);
void md5_update(md5_t *ctx, const void *data, size_t size);
void md5_final(u_char result[16], md5_t *ctx);
static const u_char *md5_body(md5_t *ctx, const u_char *data, size_t size);
void md5_hash(const char *message, u_char result[16]);

void md5_init(md5_t *ctx) {
	ctx->A = 0x67452301;
	ctx->B = 0xefcdab89;
	ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;

	ctx->bytes = 0;
}

void md5_update(md5_t *ctx, const void *data, size_t size) {
	size_t used, free;

	used = (size_t)(ctx->bytes & 0x3f);
	ctx->bytes += size;

	if (used)	{
		free = 64 - used;

		if (size < free) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, free);
		data = (u_char *)data + free;
		size -= free;
		(void)md5_body(ctx, ctx->buffer, 64);
	}

	if (size >= 64) {
		data = md5_body(ctx, data, size & ~(size_t)0x3f);
		size &= 0x3f;
	}

	memcpy(ctx->buffer, data, size);
}

void md5_final(u_char result[16], md5_t *ctx) {
	size_t used, free;

	used = (size_t)(ctx->bytes & 0x3f);

	ctx->buffer[used++] = 0x80;

	free = 64 - used;

	if (free < 8) {
		memzero(&ctx->buffer[used], free);
		(void)md5_body(ctx, ctx->buffer, 64);
		used = 0;
		free = 64;
	}

	memzero(&ctx->buffer[used], free - 8);

	ctx->bytes <<= 3;
	ctx->buffer[56] = (u_char)ctx->bytes;
	ctx->buffer[57] = (u_char)(ctx->bytes >> 8);
	ctx->buffer[58] = (u_char)(ctx->bytes >> 16);
	ctx->buffer[59] = (u_char)(ctx->bytes >> 24);
	ctx->buffer[60] = (u_char)(ctx->bytes >> 32);
	ctx->buffer[61] = (u_char)(ctx->bytes >> 40);
	ctx->buffer[62] = (u_char)(ctx->bytes >> 48);
	ctx->buffer[63] = (u_char)(ctx->bytes >> 56);

	(void)md5_body(ctx, ctx->buffer, 64);

	result[0] = (u_char)ctx->A;
	result[1] = (u_char)(ctx->A >> 8);
	result[2] = (u_char)(ctx->A >> 16);
	result[3] = (u_char)(ctx->A >> 24);
	result[4] = (u_char)ctx->B;
	result[5] = (u_char)(ctx->B >> 8);
	result[6] = (u_char)(ctx->B >> 16);
	result[7] = (u_char)(ctx->B >> 24);
	result[8] = (u_char)ctx->C;
	result[9] = (u_char)(ctx->C >> 8);
	result[10] = (u_char)(ctx->C >> 16);
	result[11] = (u_char)(ctx->C >> 24);
	result[12] = (u_char)ctx->D;
	result[13] = (u_char)(ctx->D >> 8);
	result[14] = (u_char)(ctx->D >> 16);
	result[15] = (u_char)(ctx->D >> 24);

	memzero(ctx, sizeof(*ctx));
}

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define STEP(f, A, B, C, D, x, t, s)                       \
	(A) += f((B), (C), (D)) + (x) + (t);                     \
	(A) = (((A) << (s)) | (((A)&0xffffffff) >> (32 - (s)))); \
	(A) += (B)


#define SET(n)                          \
	(block[n] =                           \
			 (uint32_t)p[n * 4] |             \
			 ((uint32_t)p[n * 4 + 1] << 8) |  \
			 ((uint32_t)p[n * 4 + 2] << 16) | \
			 ((uint32_t)p[n * 4 + 3] << 24))

#define GET(n) block[n]

static const u_char *md5_body(md5_t *ctx, const u_char *data, size_t size) {
	uint32_t A, B, C, D;
	uint32_t saved_a, saved_b, saved_c, saved_d;
	const u_char *p;
	uint32_t block[16];

	p = data;

	A = ctx->A;
	B = ctx->B;
	C = ctx->C;
	D = ctx->D;

	do {
		saved_a = A;
		saved_b = B;
		saved_c = C;
		saved_d = D;

		/* Round 1 */

		STEP(F, A, B, C, D, SET(0), 0xd76aa478, 7);
		STEP(F, D, A, B, C, SET(1), 0xe8c7b756, 12);
		STEP(F, C, D, A, B, SET(2), 0x242070db, 17);
		STEP(F, B, C, D, A, SET(3), 0xc1bdceee, 22);
		STEP(F, A, B, C, D, SET(4), 0xf57c0faf, 7);
		STEP(F, D, A, B, C, SET(5), 0x4787c62a, 12);
		STEP(F, C, D, A, B, SET(6), 0xa8304613, 17);
		STEP(F, B, C, D, A, SET(7), 0xfd469501, 22);
		STEP(F, A, B, C, D, SET(8), 0x698098d8, 7);
		STEP(F, D, A, B, C, SET(9), 0x8b44f7af, 12);
		STEP(F, C, D, A, B, SET(10), 0xffff5bb1, 17);
		STEP(F, B, C, D, A, SET(11), 0x895cd7be, 22);
		STEP(F, A, B, C, D, SET(12), 0x6b901122, 7);
		STEP(F, D, A, B, C, SET(13), 0xfd987193, 12);
		STEP(F, C, D, A, B, SET(14), 0xa679438e, 17);
		STEP(F, B, C, D, A, SET(15), 0x49b40821, 22);

		/* Round 2 */

		STEP(G, A, B, C, D, GET(1), 0xf61e2562, 5);
		STEP(G, D, A, B, C, GET(6), 0xc040b340, 9);
		STEP(G, C, D, A, B, GET(11), 0x265e5a51, 14);
		STEP(G, B, C, D, A, GET(0), 0xe9b6c7aa, 20);
		STEP(G, A, B, C, D, GET(5), 0xd62f105d, 5);
		STEP(G, D, A, B, C, GET(10), 0x02441453, 9);
		STEP(G, C, D, A, B, GET(15), 0xd8a1e681, 14);
		STEP(G, B, C, D, A, GET(4), 0xe7d3fbc8, 20);
		STEP(G, A, B, C, D, GET(9), 0x21e1cde6, 5);
		STEP(G, D, A, B, C, GET(14), 0xc33707d6, 9);
		STEP(G, C, D, A, B, GET(3), 0xf4d50d87, 14);
		STEP(G, B, C, D, A, GET(8), 0x455a14ed, 20);
		STEP(G, A, B, C, D, GET(13), 0xa9e3e905, 5);
		STEP(G, D, A, B, C, GET(2), 0xfcefa3f8, 9);
		STEP(G, C, D, A, B, GET(7), 0x676f02d9, 14);
		STEP(G, B, C, D, A, GET(12), 0x8d2a4c8a, 20);

		/* Round 3 */

		STEP(H, A, B, C, D, GET(5), 0xfffa3942, 4);
		STEP(H, D, A, B, C, GET(8), 0x8771f681, 11);
		STEP(H, C, D, A, B, GET(11), 0x6d9d6122, 16);
		STEP(H, B, C, D, A, GET(14), 0xfde5380c, 23);
		STEP(H, A, B, C, D, GET(1), 0xa4beea44, 4);
		STEP(H, D, A, B, C, GET(4), 0x4bdecfa9, 11);
		STEP(H, C, D, A, B, GET(7), 0xf6bb4b60, 16);
		STEP(H, B, C, D, A, GET(10), 0xbebfbc70, 23);
		STEP(H, A, B, C, D, GET(13), 0x289b7ec6, 4);
		STEP(H, D, A, B, C, GET(0), 0xeaa127fa, 11);
		STEP(H, C, D, A, B, GET(3), 0xd4ef3085, 16);
		STEP(H, B, C, D, A, GET(6), 0x04881d05, 23);
		STEP(H, A, B, C, D, GET(9), 0xd9d4d039, 4);
		STEP(H, D, A, B, C, GET(12), 0xe6db99e5, 11);
		STEP(H, C, D, A, B, GET(15), 0x1fa27cf8, 16);
		STEP(H, B, C, D, A, GET(2), 0xc4ac5665, 23);

		/* Round 4 */

		STEP(I, A, B, C, D, GET(0), 0xf4292244, 6);
		STEP(I, D, A, B, C, GET(7), 0x432aff97, 10);
		STEP(I, C, D, A, B, GET(14), 0xab9423a7, 15);
		STEP(I, B, C, D, A, GET(5), 0xfc93a039, 21);
		STEP(I, A, B, C, D, GET(12), 0x655b59c3, 6);
		STEP(I, D, A, B, C, GET(3), 0x8f0ccc92, 10);
		STEP(I, C, D, A, B, GET(10), 0xffeff47d, 15);
		STEP(I, B, C, D, A, GET(1), 0x85845dd1, 21);
		STEP(I, A, B, C, D, GET(8), 0x6fa87e4f, 6);
		STEP(I, D, A, B, C, GET(15), 0xfe2ce6e0, 10);
		STEP(I, C, D, A, B, GET(6), 0xa3014314, 15);
		STEP(I, B, C, D, A, GET(13), 0x4e0811a1, 21);
		STEP(I, A, B, C, D, GET(4), 0xf7537e82, 6);
		STEP(I, D, A, B, C, GET(11), 0xbd3af235, 10);
		STEP(I, C, D, A, B, GET(2), 0x2ad7d2bb, 15);
		STEP(I, B, C, D, A, GET(9), 0xeb86d391, 21);

		A += saved_a;
		B += saved_b;
		C += saved_c;
		D += saved_d;

		p += 64;

	} while (size -= 64);

	ctx->A = A;
	ctx->B = B;
	ctx->C = C;
	ctx->D = D;

	return p;
}

void md5_hash(const char *message, u_char result[16]) {
	md5_t md5;
	md5_init(&md5);
	md5_update(&md5, message, strlen(message));
	md5_final(result, &md5);
}

u_long** generateMatrix() {
  u_long **matrix = (u_long**)calloc((N - K), sizeof(u_long*));
  for (int i = 0; i < (N - K); i++)
    matrix[i] = (u_long*)calloc(K, sizeof(u_long));

  for (int i = 0; i < (N - K); i++) {
    for (int j = 0; j < K; j++) {
      matrix[i][j] = gfsr5() % 2; // сразу по модулю два
    }
  }

  return matrix;
}

u_long* generateVector(int seed) {
  init_gfsr5(seed);
  u_long* vector = (u_long*)calloc(N, sizeof(u_long));

  for (int i = 0; i < N; i++)
    vector[i] = gfsr5() % 2;

  return vector;
}


u_long* generateSet() {
  u_long *set = (u_long*)malloc(omega * sizeof(u_long));

  for (int i = 0; i < omega; i++) {
    set[i] = rand() % N;

    for (int j = 0; j < i; j++) {
      if (set[i] == set[j]) {
        i--;
        break;
      }
    }
  }

  return set;
}

u_long* buildVector(u_long* set) {
  u_long*vector = (u_long*)calloc(N, sizeof(u_long));
  for (int i = 0; i < omega; i++)
    vector[set[i]] = 1;

  return vector;
}

u_long* splitVector(u_long* vector, int size) {
  u_long* result = (u_long*)malloc((size) * sizeof(u_long));
  for (int i = 0; i < size; i++)
    result[i] = vector[i];

  return result;
}

u_long** transposeMatrix(u_long** matrix) {
  u_long **transpose = (u_long**)malloc(K * sizeof(u_long*));
  for (int i = 0; i < K; i++) {
    transpose[i] = (u_long*)malloc((N - K) * sizeof(u_long));
    for (int j = 0; j < N - K; j++) {
      transpose[i][j] = matrix[j][i];
    }
  }

  return transpose;
}

u_long* multiplyMatrixVector(u_long** matrix, u_long* vector, int rows, int cols) {
  u_long* result = (u_long*)calloc(rows, sizeof(u_long));
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result[i] += matrix[j][i] * vector[j];
    }
    result[i] = result[i] % 2;
  }

  return result;
}

u_long* multiplyMatrixVector2(u_long** matrix, u_long* vector, int rows, int cols) {
  u_long* result = (u_long*)calloc(rows, sizeof(u_long));
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result[i] += matrix[i][j] * vector[j];
    }
    result[i] = result[i] % 2;
  }

  return result;
}

u_long* generatePermutation() {
  u_long* permutation = (u_long*)malloc(N * sizeof(u_long));

  for (int i = 0; i < N; i++)
    permutation[i] = i + 1;

  return permutation;
}

u_long* permutationToBinary(u_long *array, int size, int *newSize) {
  int sss = 0;
  for (int i = 0; i < size; i++)
    sss += floor(log2(array[i])) + 1;

  *newSize = sss;
  u_long *binaryArray = (u_long*)malloc(sss * sizeof(u_long));

  int binaryIndex = 0;
  for (int i = 0; i < size; i++) {
    int num = array[i];
    u_long binary[32];
    int index = 0;

    while (num > 0) {
      binary[index] = num % 2;
      num /= 2;
      index++;
    }

    for (int j = index - 1; j >= 0; j--) {
      binaryArray[binaryIndex] = binary[j];
      binaryIndex++;
    }
  }

  return binaryArray;
}

u_long* concatenateVectors(const u_long* vector1, int length1, const u_long* vector2, int length2) {
  int totalLength = length1 + length2;
  u_long* concatenatedVector = (u_long*)calloc(sizeof(u_long), totalLength);

  for (int i = 0; i < length1; i++)
    concatenatedVector[i] = vector1[i];

  for (int i = 0; i < length2; i++)
    concatenatedVector[length1 + i] = vector2[i];

  return concatenatedVector;
}

char* convertToBinaryString(const u_long* array, int length) {
  char* binaryString = (char*)calloc(sizeof(char), length + 1);

  for (int i = 0; i < length; i++) {
    binaryString[i] = array[i] ? '1' : '0';
  }

  binaryString[length] = '\0';

  return binaryString;
}

u_long* permuteVector(const u_long* u, const u_long* sigma, int length) {
  u_long* permutedVector = (u_long*)calloc(sizeof(u_long), length);

  for (int i = 0; i < length; i++)
    permutedVector[i] = u[sigma[i] - 1];

  return permutedVector;
}

u_char* decimalToHex(const u_char* decimal) {
  int decimalLength = strlen((const char*)decimal);
  int hexLength = decimalLength * 2;
  u_char* hex = (u_char*)malloc((hexLength + 1) * sizeof(u_char));

  for (int i = 0; i < decimalLength; i++) {
    sprintf((char*)(hex + i * 2), "%02x", decimal[i]);
  }

  return hex;
}

u_char* concatenateMessageWithC(const u_char* M, const u_char** c) {
  u_char* hexM = decimalToHex(M);
  int totalLength = strlen((const char*)hexM);
  totalLength += 48 * (d - 1);

  u_char* concatenated = (u_char*)calloc(sizeof(u_char), 2 * totalLength + 1);
  sprintf((char*)concatenated, "%s", hexM);

  for (int i = 0; i < d - 1; i++)
    memcpy(concatenated + strlen((const char*)hexM) + 48 * i, c[i], 48);

  free(hexM);

  return concatenated;
}

void decimalToTernary(mpz_t decimal, int *ternary, int size) {
  for (int i = 0; i < size; i++) {
    ternary[i] = mpz_fdiv_ui(decimal, 3);
    mpz_fdiv_q_ui(decimal, decimal, 3);
  }
}

int* multiplyByPowerOfThree(int *ternary, int size, int power) {
  int newSize = size + power;
  int *newTernary = malloc(newSize * sizeof(int));
  memcpy(newTernary, ternary, size * sizeof(int));
  memset(newTernary + size, 0, power * sizeof(int));
  return newTernary;
}

void multiplyAndShift(mpz_t number, int pow, int len) {
  mpz_t power;
  mpz_init(power);
  mpz_set_ui(power, 3);
  mpz_pow_ui(power, power, pow);

  mpz_mul(number, number, power);

  mpz_tdiv_q_2exp(number, number, len);

  mpz_clear(power);
}

void freeMatrix(u_long** matrix) {
  for (int i = 0; i < N - K; i++)
    free(matrix[i]);

  free(matrix);
}

int main() {
  srand(time(NULL));

  u_long **H = NULL;
  u_long **H_transpose = NULL;
  u_long *set = NULL;
  u_long *s = NULL;
  u_long *s_l = NULL;
  u_long *s_r = NULL;
  u_long *y = NULL;
  u_long *sigma = NULL;
  u_long *sigma_binary = NULL;
  u_long *u_i = NULL;
  u_long *u_l = NULL;
  u_long *u_r = NULL;
  u_long *temp = NULL;
  u_long *temp2 = NULL;

  const char* message = "lvdnv";

  int sigma_binary_size = 0;

  init_gfsr5(gfsr5_seed);
  H = generateMatrix();
  H_transpose = transposeMatrix(H);

  set = generateSet();
  s = buildVector(set);
  free(set);

  s_l = splitVector(s, N / 2);
  s_r = splitVector(s + N / 2, N / 2);

  y = multiplyMatrixVector(H_transpose, s_l, K, N - K);

  for (int i = 0; i < N - K; i++) {
    y[i] ^= s_r[i];
  }

  int i = 0;
  u_char **c = (u_char**)calloc(sizeof(u_char*), d);
  u_long **u = (u_long**)calloc(sizeof(u_long*), d);

  // first big while
  while (i < d - 1) {
    u_i = generateVector(i);
    u[i] = (u_long*)calloc(sizeof(u_long), N);
    memcpy(u[i], u_i, N);

    sigma = generatePermutation();
    sigma_binary = permutationToBinary(sigma, N, &sigma_binary_size);

    u_l = splitVector(u_i, N / 2);
    u_r = splitVector(u_i + N / 2, N / 2);

    temp = multiplyMatrixVector2(H, u_l, K, N - K);

    for (int j = 0; j < K; j++)
      temp[j] ^= u_r[j];

    temp2 = concatenateVectors(sigma_binary, sigma_binary_size, temp, K);
    int temp2_len = sigma_binary_size + K;

    u_char c1[16] = {0};
    u_char c2[16] = {0};
    u_char c3[16] = {0};
    u_char c_i[48] = {0};

    char *binary_string = NULL;

    binary_string = convertToBinaryString(temp2, temp2_len);
    md5_hash(binary_string, c1);
    free(binary_string);

    u_long *permuted_vector = permuteVector(u_i, sigma, N);

    binary_string = convertToBinaryString(permuted_vector, N);
    md5_hash(binary_string, c2);
    free(binary_string);

    u_long *temp_vec = calloc(sizeof(u_long), N);
    for (int i = 0; i < N; i++)
      temp_vec[i] = (u_i[i] + s[i]) % 2;

    binary_string = convertToBinaryString(temp_vec, N);
    md5_hash(binary_string, c3);
    free(binary_string);

    memcpy(c_i, c1, 16);
    memcpy(c_i + 16, c2, 16);
    memcpy(c_i + 32, c3, 16);

    c[i] = (u_char*)calloc(sizeof(u_char), 48);
    memcpy(c[i], c_i, 48);

    free(temp);
    free(temp2);
    free(sigma);
    free(sigma_binary);
    free(temp_vec);
    free(permuted_vector);
    free(u_i);
    free(u_l);
    free(u_r);
    i++;
  }

  u_char *concatenated = concatenateMessageWithC((const u_char*)message, (const u_char**)c);

  u_char hash_of_concatenated[16] = {0};
  md5_hash((const char*)concatenated, hash_of_concatenated);

  mpz_t big_number;
  mpz_init(big_number);
  mpz_import(big_number, 16, 1, sizeof(u_char), 0, 0, hash_of_concatenated);

  int ternary_size = mpz_sizeinbase(big_number, 3);

  multiplyAndShift(big_number, d, 5);
  int *ternary_number = malloc(ternary_size * sizeof(int));
  decimalToTernary(big_number, ternary_number, ternary_size);

  u_long **r = (u_long**)calloc(sizeof(u_long*), ternary_size);

  for (int i = 0; i < ternary_size; i++) {
    switch (ternary_number[i]) {
    case 0:
      sigma = generatePermutation();
      sigma_binary = permutationToBinary(sigma, N, &sigma_binary_size);
      r[i] = concatenateVectors(sigma_binary, sigma_binary_size, u[i], N);

      free(sigma);
      free(sigma_binary);
      break;

    case 1:
      sigma = generatePermutation();
      sigma_binary = permutationToBinary(sigma, N, &sigma_binary_size);
      temp = (u_long*)calloc(sizeof(u_long), N);
      for (int j = 0; j < N; j++)
        temp[j] = u[i][j] + s[j];

      r[i] = concatenateVectors(sigma_binary, sigma_binary_size, temp, N);
      free(temp);
      free(sigma);
      free(sigma_binary);
      break;

    case 2:
      sigma = generatePermutation();
      temp = permuteVector(u[i], sigma, N);
      temp2 = permuteVector(s, sigma, N);

      r[i] = concatenateVectors(temp, N, temp2, N);
      free(temp);
      free(temp2);
      free(sigma);
      break;

    default:
      break;
    }
  }

  u_char *result = (u_char*)calloc(sizeof(u_char), d * 48 + ternary_size * N);

  for (int i = 0; i < d - 1; i++)
    memcpy(result + i * 48, c[i], 48);

  for (int i = 0; i < ternary_size; i++)
    memcpy(result + (d - 1) * 48 + i * N, (u_char*)r[i], N);

  // printf("%s", result); // В БИНАРНОМ ВИДЕ, лучше принтить хексами.

  free(result);
  free(ternary_number);
  mpz_clear(big_number);

  if (H)
    freeMatrix(H);

  if (H_transpose)
    freeMatrix(H_transpose);

  free(s);
  free(s_l);
  free(s_r);
  free(y);
  free(concatenated);

  for (int i = 0; i < ternary_size; i++)
    free(r[i]);

  free(r);

  for (int i = 0; i < d; i++)
    free(c[i]);

  free(c);

  for (int i = 0; i < d; i++)
    free(u[i]);

  free(u);

  return 0;
}