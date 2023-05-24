#include"gfsr5.h"

#define P 521
#define Q1 86
#define Q2 197
#define Q3 447
#define W 32

static u_long state[P];
static int state_i;

void init_gfsr5(u_long s) {
  int i = 0;
  int j = 0;
  int k = 0;
  static u_long x[P] = {0};

  s &= 0xffffffffUL;

  for (i = 0; i < P; i++) {
    x[i] = s >> 31;
    s = 1664525UL * s + 1UL;
    s &= 0xffffffffUL;
  }

  for (i = 0, k = 0; i < P; i++) {
    state[i] = 0UL;
    for (j = 0; j < W; j++) {
      state[i] <<=1 ;
      state[i] |= x[k];

      x[k] ^= x[ (k + Q1) % P] ^ x[ (k + Q2) % P] ^ x[ (k + Q3) % P];
      k++;

      if (k == P)
        k = 0;

    }
  }
  state_i = 0;
}

u_long gfsr5() {
  int i = 0;

  u_long *p0 = NULL;
  u_long *p1 = NULL;
  u_long *p2 = NULL;
  u_long *p3 = NULL;

  if (state_i >= P) {
    state_i = 0;
    p0 = state;
    p1 = state + Q1;
    p2 = state + Q2;
    p3 = state + Q3;

    int P_Q1 = P - Q1;
    int P_Q2 = P - Q2;
    int P_Q3 = P - Q3;

    for (i = 0; i < P_Q3; i++)
      *p0++ ^= *p1++ ^ *p2++ ^ *p3++;

    p3 = state;

    for ( ; i < P_Q2; i++)
      *p0++ ^= *p1++ ^ *p2++ ^ *p3++;

    p2 = state;

    for ( ; i < P_Q1; i++)
      *p0++ ^= *p1++ ^ *p2++ ^ *p3++;

    p1 = state;

    for ( ; i < P; i++)
      *p0++ ^= *p1++ ^ *p2++ ^ *p3++;
  }

  return state[state_i++];
}

long gfsr5_31() {
  return (long) (gfsr5() >> 1);
}
