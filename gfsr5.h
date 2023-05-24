#include<stdio.h>
#include<string.h>
#include<stdint.h>
#include<sys/types.h>
#include<inttypes.h>
#include<stdlib.h>
#include<time.h>
#include<math.h>
#include<stddef.h>

typedef unsigned long u_long;

#define gfsr5_seed 0xc90fdaa2

void init_gfsr5(u_long s);
u_long gfsr5();
u_long *generateSet();
u_long *buildVector(u_long *set);