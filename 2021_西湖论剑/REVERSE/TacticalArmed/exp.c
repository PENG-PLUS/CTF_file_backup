#include<stdio.h>
#include<stdint.h>
#define DELTA 0x81A5692E

void encrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=DELTA;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<33; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t v[2], const uint32_t k[4],uint32_t idx) {
    uint32_t v0=v[0], v1=v[1], sum=DELTA*33*idx, i;  /* set up; sum is 32*delta */
    uint32_t delta=DELTA;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<33; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}


int main(int argc, char const *argv[])
{
    unsigned int key1[4]={0x7ce45630,0x58334908,0x66398867,0xc35195B1};//key1
    unsigned int v0[2] = {0x30303030,0x30303030};
    encrypt(v0,key1);
    printf("enc v1:%x %x\n",v0[0],v0[1]);
    decrypt(v0,key1,1);
    printf("dec v1:%x %x\n",v0[0],v0[1]);
    unsigned int v1[2] = {0x422f1ded,0x1485e472};
    unsigned int v2[2] = {0x035578d5,0xbf6b80a2};
    unsigned int v3[2] = {0x97d77245,0x2dae75d1};
    unsigned int v4[2] = {0x665fa963,0x292e6d74};
    unsigned int v5[2] = {0x9795fcc1,0x0bb5c8e9};

    decrypt(v1,key1,1);
    decrypt(v2,key1,2);
    decrypt(v3,key1,3);
    decrypt(v4,key1,4);
    decrypt(v5,key1,5);


    printf("v1:%x %x\n",v1[0],v1[1]);
    printf("v2:%x %x\n",v2[0],v2[1]);
    printf("v3:%x %x\n",v3[0],v3[1]);
    printf("v4:%x %x\n",v4[0],v4[1]);
    printf("v5:%x %x\n",v5[0],v5[1]);
    return 0;
}