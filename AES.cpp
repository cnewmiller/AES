//
//  AES.cpp
//  AES
//
//  Created by Clayton Newmiller on 5/2/16.
//  Copyright © 2016 Clayton Newmiller. All rights reserved.
//

#include "AES.hpp"
#include <iostream>
#define byte unsigned char

const unsigned char AES::s[256];
const unsigned char AES::rcon[256];
const unsigned char AES::inv_s[256];
const unsigned char AES::gmult_2[256];
const unsigned char AES::gmult_3[256];
const unsigned char AES::gmult_9[256];
const unsigned char AES::gmult_11[256];
const unsigned char AES::gmult_13[256];
const unsigned char AES::gmult_14[256];


AES::AES(){

}
AES::~AES(){
    
}


void AES::subBytes(){
    //S-box transformation
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            state[i][j]=s[state[i][j]];
        }
    }
};
const void AES::subBytes(unsigned char a[4][4]){
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            a[i][j]=AES::s[a[i][j]];
        }
    }
}
void AES::rotKeyByte(int row){//rotate up by one in grid orientation
    unsigned char temp=roundkeys[row][0];
    for (int i=0;i<3;i++){
        roundkeys[row][i]=roundkeys[row][(i+1)];
    }
    roundkeys[row][3]=temp;
};
void AES::rotKeyByte(unsigned char a[44][4], int row){//rotate up by one in grid orientation
    unsigned char temp=a[row][0];
    for (int i=0;i<3;i++){
        a[row][i]=a[row][(i+1)];
    }
    a[row][3]=temp;
};


void AES::subKeyByte(int row){
    for (int j=0;j<4;j++){
        roundkeys[row][j]=s[roundkeys[row][j]];
    }
}
void AES::subKeyByte(unsigned char bigkey[44][4], int row){
    for (int j=0;j<4;j++){
        bigkey[row][j]=s[bigkey[row][j]];
    }
}

void AES::shiftRows(){
    for (int x=1;x<4;x++){
        for (int i=x;i<4;i++){
            byte temp=state[0][i];
            for (int j=0;j<4;j++){
                state[j][i]=state[(j+1)%4][i];
            }
            state[3][i]=temp;
        }
    }
}
void AES::shiftRows(unsigned char a[4][4]){
    for (int x=1;x<4;x++){
        for (int i=x;i<4;i++){
            byte temp=a[0][i];
            for (int j=0;j<4;j++){
                a[j][i]=a[(j+1)%4][i];
            }
            a[3][i]=temp;
        }
    }
}

void AES::mixColumns(){
    unsigned char temp[4][4];
    for (int i = 0; i<4;i++){//pattern for individual assignments taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns
        temp[i][0] = (gmult_2[state[i][0]] ^ gmult_3[state[i][1]] ^ (state[i][2]) ^ (state[i][3] ));
        temp[i][1] = ((state[i][0]) ^ gmult_2[state[i][1]] ^ gmult_3[state[i][2]] ^ (state[i][3] ));
        temp[i][2] = ((state[i][0]) ^ (state[i][1]) ^ gmult_2[state[i][2]] ^ gmult_3[state[i][3]] );
        temp[i][3] = (gmult_3[state[i][0]]  ^ (state[i][1]) ^ (state[i][2]) ^ gmult_2[state[i][3]]);
    }
    for (int x=0;x<4;x++){
        for (int i=0;i<4;i++){
            state[x][i]=temp[x][i];
        }
    }
}
void AES::mixColumns(unsigned char a[4][4]){
    unsigned char temp[4][4];
    for (int i = 0; i<4;i++){//pattern for individual assignments taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns
        temp[i][0] = (gmult_2[a[i][0]] ^ gmult_3[a[i][1]] ^ (a[i][2]) ^ (a[i][3] ));
        temp[i][1] = ((a[i][0]) ^ gmult_2[a[i][1]] ^ gmult_3[a[i][2]] ^ (a[i][3] ));
        temp[i][2] = ((a[i][0]) ^ (a[i][1]) ^ gmult_2[a[i][2]] ^ gmult_3[a[i][3]] );
        temp[i][3] = (gmult_3[a[i][0]]  ^ (a[i][1]) ^ (a[i][2]) ^ gmult_2[a[i][3]]);
    }
    for (int x=0;x<4;x++){
        for (int i=0;i<4;i++){
            a[x][i]=temp[x][i];
        }
    }
    
}

void AES::addRoundKey(int roundnum){
    int roundindex =(roundnum*4);
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
//            printf("before- state: %x key: %x\n",state[i][j], roundkeys[roundindex+i][j]);
            state[i][j]=((state[i][j]) ^ roundkeys[roundindex+i][j]);
//            printf("after- state: %x key: %x\n",state[i][j], roundkeys[roundindex+i][j]);
        }
    }
}
void AES::addRoundKey(unsigned char a[4][4], unsigned char bigkey[44][4], int roundnum){
    int roundindex =(roundnum*4);
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            a[i][j]=((a[i][j]) ^ bigkey[roundindex+i][j]);
        }
    }
}




void AES::printState(unsigned char a[4][4]){
    printf("\n------\n");
    for (int l=0;l<4;l++){
        for (int k=0;k<4;k++){
            if (a[k][l]<0x10){
                printf("{0%x}\t", a[k][l]);
            }
            else
                printf("{%x}\t", a[k][l]);
        }
        printf("\n");
    }
    printf("------\n");
}
void AES::keyExpansion(){
    
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            roundkeys[i][j]=key[i][j]; //copy key into first part of expandedkey
        }
    }
    for (int i=4;i<44;i++){
        for (int j=0;j<4;j++){
            roundkeys[i][j]=roundkeys[i-1][j];
        }
        
        if (i % 4 == 0){
            rotKeyByte(i);
            subKeyByte(i);
            roundkeys[i][0] = (roundkeys[i][0] ^ rcon[i/4]);
        }
        
        for (int j=0;j<4;j++){
            roundkeys[i][j]=(roundkeys[i-4][j] ^ roundkeys[i][j]);
        }
    }
}
void AES::keyExpansion(unsigned char inkey[4][4], unsigned char outkey[44][4]){
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            outkey[i][j]=inkey[i][j]; //copy key into first part of expandedkey
        }
    }
    for (int i=4;i<44;i++){
        for (int j=0;j<4;j++){
            outkey[i][j]=outkey[i-1][j];
        }
        
        if (i % 4 == 0){ // this is the g function
            rotKeyByte(outkey, i);
            subKeyByte(outkey, i);
            outkey[i][0] = (outkey[i][0] ^ rcon[i/4]);
        }
        
        for (int j=0;j<4;j++){
            outkey[i][j]=(outkey[i-4][j] ^ outkey[i][j]);
        }
    }
}



void AES::setKey(unsigned char newkey[4][4]){
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            key[i][j]=newkey[i][j];
        }
    }
}
void AES::setData(unsigned char newdata[4][4]){
    for (int i=0;i<4;i++){
        for (int j=0;j<4;j++){
            state[i][j]=newdata[i][j];
        }
    }
}



void AES::encrypt(){
    keyExpansion();
    addRoundKey(0);
    for (int i = 1; i<10;i++){
        subBytes();
        shiftRows();
        mixColumns();
        addRoundKey(i);
    }
    subBytes();
    shiftRows();
    addRoundKey(10);
}
void AES::encrypt(unsigned char a[4][4], unsigned char k[4][4]){ //data, key
    unsigned char K[44][4];
    keyExpansion(k, K);
    addRoundKey(a, K, 0);
    for (int i = 1; i<10;i++){
        subBytes(a);
        shiftRows(a);
        mixColumns(a);
        addRoundKey(a, K, i);
//        printState(a);
    }
    subBytes(a);
    shiftRows(a);
    addRoundKey(a, K, 10);
}
void AES::singleRound(unsigned char a[4][4], unsigned char k[4][4]){
    unsigned char K[44][4];
    keyExpansion(k, K);
    addRoundKey(a, K, 0);
    subBytes(a);
    shiftRows(a);
    mixColumns(a);
}


unsigned char AES::convertHexToNum(unsigned char c) { //copied and modified from ConvertStringToBinary.java, given by Prof. Rogers
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else {
        return 0;
    }
}
unsigned char AES::convertNumToHex(unsigned char c) { //copied and modified from ConvertStringToBinary.java, given by Prof. Rogers
    if (c >= 0 && c <= 9) {
        return c + '0';
    }
    else if (c >= 0xa && c <= 0xf) {
        return c + 'a' - 10;
    }
    else {
        return 0;
    }
}

void AES::fill_hexes(unsigned char out[4][4], unsigned char in[32]){
//    for (int i=0;i<32;i++)
//        cout<<in[i];
//    cout<<endl;
    
    for (int i = 0; i<4 ; i++){
        for (int j = 0; j<4 ; j++){
            out[i][j] = (convertHexToNum(in[i*8+j*2])<<4)^(convertHexToNum(in[i*8+j*2+1]));
        }
    }
    
}

void AES::toHex(unsigned char in[4][4], unsigned char out[33]){
    
    for (int i = 0; i<4 ; i++){
        for (int j = 0; j<4 ; j++){
//            printf("in loop, we have %c and %c\n",convertNumToHex((in[i][j] >>4) & 0x0f),convertNumToHex(in[i][j] & 0x0f));
            out[i*8+j*2] = convertNumToHex((in[i][j] >>4) & 0x0f);
            out[i*8+j*2+1] = convertNumToHex(in[i][j] & 0x0f);
        }
    }
    out[32]='\0';
}




