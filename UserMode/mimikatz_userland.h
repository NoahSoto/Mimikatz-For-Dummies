#pragma once
#pragma once
#ifndef MIMIKATZ_HEADERS_H
#define MIMIKATZ_HEADERS_H

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <bcrypt.h>



// forward declarations
typedef struct _KIWI_MSV1_0_LIST_63 KIWI_MSV1_0_LIST_63;
typedef struct _KIWI_MSV1_0_CREDENTIALS KIWI_MSV1_0_CREDENTIALS;
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS KIWI_MSV1_0_PRIMARY_CREDENTIALS;
typedef struct _LSA_UNICODE_STRING;


typedef struct _LSA_UNICODE_STRING {
    USHORT Length;          // in bytes, not characters
    USHORT MaximumLength;   // in bytes
    PWSTR  Buffer;          // pointer to wide string
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING;


typedef struct _KIWI_MSV1_0_LIST_63 {
    struct _KIWI_MSV1_0_LIST_63* Flink;
    struct _KIWI_MSV1_0_LIST_63* Blink;
    PVOID unk0;
    ULONG unk1;
    PVOID unk2;
    ULONG unk3;
    ULONG unk4;
    ULONG unk5;
    HANDLE hSemaphore6;
    PVOID unk7;
    HANDLE hSemaphore8;
    PVOID unk9;
    PVOID unk10;
    ULONG unk11;
    ULONG unk12;
    PVOID unk13;
    LUID LocallyUniqueIdentifier;
    LUID SecondaryLocallyUniqueIdentifier;
    UCHAR waza[12];
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    PVOID unk14;
    PVOID unk15;
    LSA_UNICODE_STRING Type;
    PSID pSid;
    ULONG LogonType;
    PVOID unk18;
    ULONG Session;
    LARGE_INTEGER LogonTime;
    LSA_UNICODE_STRING LogonServer;
    KIWI_MSV1_0_CREDENTIALS* Credentials;
    PVOID unk19;
    PVOID unk20;
    PVOID unk21;
    ULONG unk22;
    ULONG unk23;
    ULONG unk24;
    ULONG unk25;
    ULONG unk26;
    PVOID unk27;
    PVOID unk28;
    PVOID unk29;
    PVOID CredentialManager;
} KIWI_MSV1_0_LIST_63, * PKIWI_MSV1_0_LIST_63;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
    struct _KIWI_MSV1_0_CREDENTIALS* next;
    ULONG AuthenticationPackageId;
    KIWI_MSV1_0_PRIMARY_CREDENTIALS* PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, * PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
    struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS* next;
    ANSI_STRING Primary;            // defined in ntifs.h
    LSA_UNICODE_STRING Credentials; // defined in ntifs.h
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, * PKIWI_MSV1_0_PRIMARY_CREDENTIALS;


//keys extractinon

typedef struct _KIWI_HARD_KEY {
    ULONG cbSecret;
    BYTE data[60]; // etc...
} KIWI_HARD_KEY, * PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
    ULONG size;
    ULONG tag;	// 'MSSK'
    ULONG type;
    ULONG unk0;
    ULONG unk1;
    ULONG unk2;
    ULONG unk3;
    ULONG unk4;
    PVOID unk5;	// before, align in x64
    ULONG unk6;
    ULONG unk7;
    ULONG unk8;
    ULONG unk9;
    KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, * PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
    ULONG size;
    ULONG tag;	// 'UUUR'
    PVOID hAlgorithm;
    PKIWI_BCRYPT_KEY81 key;
    PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, * PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _SECURITY_BLOB {
    BYTE LMHash[16];           // 0x00
    BYTE NTHash[16];           // 0x10
    BYTE IV[16];               // 0x20, optional AES IV
    BYTE reserved[0x190];      // padding / metadata up to 0x1B0
    WCHAR Username[64];        // UTF-16, starts around 0x1B0
    WCHAR Domain[64];          // UTF-16, optional
} SECURITY_BLOB, * PSECURITY_BLOB;

#endif // MIMIKATZ_HEADERS_H
