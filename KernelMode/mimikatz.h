#pragma once
#ifndef MIMIKATZ_HEADERS_H
#define MIMIKATZ_HEADERS_H

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <stdarg.h>

// forward declarations
typedef struct _KIWI_MSV1_0_LIST_63 KIWI_MSV1_0_LIST_63;
typedef struct _KIWI_MSV1_0_CREDENTIALS KIWI_MSV1_0_CREDENTIALS;
typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS KIWI_MSV1_0_PRIMARY_CREDENTIALS;

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



//KEYS EXTRACTION




#endif // MIMIKATZ_HEADERS_H
