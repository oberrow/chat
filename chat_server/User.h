#pragma once
#include "boolean_type.h"

typedef enum { perm_mute, perm_normal, perm_all } perm;


typedef struct _cdat
{
    char* password; // only will be used during signin / signup
    struct _cdat(*init)(struct _cdat *clientData, char* pwd, bool hasJoinedTwice);
    struct _cdat(*init_all)(struct _cdat *clientData, perm p, char* pwd, bool hasJoinedTwice);
    bool hasJoinedTwice;
    perm permmissions;
} ClientData;


bool init_struct(ClientData* sinit, const char* exeName);