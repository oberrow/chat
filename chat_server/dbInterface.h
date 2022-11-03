#pragma once
#include <db.h>
#include <stdint.h>
#include "boolean_type.h"
#include <sal.h>

/*
* Opens the database
	filename  - the database to open.
	flags     - the open flags.
	dbType    - the database type.
	pointerDB - a pointer to the database object.
	err		  - a pointer to an integer that holds the last error.
*/
bool OpenDB(
	_In_  char* filename, 
	_In_  uint32_t flags, 
	_In_  DBTYPE dbType, 
	_Out_ DB** pointerDB, 
	_Out_ int* err);
/*
* Writes to the database
	key   - the new key.
	data  - the data to be saved.
	db    - the database to save the data to.
	flags - the writing flags.
	err	  - a pointer to an integer that holds the last error.
*/
bool WriteDB(
	_In_  char* key,
	_In_  char* data,
	_In_  size_t size,
	_In_  DB* db,
	_In_  int flags,
	_Out_ int* err);
/*
* Reads data from the database
	key   - the key to get the data from.
	data  - the string to save the data to.
	db    - the database to read the data from.
	err	  - a pointer to an integer that holds the last error.
*/
bool ReadDB(
	_In_ char* key, 
	_Out_writes_bytes_(*dataLen) char* data, 
	_Inout_ int* dataLen,
	_In_ DB* db, 
	_Out_ int* err);
/*
* Removes an item from the database
* Warning! Will remove all records with {key} as the key
	db  - the database.
	key - the key to remove.
	err - a pointer to an integer that holds the last error
*/
bool DeleteKey
(
	_In_  DB* db,
	_In_  char* key,
	_Out_ int* err
);
/*
* Checks if {key} exists in the database
	db     - the database.
	key    - the key to try and find.
	exists - the output
	err	   - a pointer to an integer that holds the last error.
*/
bool ContainsKey
(
	_In_  DB* db,
	_In_  char* key,
	_In_  int maxLen,
	_Out_ bool* exists,
	_Out_ int* err
);
/*
* Closes the database
	db - the database
*/
bool CloseDB(_In_ DB* db);