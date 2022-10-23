#include "dbInterface.h"
#include <memory.h>
#include <windows.h>
#include <malloc.h>

bool OpenDB(
	_In_  char* filename,
	_In_  uint32_t flags,
	_In_  DBTYPE dbType,
	_Out_ DB** pointerDB,
	_Out_ int* err)
{
	DB* db;
	int ret = 0;
	ret = db_create(&db, NULL, 0);
	if (ret != 0)
	{
		*err = ret;
		return false;
	}
	ret = db->open
	(
		db,
		NULL,
		filename,
		NULL,
		dbType,
		flags,
		0
	);
	if (ret != 0)
	{
		*err = ret;
		return false;
	}
	*pointerDB = db;
	return true;
}
bool WriteDB(
	_In_  char* key,
	_In_  char* data,
	_In_  DB* db,
	_In_  int flags,
	_Out_ int* err)
{
	DBT dbKey, dbData;
	memset(&dbKey , 0, sizeof(DBT));
	memset(&dbData, 0, sizeof(DBT));
	dbKey.data = key;
	dbKey.size = strlen(key);

	dbData.data = data;
	dbData.size = strlen(data);
	*err = db->put(db, NULL, &dbKey, &dbData, flags);
	return true;
}
bool ReadDB(
	_In_ char* key,
	_Out_writes_bytes_(*dataLen) char* data,
	_Inout_ int* dataLen,
	_In_ DB* db,
	_Out_ int* err)
{
	*err = 0;
	DBT dbKey, dbData;
	memset(&dbKey, 0, sizeof(DBT));
	memset(&dbData, 0, sizeof(DBT));
	dbKey.data = key;
	dbKey.size = strlen(key);

	dbData.data = data;
	dbData.ulen = *dataLen;
	dbData.flags = DB_DBT_USERMEM;

	*err = db->get(db, NULL, &dbKey, &dbData, 0);
	if (*err) return false;
	*dataLen = dbData.size;
	return true;
}
bool DeleteKey
(
	_In_  DB* db,
	_In_  char* key,
	_Out_ int* err
)
{
	DBT dbKey;
	memset(&dbKey, 0, sizeof(DBT));

	dbKey.data = key;
	dbKey.size = strlen(key);
	*err = db->del(db, NULL, &dbKey, 0);
	if (*err) return false;
	return true;
}
bool ContainsKey
(
	_In_  DB* db,
	_In_  char* key,
	_In_  int maxLen,
	_Out_ bool* exists,
	_Out_ int* err
)
{
	*exists = false;
	char* data = NULL;
	__try { data = calloc(maxLen, 1); }
	__except (GetExceptionCode() == STATUS_ACCESS_VIOLATION) { *err = STATUS_ACCESS_VIOLATION; return false; }
	int ec = 0;
	int sz = maxLen;
	bool s = ReadDB(key, data, &sz, db, &ec);
	if(data) SecureZeroMemory(data, (SIZE_T)maxLen);
	free(data);
	if (!s && ec == DB_NOTFOUND) { *exists = false; return true; }
	else if (!s) 
	{
		*err = ec;
		return false;
	}	
	*exists = true;
	return true;
}
bool CloseDB(_In_ DB* db)
{
	if (!db) return false;
	db->close(db, 0);
	return true;
}