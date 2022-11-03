#include "User.h"
#include <windows.h>

struct _cdat init(struct _cdat *clientData, char* pwd, bool hasJoinedTwice)
{
	struct _cdat def;
	memset(&def, 0, sizeof(ClientData));
	def.hasJoinedTwice = hasJoinedTwice;
	def.password = pwd;
	def.permmissions = perm_normal;
	*clientData = def;
}
struct _cdat init_all(struct _cdat *clientData, perm p, char* pwd, bool hasJoinedTwice)
{
	struct _cdat def;
	memset(&def, 0, sizeof(ClientData));
	def.hasJoinedTwice = hasJoinedTwice;
	def.password = pwd;
	def.permmissions = p;
	*clientData = def;
}

bool init_struct(ClientData* sinit, const char* exeName)
{
	sinit->init = init;
	sinit->init_all = init_all;
	return sinit->init && sinit->init_all;
}