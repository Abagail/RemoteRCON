#include <a_samp>
#include <rcon>
#define FILTERSCRIPT

public OnFilterScriptInit()
{
	WhitelistIP("127.0.0.1");
	ToggleLogging(true);
	return 1;
}

public OnRemoteRCONFail(ipaddr[], port, password[], command[])
{
	new string[64];
	format(string, sizeof(string), "banip %s", ipaddr);
	SendRconCommand(string);
	
	return 1;
}

public OnRemoteRCONExecuted(ipaddr[], port, password[], command[])
{
	return 1;
}
