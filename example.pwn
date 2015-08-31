#include <a_samp>
#include <remotercon>

public OnFilterScriptInit() {

	ToggleRCONLogging(true);
	WhitelistIP("127.0.0.1");

	return 1;
}

public OnRemoteRCONFail(const ipaddr[], port, const password[], const command[], reason) {

	new
	    temp_bString[26];
	format(temp_bString, sizeof(temp_bString), "banip %s", ipaddr);
	SendRconCommand(temp_bString);
	
	return 1;
}

public OnRemoteRCONExecuted(const ipaddr[], port, const password[], const command[]) {

	new
	    temp_String[144];
	format(temp_String, sizeof(temp_String), "[REMOTE-RCON] : %s:%d executed CMD : %s using password : %s",
	    ipaddr, port, command, password);

	for(new i = 0, j = GetPlayerPoolSize(); i <= j; i++) {
	
	    if(!IsPlayerConnected(i)) continue;
	    if(!IsPlayerAdmin(i)) continue;
	    
	    SendClientMessage(i, -1, temp_String);
	}
	return 1;
}

