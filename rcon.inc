#tryinclude <a_samp>
#tryinclude <YSF>

#if !defined MAX_RCONS
	#define MAX_RCONS 20
#endif

#if !defined INVALID_RCON_ID
	#define INVALID_RCON_ID -1
#endif


#if !defined INVALID_RCON_SLOT
	#define INVALID_RCON_SLOT -1
#endif

#if !defined MAX_IP_LEN
	#define MAX_IP_LEN 16
#endif

#if !defined strcpy
	#define strcpy(%0,%1,%2)    strcat((%0[0] = '\0',%0), %1, %2)
#endif

enum e_RCON_DATA {

	e_iIP[MAX_IP_LEN]
}

enum e_REMOTE_RCON_BOOLS:(<<= 1) {

	e_BOOL_iRCON = 1,
	e_BOOL_iLogging,
	e_BOOL_iWhitelisting,
	e_BOOL_iInit
}

new static
		g_iRCONData[MAX_RCONS][e_RCON_DATA],
		e_REMOTE_RCON_BOOLS:g_iRCONBools;


static Ab_RCONInit() {

	if(!GetConsoleVarAsInt("rcon"))
	    print("[WARNING] : RCON is disabled in server.cfg! Enable it.");

	for(new i = 0; i< MAX_RCONS; i++)
	    g_iRCONData[i][e_iIP][0] = '\0';

	g_iRCONBools |= e_BOOL_iRCON;
	g_iRCONBools |= e_BOOL_iWhitelisting;
	return 1;
}

public OnFilterScriptInit() {

	if(!(g_iRCONBools & e_BOOL_iInit)) {

	    g_iRCONBools |= e_BOOL_iInit;
	    Ab_RCONInit();
	}
	#if defined Ab_RCON_OnFilterScriptInit
		return Ab_RCON_OnFilterScriptInit();
	#else
		return 1;
	#endif
}

public OnGameModeInit() {

	if(!(g_iRCONBools & e_BOOL_iInit)) {

	    g_iRCONBools |= e_BOOL_iInit;
		Ab_RCONInit();
	}
	#if defined Ab_RCON_OnGameModeInit
	    return Ab_RCON_OnGameModeInit();
	#else
	    return 1;
	#endif
}

public OnRemoteRCONPacket(const ipaddr[], port, const password[], success, const command[]) {

	if(g_iRCONBools & e_BOOL_iRCON) {

	    if(g_iRCONBools & e_BOOL_iLogging) {

		    if(!success) {

		        printf("IP : %s:%d(using password : %s) failed remote RCON login!", ipaddr, port, password);
		        printf("[RAW DETAILS]: %s,%d,%s,%d,%s", ipaddr, port, password, success, command);
				CallLocalFunction("OnRemoteRCONFail", "sissi", ipaddr, port, password, command, 2);
			}
		}
		if(success) {

		    if(g_iRCONBools & e_BOOL_iWhitelisting) {

		        if(IsIPWhitelisted(ipaddr)) {

		            if(g_iRCONBools & e_BOOL_iLogging)
		                printf("RCON Command executed by %s:%d(password : %s) - Command : %s", ipaddr, port, password, command);

					CallLocalFunction("OnRemoteRCONExecuted", "siss", ipaddr, port, password, command);

	    			if(!OnRemoteRCONExecuted(ipaddr, port, password, command)) {

	    			    if(g_iRCONBools & e_BOOL_iLogging)
	    			        printf("Command : \"%s\" dropped in OnRemoteRCONExecuted.", command);

						return 0;
					}
					return 1;
				}
				else {

				    CallLocalFunction("OnRemoteRCONFail", "sissi", ipaddr, port, password, command, 1);
				    return 0;
				}
			}
		}
	}
	else {

	    CallLocalFunction("OnRemoteRCONFail", "sissi", ipaddr, port, password, command, 3);
		return 0;
	}
	#if defined Ab_RCON_OnRemoteRCONPacket
	    return Ab_RCON_OnRemoteRCONPacket(ipaddr, port, password, success, command);
	#else
		return 1;
	#endif
}

#if defined _ALS_OnFilterScriptInit
	#undef OnFilterScriptInit
#else
	#define _ALS_OnFilterScriptInit
#endif

#if defined _ALS_OnGameModeInit
	#undef OnGameModeInit
#else
	#define _ALS_OnGameModeInit
#endif

#if defined _ALS_OnRemoteRCONPacket
	#undef OnRemoteRCONPacket
#else
	#define _ALS_OnRemoteRCONPacket
#endif


#define OnFilterScriptInit 	Ab_RCON_OnFilterScriptInit
#define OnGameModeInit      Ab_RCON_OnGameModeInit
#define OnRemoteRCONPacket 	Ab_RCON_OnRemoteRCONPacket


#if defined Ab_RCON_OnFilterScriptInit
	forward Ab_RCON_OnFilterScriptInit();
#endif

#if defined Ab_RCON_OnGameModeInit
	forward Ab_RCON_OnGameModeInit();
#endif

#if defined Ab_RCON_OnRemoteRCONPacket
	forward Ab_RCON_OnRemoteRCONPacket(const ipaddr[], port, const password[], success, const command[]);
#endif



stock ToggleRCONLogging(bool:toggle) {

	if(toggle)
	    g_iRCONBools |= e_BOOL_iLogging;
	else
	    g_iRCONBools &= ~e_BOOL_iLogging;
	return 1;
}

stock ToggleRemoteRCON(bool:toggle) {

	if(toggle)
	    g_iRCONBools |= e_BOOL_iRCON;
	else
	    g_iRCONBools &= ~e_BOOL_iRCON;
	return 1;
}

stock ToggleRemoteWhitelist(bool:toggle) {

	if(toggle)
	    g_iRCONBools |= e_BOOL_iWhitelisting;
	else
	    g_iRCONBools &= ~e_BOOL_iWhitelisting;
	return 1;
}

stock RCON_IsWhitelistingEnabled() 	return g_iRCONBools & e_BOOL_iWhitelisting;
stock RCON_IsRemoteRCONEnabled()    return g_iRCONBools & e_BOOL_iRCON;
stock RCON_IsLoggingEnabled()       return g_iRCONBools & e_BOOL_iLogging;


stock GetFreeRCONSlot() {

	for(new i = 0; i< MAX_RCONS; i++) {

	    if(g_iRCONData[i][e_iIP][0] == '\0')
	        return i;
	}
	return INVALID_RCON_SLOT;
}

static stock RCON_GetIPSlot(ip_address[]) {

	for(new i = 0; i< MAX_RCONS; i++) {

	    if(!strcmp(ip_address, g_iRCONData[i][e_iIP], true))
	        return i;
	}
	return INVALID_RCON_SLOT;
}

stock IsIPWhitelisted(const ip_address[]) {

	for(new i = 0; i< MAX_RCONS; i++) {

	    if(!strcmp(ip_address, g_iRCONData[i][e_iIP], true))
	        return 1;
	}
	return 0;
}

stock WhitelistIP(ip_address[]) {

	if(IsIPWhitelisted(ip_address)) return 0;

	new
	    temp_Slot = RCON_GetIPSlot(ip_address);

	if(temp_Slot != INVALID_RCON_SLOT) {

	    strcpy(g_iRCONData[temp_Slot][e_iIP], ip_address, MAX_IP_LEN);
		return 1;
	}
	return 0;
}

stock UnwhitelistIPAddress(ip_address[]) {

	new
	    temp_Slot = RCON_GetIPSlot(ip_address);

	if(temp_Slot != INVALID_RCON_SLOT) {

	    g_iRCONData[temp_Slot][e_iIP][0] = '\0';
	    return 1;
	}
	return 0;
}


forward OnRemoteRCONFail(const ipaddr[], port, const password[], const command[], reason);
forward OnRemoteRCONExecuted(const ipaddr[], port, const password[], const command[]);

