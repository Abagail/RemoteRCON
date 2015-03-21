#include <a_samp>
#include <YSF>
#define MAX_COMMANDS 10
#define MAX_RCONS 20
#define INVALID_RCON_ID -1
#define MAX_IP_LEN 32

enum g_rcon_data
{
	g_iIP[MAX_IP_LEN],
	g_icommanddata[MAX_COMMANDS],
	g_iUsed
}

new g_iLogging;
new g_iRCON = 1;
new g_iWhitelisting = 1;
new g_iRCONData[MAX_RCONS][g_rcon_data];

forward OnRemoteRCONFail(ipaddr[], port, password[], command[], reason);
forward OnRemoteRCONExecuted(ipaddr[], port, password[], command[]);

public OnFilterScriptInit()
{
     if(!GetServerVarAsInt("rcon"))
     {
          printf("[WARNING]: RCON is disabled in server.cfg! Enable it.");
     }
     
     CallLocalFunction("A_OnFilterScriptInit", "", "");
     return 1;
}
     #if defined _ALS_OnFilterScriptInit
     #undef OnFilterScriptInit
     #else
     #define _ALS_OnFilterScriptInit
     #endif

     #define OnFilterScriptInit A_OnFilterScriptInit

forward A_OnFilterScriptInit();
          
public OnRemoteRCONPacket(const ipaddr[], port, const password[], success, const command[])
{
	new modifyableIP[MAX_IP_LEN], modifyablePassword[32], modifyableCommand[80], reason;
	format(modifyableIP, sizeof(modifyableIP), "%s", ipaddr); // we have to do this since YSF makes the ipaddr var a constant
	format(modifyablePassword, sizeof(modifyablePassword), "%s", password);
	format(modifyableCommand, sizeof(modifyableCommand), "%s", command);
	if(g_iRCON)
	{
		if(g_iLogging)
		{
			if(!success)
			{
			    printf("IP: %s:%d(using password: %d) failed remote-RCON login.");
			    printf("[RAW DETAILS]: %s,%d,%s,%d,%s");
			}
		}
			    
			
	    if(success)
	    {
	        if(g_iWhitelisting)
			{
				if(IsIPWhitelisted(modifyableIP))
				{
					/*new id = GetIPEnumInt(), command; // Command system in progress
					
					if(strcmp(command, "NULL", true) == -1)
					{
						// No command was reported
						command = 0;
					}
					
					else
					{
						if(strcmp(command, "echo RCON admin connected to server.", true) == 0)
						{
						    command = 1; // Login
						}
					}*/
					
					//if(g_iCommandData[command][permission] == 0) // Aren't denied the permission
					//{
							
					    if(g_iLogging) printf("Command executed by %s:%d(password: %s) - Command: %s.", ipaddr, port, password, command);
						CallLocalFunction("OnRemoteRCONExecuted", ipaddr, port, password, command);
						
						if(funcidx("OnRemoteRCONExecuted") >= 0)
						{
							if(OnRemoteRCONExecuted(modifyableIP, port, modifyablePassword, modifyableCommand) == 0)
							{
								if(g_iLogging) printf("Command dropped in OnRemoteRCONExecuted.");
								return 0;
							}
						}
						
						return 1;
					//}
				}
				else 
				{
					reason = 1;
					CallLocalFunction("OnRemoteRCONFail", ipaddr, port, password, command, reason);
					return 0; // drop the packet
				}
			}
		}
		
		else
		{
			reason = 2;
		    CallLocalFunction("OnRemoteRCONFail", ipaddr, port, password, command, reason);
			return 0; // drop the packet
		}
	}
	
	else
	{
		reason = 3;
		CallLocalFunction("OnRemoteRCONFail", ipaddr, port, password, command, reason);
		return 0; // Remote RCON isn't enabled.
	}
	
	return 1;
}

stock bool: ToggleLogging(bool: toggle)
{
	if(toggle == true)
	{
		g_iLogging = true;
	}
	else
	{
		g_iLogging = false;
	}
	
	return toggle;
}
	
stock bool: ToggleRemoteRCON(bool: toggle)
{
	if(toggle == true)
	{
	    g_iRCON = 1;
	}
	
	else
	{
	    g_iRCON = 0;
	}

	return toggle;
}

stock bool: ToggleRemoteWhitelist(bool: toggle)
{
	if(toggle == true)
	{
	    g_iWhitelisting = 1;
	}
	
	else
	{
	    g_iWhitelisting = 0;
	}
	
	return toggle;
}

stock GetFreeRCONSlot()
{
	new id = -1;
	for (new i = 0; i != MAX_RCONS; ++i)
	{
		if(g_iRCONData[i][g_iUsed])
		{
			continue;
		}
		
		else
		{
			id = i;
			break;
		}
	}
	
	return id;
}
	

stock WhitelistIP(ipaddr[])
{
	if(IsIPWhitelisted(ipaddr))
	{
	    return 1; // the IP is already whitelisted.
	}
	
	else
	{
	    new slot = GetFreeRCONSlot();

		if(slot || slot == 0) // Will be -1 if none are avaliable
		{
			format(g_iRCONData[slot][g_iIP], MAX_IP_LEN, "%s", ipaddr);
			g_iRCONData[slot][g_iUsed] = 1;
			
			return 1;
		}
		
		else return 0;
	}
}

stock UnwhitelistIPAddress(ipaddr[])
{
	if(IsIPWhitelisted(ipaddr)
	{
	    new slot = GetIPSlot(ipaddr);

		g_iRCONData[i][g_iIP] = EOS;
		g_iRCONData[i][g_iUsed] = 0;
		return 1;
	}
	
	else return 0;
}
stock IsIPWhitelisted(ipaddr[])
{
    for (new i = 0; i != MAX_RCONS; ++i)
	{
	    if(strcmp(g_iRCONData[i][g_iIP], ipaddr, true) == 0)
	    {
	        return 1;
		}
	}
	
	return 0;
}
		
stock GetIPSlot(ipaddr[])
{
    for (new i = 0; i != MAX_RCONS; ++i)
	{
	    if(strcmp(g_iRCONData[i][g_iIP], ipaddr, true) == 0)
	    {
	        return i;
		}
	}
	
	return INVALID_RCON_SLOT;
}
					
					
