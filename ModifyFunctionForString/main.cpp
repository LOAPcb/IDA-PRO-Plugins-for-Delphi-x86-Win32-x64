
#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>



bool AnalyzingFunctionFormat()
{
	msg("Analyzing function format: \"0x00,Function,Size,XXX...\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();//

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	for (int i = 0; i < (Max_ea - Min_ea); i++)
	{
		b_ret = get_data_value(&nEax, eaBaseAddress + i, 1);
		if (!b_ret)
		{
			continue;
		}

		if ( nEax < 4 )
		{
			continue;
		}

		int nAscllLenght = nEax;
		int nASCLLCount = 0;
		for ( int nbase = 1; nbase <= nAscllLenght; nbase++ )
		{
			get_data_value(&nEax, eaBaseAddress + i + nbase, 1);
			if (!b_ret)
			{
				break;
			}

			if ((nEax >= 0x41 && nEax <= 0x5A) 
				|| (nEax >= 0x61 && nEax <= 0x7A)
				|| (nEax >= 0x30 && nEax <= 0x39)
				|| nEax == 0x5F || nEax == 0x20
				|| nEax == 0x2D)
			{
				nASCLLCount++;
			}
			else
			{
				nASCLLCount = 0;
			}

			if (nASCLLCount == nAscllLenght)
			{
				uval_t uTotalSize = nAscllLenght + 1;

				char szfunctionName[255];
				memset(szfunctionName, 0, 255);
				szfunctionName[0] = 'C';
				szfunctionName[1] = '_';
				for ( int nName = 0; nName < nASCLLCount; nName++ )
				{
					get_data_value((uval_t*)(szfunctionName+nName+2), eaBaseAddress + i + nName + 1, 1);
				}

				for (int nName = 0; nName < nASCLLCount + 2; nName++)
				{
					if (szfunctionName[nName] == 0x20)
					{
						szfunctionName[nName] = '_';
					}
				}
			
				get_data_value(&nEax, eaBaseAddress + i - 5, 1);
				if (!nEax)
				{
					get_data_value(&nEax, eaBaseAddress + i - 4, 4);
					if (nEax > Min_ea && nEax < Max_ea)
					{
						
						uAnalysisCount++;
						bool bRet = set_name(nEax, szfunctionName, SN_FORCE);
						if (!bRet)
						{
							msg("   Fail Offset:[%X]\n", eaBaseAddress + i - 4);
						}
					}
				}

				i += uTotalSize;
				i--;
				break;
			}
		}
	}
	refresh_idaview_anyway();
	msg(" Finally! Total:[%d]\n", uAnalysisCount);
	return true;
}

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
	virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
	msg("Copyright:lujie Version:1.1  Date:2023/04/19 \n");

	show_wait_box("HIDECANCEL\n Please wait...");
	AnalyzingFunctionFormat();
	hide_wait_box();

	msg("End of analysis!\n");
	return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
	return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
//	PLUGIN_FIX,
	PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
	| PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
	init,                 // initialize
	nullptr,
	nullptr,
	"Analyzing function format: \"0x00,Function,Size,XXX...\"",              // long comment about the plugin
	nullptr,              // multiline help about the plugin
	"Modify Function For String",       // the preferred short name of the plugin
	nullptr,              // the preferred hotkey to run the plugin
};
