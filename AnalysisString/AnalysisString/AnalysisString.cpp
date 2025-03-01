
#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>



//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
	virtual bool idaapi run(size_t) override;
};

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t)
{
	msg("Analysis Unicode string format: 0x204B0,0xFFFFFFFF,Size\n");
	
	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg("Search Area:[%X]-[%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	for (int i = 0; i < (Max_ea - Min_ea); i++)
	{
		b_ret = get_data_value(&nEax, eaBaseAddress + i, 4);
		if (!b_ret)
		{
			break;
		}

		if (nEax != 0x204B0)
		{
			//break;
			continue;
		}

		get_data_value(&nEax, eaBaseAddress + i + 4, 4);
		if (nEax != 0xFFFFFFFF)
		{
			continue;
		}

		get_data_value(&nEax, eaBaseAddress + i + 8, 4);
		uval_t uOriginalSize = nEax * 2;
		uval_t uReadEndLenght = 4;
		if ( uOriginalSize % 4 )
		{
			uReadEndLenght = 2;
		}

		get_data_value(&nEax, eaBaseAddress + i + 12 + uOriginalSize, uReadEndLenght);
		if (nEax)
		{
			continue;
		}

		create_data(eaBaseAddress + i, dword_flag(), 12, BADNODE);

		array_parameters_t arr_param;
		arr_param.alignment = -1;
		arr_param.lineitems = 0x03;
		arr_param.flags = AP_ALLOWDUPS | AP_IDXHEX | AP_ARRAY | AP_IDXBASEMASK;
		set_array_parameters(eaBaseAddress + i, &arr_param);

		uval_t uTotalSize = uOriginalSize + uReadEndLenght;
		create_strlit(eaBaseAddress + i + 12, uTotalSize, STRTYPE_C_16);

		i = i + uTotalSize + 12;
		i--;
		uAnalysisCount++;
	}

	msg(" Finally! Total:[%X]\n", uAnalysisCount);
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
	"Analysis Special Unicode String [0x204B0,0xFFFFFFFF,Size]",              // long comment about the plugin
	nullptr,              // multiline help about the plugin
	"Analysis Unistring",       // the preferred short name of the plugin
	nullptr,              // the preferred hotkey to run the plugin
};
