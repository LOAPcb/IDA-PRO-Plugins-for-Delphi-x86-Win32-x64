#include"AnalysisFuncitonName.h"
//--------------------------------------------------------------------------
static plugmod_t* idaapi init()
{
	return new MyPlugmod();
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

bool idaapi MyPlugmod::run(size_t arg)
{
	show_wait_box("HIDECANCEL\n Please wait...");
	ModifyFunctionNameForString2();
	ModifyFunctionNameForString();
	hide_wait_box();

	msg("End of analysis!\n");
	return true;
}

bool MyPlugmod::ModifyFunctionNameForString2()
{
	msg("Analyzing function2 format: \"0x00,Function,Size,XXX...\"\n");
	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	ea_t eaBaseAddress = Min_ea;
	uval_t dataValue = 0;
	uval_t stringSize = 0;
	uval_t guessStringSize = 0;
	uval_t stringData = 0;
	bool bRet = false;
	char functionName[255] = { 0 };
	char guessFunctionName[255] = { 0 };
	uval_t stringCount = 0;
	uval_t functionAddress;
	for (ea_t i = 0; i < (Max_ea - Min_ea); i++)
	{
		if (i + eaBaseAddress == 0x0000000023DCB7EC)
		{
			int a = 0;
		}
		guessStringSize = 0;
		stringSize = 0;
		get_data_value(&dataValue, eaBaseAddress + i, 8);//10 61 DD 23 00 00 00 00                 dq offset sub_23DD6110
		functionAddress = dataValue;
		if (dataValue > Min_ea && dataValue < Max_ea)
		{
			get_data_value(&dataValue, eaBaseAddress + i + 8, 8); //00 00 00 00 00 00 00 00                 dq 0
			if (dataValue != 0)
			{
				continue;
			}
			get_data_value(&dataValue, eaBaseAddress + i + 0x10, 8);//01 00 00 00 00 00 00 00                 dq 1
			if (dataValue != 1)
			{
				continue;
			}
			get_data_value(&dataValue, eaBaseAddress + i + 0x18, 8); //00 00 00 80 00 00 00 00                 dq 80000000h
			if (dataValue != 0x8000000080000000)
			{
				continue;
			}
			get_data_value(&dataValue, eaBaseAddress + i + 0x20, 2);//FF FF                                   dw 0FFFFh
			if (dataValue != 0xFFFF)
			{
				continue;
			}
			ea_t stringAddress = eaBaseAddress + i + 0x22;
			get_data_value(&stringSize, stringAddress, 1);//07 43 68 69 70 44 69 6D aChipdim        db 7,'ChipDim' 
			if (!stringSize)
			{
				continue;
			}
			memset(guessFunctionName,0, 255);
			memset(functionName, 0, 255);
			for (int j = 1; j <= stringSize; j++)
			{
				get_data_value(&stringData, stringAddress + j, 1);
				if ((stringData >= 0x41 && stringData <= 0x5A)
					|| (stringData >= 0x61 && stringData <= 0x7A)
					|| (stringData >= 0x30 && stringData <= 0x39)
					|| stringData == 0x5F || stringData == 0x20
					|| stringData == 0x2D)
				{
					guessStringSize++;
					guessFunctionName[j - 1] = stringData;
				}
				else
				{
					guessStringSize = 0;
				}
				if (guessStringSize == stringSize)
				{
					functionName[0] = 'G';
					functionName[1] = '_';
					memcpy_s(functionName + 2, guessStringSize, guessFunctionName, guessStringSize);
					bool bRet = set_name(functionAddress, functionName, SN_FORCE);
					stringCount++;
					break;
				}
			}
		}
	}
	refresh_idaview_anyway();
	msg(" Finally! Total:[%d]\n", stringCount);
	return true;
}

bool MyPlugmod::ModifyFunctionNameForString()
{
	msg("Analyzing function format: \"0x00,Function,Size,XXX...\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();//

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	for (ea_t i = 0; i < (Max_ea - Min_ea); i++)
	{
		b_ret = get_data_value(&nEax, eaBaseAddress + i, 1);
		if (!b_ret)        
		{
			continue;
		}

		if (nEax < 4)
		{
			continue;
		}
		if (eaBaseAddress + i == 0x0000000023F03C74)
		{
			int a = 0;
		}
		ea_t nAscllLenght = nEax;
		ea_t nASCLLCount = 0;
		for (ea_t nbase = 1; nbase <= nAscllLenght; nbase++)
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
				for (ea_t nName = 0; nName < nASCLLCount; nName++)
				{
					get_data_value((uval_t*)(szfunctionName + nName + 2), eaBaseAddress + i + nName + 1, 1);
				}

				for (ea_t nName = 0; nName < nASCLLCount + 2; nName++)
				{
					if (szfunctionName[nName] == 0x20)
					{
						szfunctionName[nName] = '_';
					}
				}
				get_data_value(&nEax, eaBaseAddress + i - 9, 1);
				if (!nEax)
				{
					get_data_value(&nEax, eaBaseAddress + i - 8, 8);
					if (nEax > Min_ea && nEax < Max_ea)
					{

						uAnalysisCount++;
						bool bRet = set_name(nEax, szfunctionName, SN_FORCE);
						if (!bRet)
						{
							msg("   Fail Offset:[%X]\n", eaBaseAddress + i - 8);
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