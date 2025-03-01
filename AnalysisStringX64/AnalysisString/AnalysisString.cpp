#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include"AnalysisString.h"
//以上是导入的SDK头文件

// Define the class that inherits from plugmod_t

static plugmod_t* idaapi init(void)
{
	return new MyPlugmod();
}

plugin_t PLUGIN = 
{
 IDP_INTERFACE_VERSION,
 //	PLUGIN_FIX,
	 PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
	 | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
	 init,                 // initialize
	 nullptr,
	 nullptr,
	 "Analyze specific ASCLL/Unicode string",              // long comment about the plugin
	 nullptr,              // multiline help about the plugin
	 "Analyze string",       // the preferred short name of the plugin
	 nullptr,              // the preferred hotkey to run the plugin
};
bool idaapi MyPlugmod::run(size_t arg)
{

	g_bChooseCode = ask_yn(ASKBTN_YES, "Whether to analyze code segment?");

	show_wait_box("HIDECANCEL\n Please wait...");
 	AnalyzeUnicodeString_204B0();
 	AnalyzeAscllString_104E3();
 	hide_wait_box();

	int bChoose = ask_yn(ASKBTN_YES, "Whether to analyze ASCLL string?");
	msg("bChoose:%d\n", bChoose);
	if (bChoose == ASKBTN_YES)
	{

		show_wait_box("HIDECANCEL\n Please wait...");
		AnalyzeAscllString();
		AnalyzeAscllString2();
		hide_wait_box();
	}

// 	bChoose = ask_yn(ASKBTN_YES, "Whether to analyze chinese string?\r\n\
// Only parse non Code segments to avoid unnecessary trouble!!!\r\n\
// Please set \"Default 8-bit\" in Strings to \"CP936\"\r\n");
// 	//msg("bChoose:%d\n", bChoose);
// 	if (bChoose == ASKBTN_YES)
// 	{
// 		show_wait_box("HIDECANCEL\n Please wait...");
// 		// AnalyzeChineseString();
// 		hide_wait_box();
// 	}
	msg("End of analysis!\n");
	return true;
}

bool MyPlugmod::AnalyzeUnicodeString_204B0()
{
	msg("Analyzing Unicode string format: \"0x204B0,0xFFFFFFFF,Size,XXX...,0x00...\"\n");
	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();//

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	ea_t i = 0;
	for (i = 0; i < (Max_ea - Min_ea); i++)
	{
		if (eaBaseAddress + i == 0x0000000023F0AE7C)
		{
			int a = 1;
		}
		if (!g_bChooseCode)
		{
			segment_t* Seg = getseg(eaBaseAddress + i);
			if (Seg->type == SEG_CODE)
			{
				continue;
			}
		}

		b_ret = get_data_value(&nEax, eaBaseAddress + i, 4);
		if (!b_ret)
		{
			continue;
		}

		if (nEax != 0x204B0)//这里确定字符串位置
		{
			//break;
			continue;
		}

		get_data_value(&nEax, eaBaseAddress + i + 4, 4);
		if (nEax != 0xFFFFFFFF)//这里是第二个标志
		{
			continue;
		}

		get_data_value(&nEax, eaBaseAddress + i + 8, 4);//nEax 为字符串的长度
		ulonglong uOriginalSize = nEax * 2;
		ulonglong uReadEndLenght = 4;
		//4字节对齐
		if (uOriginalSize % 4 != 0)
		{
			uReadEndLenght = 2;
		}
		/*get_data_value(&nEax, eaBaseAddress + i + 12 + uOriginalSize, uReadEndLenght);//判断结束符是不是00
		if (nEax)
		{
			continue;
		}*/ 

		create_data(eaBaseAddress + i, dword_flag(), 12, BADNODE);//把标识 签名 全部都解析出来了

		array_parameters_t arr_param;
		arr_param.alignment = -1;
		arr_param.lineitems = 0x03;
		arr_param.flags = AP_ALLOWDUPS | AP_IDXHEX | AP_ARRAY | AP_IDXBASEMASK;
		set_array_parameters(eaBaseAddress + i, &arr_param);//然后把索引都给表示起来

		uval_t uTotalSize = uOriginalSize;
		del_items(eaBaseAddress + i + 12, DELIT_EXPAND, uOriginalSize + uReadEndLenght);
		create_strlit(eaBaseAddress + i + 12, uOriginalSize+ 2, STRTYPE_C_16);
		tinfo_t tif;
		tif.create_simple_type(BTF_UCHAR);  //# 假设变量类型为char
		tif.set_const(); // # 设置为const类型
		bool setinfoType=set_tinfo(eaBaseAddress + i + 12, &tif);
		if (!setinfoType)
		{
			int a = 0;
		}
		i = i + uTotalSize + 12;
		i--;
		uAnalysisCount++;
	}

	msg(" Finally! Total AnalyzeUnicodeString_204B0:[%d]\n", uAnalysisCount);
	return true;
}

bool MyPlugmod::AnalyzeAscllString_104E3()
{
	msg("Analyzing Ascll string format: \"0x104E3,0xFFFFFFFF,Size,XXX...,0x00...\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();//

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	for (uint64 i = 0; i < (Max_ea - Min_ea); i++)
	{
		//跳过代码区域
		if (!g_bChooseCode)
		{
			segment_t* Seg = getseg(eaBaseAddress + i);
			if (Seg->type == SEG_CODE)
			{
				continue;
			}
		}

		b_ret = get_data_value(&nEax, eaBaseAddress + i, 4);
		if (!b_ret)
		{
			continue;
		}

		if (nEax != 0x104E3)
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
		uval_t uHeadSize = 12;
		uval_t uOriginalSize = nEax;
		uval_t uReadEndLenght = 1;
		//4字节对齐
		uval_t uEndAddress = eaBaseAddress + i + uHeadSize + uOriginalSize;
		uReadEndLenght = 4 - (uEndAddress % 4);
		//msg(" uReadEndLenght:[%d]\n", uReadEndLenght);

		if (uReadEndLenght == 3)
		{
			get_data_value(&nEax, eaBaseAddress + i + uHeadSize + uOriginalSize, 2);
			if (nEax)
			{
				continue;
			}
			get_data_value(&nEax, eaBaseAddress + i + uHeadSize + uOriginalSize + 2, 1);
			if (nEax)
			{
				continue;
			}
		}
		else
		{
			get_data_value(&nEax, eaBaseAddress + i + uHeadSize + uOriginalSize, uReadEndLenght);
			if (nEax)
			{
				continue;
			}
		}


		create_data(eaBaseAddress + i, dword_flag(), uHeadSize, BADNODE);

		array_parameters_t arr_param;
		arr_param.alignment = -1;
		arr_param.lineitems = 0x03;
		arr_param.flags = AP_ALLOWDUPS | AP_IDXHEX | AP_ARRAY | AP_IDXBASEMASK;
		set_array_parameters(eaBaseAddress + i, &arr_param);
		uval_t uTotalSize = uOriginalSize + uReadEndLenght;
		bool c1 = del_items(eaBaseAddress + i + uHeadSize, DELIT_EXPAND, uTotalSize);
		create_strlit(eaBaseAddress + i + uHeadSize, uTotalSize, STRTYPE_C);

		tinfo_t tif;
		tif.create_simple_type(BTF_CHAR);  //# 假设变量类型为char
		tif.set_const(); // # 设置为const类型
		set_tinfo(eaBaseAddress + i + uHeadSize, &tif);

		i = i + uTotalSize + uHeadSize;
		i--;
		uAnalysisCount++;
	}

	msg(" Finally! Total 104E3:[%d]\n", uAnalysisCount);
	return true;
}

bool MyPlugmod::AnalyzeAscllString()
{
	msg("Analyzing ASCLL string format: \"Size,XXX...\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();//

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;
	for (uint64 i = 0; i < (Max_ea - Min_ea); i++)
	{
		//跳过代码区域
		if (!g_bChooseCode)
		{
			segment_t* Seg = getseg(eaBaseAddress + i);
			if (Seg->type == SEG_CODE)
			{
				continue;
			}
		}
		b_ret = get_data_value(&nEax, eaBaseAddress + i, 1);
		if (!b_ret)
		{
			//msg("Get Error:Offset:[%X]\n", eaBaseAddress + i);
			continue;
		}

		if (nEax < 4)
		{
			continue;
		}

		uint64 nAscllLenght = nEax;
		uint64 nASCLLCount = 0;
		for (uint64 nbase = 1; nbase <= nAscllLenght; nbase++)
		{
			b_ret = get_data_value(&nEax, eaBaseAddress + i + nbase, 1);
			if (!b_ret)
			{
				//msg("Get Error:Offset:[%X]\n", eaBaseAddress + i + nbase);
				break;
			}

			if ((nEax >= 0x20 && nEax <= 0x7E)
				|| nEax == 0x0A || nEax == 0x0D)
			{
				nASCLLCount++;
			}
			else
			{
				nASCLLCount = 0;
				break;
			}

			if (nASCLLCount == nAscllLenght)
			{
				//msg("	Offset:[%X]\n", eaBaseAddress + i);
				uAnalysisCount++;

				uval_t uTotalSize = nAscllLenght + 1;

				del_items(eaBaseAddress + i, DELIT_EXPAND, uTotalSize);
				create_strlit(eaBaseAddress + i, uTotalSize, STRTYPE_C);

				tinfo_t tif;
				tif.create_simple_type(BTF_CHAR);  //# 假设变量类型为char
				tif.set_const(); // # 设置为const类型
				set_tinfo(eaBaseAddress + i, &tif);
 				//i += uTotalSize;
				//i--;
				break;
			}
		}
	}

	msg(" Finally! Total:[%d]\n", uAnalysisCount);
	return true;
}

bool MyPlugmod::AnalyzeAscllString2()
{
	msg("Analyzing ASCLL string format: \"XXX...,0x00\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();// 
	//ea_t eaBaseAddress = get_screen_ea();// 

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;

	uint64 nASCLLCount = 0;
	uint64 bEndflagofstring = 0;
	for (uint64 i = 0; i < (Max_ea - Min_ea); i++)
	{
		//跳过代码区域
		if (!g_bChooseCode)
		{
			segment_t* Seg = getseg(eaBaseAddress + i);
			if (Seg->type == SEG_CODE)
			{
				continue;
			}
		}
		if (eaBaseAddress + i == 0x0000000023F088C1)
		{
			int a = 0;
		}
		b_ret = get_data_value(&nEax, eaBaseAddress + i, 1);
		if (!b_ret)
		{
			continue;
		}

		bEndflagofstring = 0;
		if ((nEax >= 0x20 && nEax <= 0x7E)|| nEax == 0x0A || nEax == 0x0D)
		{
			nASCLLCount++;
			if (nASCLLCount >= 4)
			{
				b_ret = get_data_value(&nEax, eaBaseAddress + i + 1, 1);
				if (!b_ret)
				{
					continue;
				}

				if (!nEax)
				{
					bEndflagofstring = 1;
				}
			}
		}
		else
		{
			nASCLLCount = 0;
		}

		if (nASCLLCount >= 4 && bEndflagofstring)
		{
			uAnalysisCount++;

			uval_t uStringStartOffset = i - nASCLLCount + 1;
			uval_t uTotalSize = nASCLLCount + 1;

			del_items(eaBaseAddress + uStringStartOffset, DELIT_EXPAND, uTotalSize);
			create_strlit(eaBaseAddress + uStringStartOffset, uTotalSize, STRTYPE_C);

			tinfo_t tif;
			tif.create_simple_type(BTF_CHAR);  //# 假设变量类型为char
			tif.set_const(); // # 设置为const类型
// 			get_tinfo(&tif,eaBaseAddress + uStringStartOffset);
// 			tif.get_modifiers();这里判断有没有字符串
			set_tinfo(eaBaseAddress + uStringStartOffset, &tif);
		}

	}

	msg(" Finally! Total:[%d]\n", uAnalysisCount);
	return true;
}

bool MyPlugmod::AnalyzeChineseString()
{
	msg("Analyzing Chinese string format: \"XXX...,0x00\"\n");

	ea_t Min_ea = inf_get_min_ea();
	ea_t Max_ea = inf_get_max_ea();
	msg(" Search area:[0x%X]-[0x%X]\n", Min_ea, Max_ea);
	ea_t eaBaseAddress = Min_ea;//get_screen_ea();// 
	//ea_t eaBaseAddress = get_screen_ea();// 

	uval_t uAnalysisCount = 0;
	uval_t nEax = 0;
	bool b_ret = false;

	uint64 nASCLLCount = 0;
	uint64 bEndflagofstring = 0;
	for (uint64 i = 0; i < (Max_ea - Min_ea); i++)
	{
		segment_t* Seg = getseg(eaBaseAddress + i);
		if (Seg->type == SEG_CODE)
		{
			continue;
		}

		b_ret = get_data_value(&nEax, eaBaseAddress + i, 1);
		if (!b_ret)
		{
			continue;
		}

		//CP936(GBK)0x8140-0xFEFE
		//CP936(GB)0xB0A0-0xFEFE

		bEndflagofstring = 0;
		if (nEax >= 0x20 || nEax == 0x0A || nEax == 0x0D)
		{
			nASCLLCount++;
			if (nASCLLCount >= 4)
			{
				b_ret = get_data_value(&nEax, eaBaseAddress + i + 1, 1);
				if (!b_ret)
				{
					continue;
				}

				if (!nEax)
				{
					bEndflagofstring = 1;
				}
			}
		}
		else
		{
			nASCLLCount = 0;
		}

		if (nASCLLCount >= 4 && bEndflagofstring)
		{
			uAnalysisCount++;

			uval_t uStringStartOffset = i - nASCLLCount + 1;
			uval_t uTotalSize = nASCLLCount + 1;

			del_items(eaBaseAddress + uStringStartOffset, DELIT_EXPAND, uTotalSize);
			create_strlit(eaBaseAddress + uStringStartOffset, uTotalSize, STRTYPE_C);

			tinfo_t tif;
			tif.create_simple_type(BTF_CHAR);  //# 假设变量类型为char
			tif.set_const(); // # 设置为const类型
			set_tinfo(eaBaseAddress + uStringStartOffset, &tif);
			//------------------Dubug------------------//
			//msg("   Offset:[%X]-%X\n", eaBaseAddress + uStringStartOffset, uTotalSize);
			//break;
		}

	}

	msg(" Finally! Total:[%d]\n", uAnalysisCount);
	return true;
}

