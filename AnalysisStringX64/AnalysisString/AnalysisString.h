#pragma once
class MyPlugmod : public plugmod_t
{
public:
	// Constructor
	uint64 g_bChooseCode = 0;
	MyPlugmod()
	{
		msg("AnalysisString.\n");
		msg("Copyright X64:CB Version:1.2  Date:2025/02/17 \n");
	}

	// Destructor
	virtual ~MyPlugmod()
	{
		msg("MyPlugmod: Destructor called.\n");
	}
	// Method that gets called when the plugin is activated
	virtual bool idaapi run(size_t arg) override;
	bool AnalyzeUnicodeString_204B0();
	bool AnalyzeAscllString_104E3();
	bool AnalyzeAscllString();
	bool AnalyzeAscllString2();
	bool AnalyzeChineseString();
};