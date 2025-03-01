#pragma once
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>

//以上是导入的SDK头文件

// Define the class that inherits from plugmod_t
class MyPlugmod : public plugmod_t
{
public:
	MyPlugmod()
	{
		msg("ModifyFunctionName!");
		msg("CopyRight X64:CB 2025/2/17");
	}

	// Destructor
	virtual ~MyPlugmod()
	{
	}
	// Method that gets called when the plugin is activated
	virtual bool idaapi run(size_t arg) override;
	bool ModifyFunctionNameForString();
	bool ModifyFunctionNameForString2();
};
