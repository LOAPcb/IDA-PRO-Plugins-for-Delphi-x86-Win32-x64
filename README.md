Here is the translation of your text into English:

### Notes:
1. This is a collection of IDAPRO plugins for Delphi, and it will be updated in the future.
2. Each plugin has two versions: one for 32-bit Delphi programs and one for 64-bit Delphi programs.
3. When using the plugins, **always** use a copy of the IDAPRO file to avoid causing a complete crash of the IDAPRO database.
4. Developers should adjust the plugin source code based on their own situation, and not use it directly without modifications.
5. Please execute the plugins in this order: first analyze strings, then rename functions, and finally create classes and structures.  
   **AnalysisString → ModifyFunctionForString → ClassExtractorForDelphi**

### Project Description:
1. **AnalysisString** and **AnalysisStringX64** are string analysis plugins for 32-bit and 64-bit Delphi versions, respectively. These plugins are used to analyze strings in IDAPRO that are not recognized, including Unicode and ASCII.
2. **ModifyFunctionForString** and **ModifyFunctionNameForStringX64** are one-click function renaming plugins for Delphi 32-bit and 64-bit versions.
3. **ClassExtractorForDelphi** and **DelphiClassExtractorX64** are plugins for Delphi 32-bit and 64-bit versions, used to automatically analyze Delphi’s RTTI data types. They allow one-click creation of structs, classes, and enum types in IDAPRO.

注意事项：

1.这是一个IDAPRO对于Delphi的插件集合，后期还会进行更新。
2.每个插件都有两个版本，一个针对于32位的delphi程序，一个针对于64位的delphi程序。
3.使用插件的时候一定一定一定一定要用idapro文件的副本，以免idapro数据库彻底崩溃。
4.请开发者根据自身情况调整插件源码，不要上来就直接使用。
5.请按照这个顺序执行插件，先分析字符串，然后给函数命名，再创建类、结构体。
AnalysisString->ModifyFunctionForString->ClassExtractorForDelphi

项目描述：

1.AnalysisString和AnalysisStringX64是针对于Delphi32位版本和64位版本的解析字符串插件，该插件用来分析IDAPRO中未能识别的字符串，包含unicode和ascll。
2.ModifyFunctionForString和ModifyFunctionNameForStringX64是针对于Delphi32位版本和64位版本函数一键命名插件。
3.ClassExtractorForDelphi和DelphiClassExtractorX64是针对于是针对于Delphi32位版本和64位版本的插件，用来自动分析Delphi中的Rtti数据类型，可以在IDAPRO中一键创建Strcut，Class，和Enum类型的数据。
