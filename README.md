# IDAPRO Delphi Plugins

This is a collection of IDAPRO plugins for Delphi. Updates will be released in the future.

## Notes

1. This is a collection of IDAPRO plugins specifically for Delphi. Updates will be made in the future.
2. Each plugin has two versions: one for 32-bit Delphi programs and one for 64-bit Delphi programs.
3. **Important:** Always use a copy of the IDAPRO file when using the plugins to prevent the IDAPRO database from crashing.
4. Developers should adjust the plugin source code based on their specific needs, and should **not** use it directly without modification.
5. Please execute the plugins in the following order:
   - **AnalysisString**
   - **ModifyFunctionForString**
   - **ClassExtractorForDelphi**

   **Execution Order:** `AnalysisString -> ModifyFunctionForString -> ClassExtractorForDelphi`

## Project Description

1. **AnalysisString** and **AnalysisStringX64** are plugins for analyzing strings in Delphi 32-bit and 64-bit programs, respectively. These plugins help analyze unrecognized strings in IDAPRO, including both Unicode and ASCII strings.
   
2. **ModifyFunctionForString** and **ModifyFunctionNameForStringX64** are one-click function renaming plugins for Delphi 32-bit and 64-bit versions.
   
3. **ClassExtractorForDelphi** and **DelphiClassExtractorX64** are plugins for Delphi 32-bit and 64-bit versions that automatically analyze Delphi’s RTTI data types. These plugins allow you to easily create Structs, Classes, and Enum data types in IDAPRO.

# IDAPRO Delphi 插件集合

这是一个针对 Delphi 的 IDAPRO 插件集合，后期将会进行更新。

## 注意事项

1. 这是一个 IDAPRO 针对 Delphi 的插件集合，后期还会进行更新。
2. 每个插件都有两个版本，一个针对 32 位 Delphi 程序，一个针对 64 位 Delphi 程序。
3. **使用插件时一定一定一定要用 IDAPRO 文件的副本**，以免造成 IDAPRO 数据库彻底崩溃。
4. 开发者应根据自身情况调整插件源码，不要直接使用。
5. 请按照以下顺序执行插件：
   - **AnalysisString**
   - **ModifyFunctionForString**
   - **ClassExtractorForDelphi**

   **执行顺序:** `AnalysisString -> ModifyFunctionForString -> ClassExtractorForDelphi`

## 项目描述

1. **AnalysisString** 和 **AnalysisStringX64** 是针对于 Delphi 32 位版本和 64 位版本的解析字符串插件。该插件用于分析 IDAPRO 中未能识别的字符串，包括 Unicode 和 ASCII 字符串。
2. **ModifyFunctionForString** 和 **ModifyFunctionNameForStringX64** 是针对于 Delphi 32 位版本和 64 位版本的函数一键命名插件。
3. **ClassExtractorForDelphi** 和 **DelphiClassExtractorX64** 是针对于 Delphi 32 位版本和 64 位版本的插件，用来自动分析 Delphi 中的 RTTI 数据类型，可以在 IDAPRO 中一键创建 Struct、Class 和 Enum 类型的数据。
