#include "DelphiClassAnalyzerX64.h"
// 插件描述
static const char PLUGIN_COMMENT[] = "A plugin to Analyzer Delphi program";
static const char PLUGIN_NAME[] = "DelphiAnalyzerX64";
static const char PLUGIN_HOTKEY[] = "Ctrl-Alt-L";

bool CDelphiClassAnalyzerX64::analyzeProgram() {
	uint64 g_bChooseCode = ask_yn(ASKBTN_YES, "Whether to create a Class?");
	if (g_bChooseCode == ASKBTN_YES)
	{
		show_wait_box("Creating Class!");
		extractClassInfo();
		analyzeParentClass();
		createClassStructs();
		hide_wait_box();
	}
	g_bChooseCode= ask_yn(ASKBTN_YES, "Whether to create a Struct?");
	if (g_bChooseCode == ASKBTN_YES)
	{
		show_wait_box("Creating Strcut!");
		extractRecordInfo();
		createRecordStructs();
		hide_wait_box();
	}
	g_bChooseCode = ask_yn(ASKBTN_YES, "Whether to create a Enum?");
	if (g_bChooseCode == ASKBTN_YES)
	{
		show_wait_box("Creating Enum!");
		extractEnumerationInfo();
		createEnumeration();
		hide_wait_box();
	}
	return true;
}

void CDelphiClassAnalyzerX64::getVMTAddrs() {
	segment_t* textSeg = getnseg(0);
	ea_t textSegStartAddr = textSeg->start_ea;
	ea_t textSegEndAddr = textSeg->end_ea;
	std::map<qstring, int> classNameMap;
	for (ea_t i = textSegStartAddr; i < textSegEndAddr; i++) 
	{
		if (get_qword(i) == i + 8 && get_byte(i + 8) == 0x07) 
		{
			int8 classNameLen = get_byte(i + 8 + 1);
			if (classNameLen > 60) {
				msg("class name length is too long: 0x%X\n", classNameLen);
				msg("class_addr: 0x%X\n", i);
				continue;
			}
			char className[128] = { 0 };

			get_bytes(className, classNameLen, i + 8 + 2);
			qstring clsName(className);
			if (classNameMap.find(clsName) != classNameMap.end()) {
				classNameMap[clsName]++;
				clsName.sprnt("%s_%d", className, classNameMap[clsName]);
			}
			else {
				classNameMap[clsName] = 0;
			}
			m_classNames.push_back(clsName);
			m_VMTAddrs.push_back(get_qword(i + 8 + 2 + classNameLen));
		}
	}

	int index = 0;
	for (int i = 0; i < m_VMTAddrs.size(); i++) {
		m_VMTAddrs.at(i) -= 0xC8; //-0x58
		//msg("Address %X\n", m_VMTAddrs.at(i));
	}
}

bool CDelphiClassAnalyzerX64::extractClassInfo() {
	getVMTAddrs();
 	int index = 0;
 	for (int i = 0; i < m_VMTAddrs.size(); i++) 
	{
 		DelphiVMT vmt;
 		vmt.VMTAddr = m_VMTAddrs.at(i);
 		vmt.index = index;
 		index++;
 		if (analyzeVMT(vmt)) {
 			analyzeFields(vmt);
 			analyzeTypeSize(vmt);
 			analyzeVirtualMethods(vmt);
 			analyzeCustomMethods(vmt);
 			m_VMTMap[vmt.VMTAddr] = vmt;
 		}
 	}
 	return true;
}

bool CDelphiClassAnalyzerX64::analyzeVMT(DelphiVMT& vmt) {
	try {
		vmt.className = m_classNames.at(vmt.index);
		vmt.fieldsStartAddr = get_qword(vmt.VMTAddr + 0x28);//0x14
		vmt.customMethodsStartAddr = get_qword(vmt.VMTAddr + 0x30);//0x18
		vmt.classSize = get_qword(vmt.VMTAddr + 0x48);//0X24
		vmt.parentVMT = get_dword(vmt.VMTAddr + 0x50);//0x28
		return true;
	}
	catch (std::exception& e) {
		msg("extract class info failed: 0x%X\n", vmt.VMTAddr);
		return false;
	}
}

bool CDelphiClassAnalyzerX64::extractRecordInfo() {
	segment_t* textSeg = getnseg(0);
	ea_t textSegStartAddr = textSeg->start_ea;
	ea_t textSegEndAddr = textSeg->end_ea;
	std::map<qstring, int> recordNameMap;
	for (ea_t i = textSegStartAddr; i < textSegEndAddr; i++) 
	{
		if (get_qword(i) == i + 8 && get_byte(i + 8) == 0x0E) 
		{
			DelphiRecord record;
			record.recordAddr = i;
			int8 recordNameLen = get_byte(i + 9);
			if (recordNameLen > 60) {
				msg("record name length is too long: 0x%X\n", recordNameLen);
				msg("record_addr: 0x%X\n", i);
				continue;
			}
			char recordName[128] = { 0 };

			get_bytes(recordName, recordNameLen, i + 8 + 2);
			qstring recordNameStr(recordName);
			if (recordNameMap.find(recordNameStr) != recordNameMap.end()) 
			{
				recordNameMap[recordNameStr]++;
				recordNameStr.sprnt("%s_%d", recordName, recordNameMap[recordNameStr]);
			}
			else {
				recordNameMap[recordNameStr] = 0;
			}
			record.recordName = recordNameStr;
			record.recordSize = get_dword(i + 0x8 + 0x2 + recordNameLen);
			int len = get_dword(i + 0x8 + 0x2 + recordNameLen + 0x4);
			analyzeRecordFields(i + 0x8 + 0x2 + recordNameLen + 0x9 + len * 0x10, record);
			analyzeRecordTypeSize(record);
			//msg("find record: %s, record_addr: 0x%X\n", record.recordName.c_str(), record.recordAddr);
			//for (const auto& field : record.fields) {
			//	msg("field: %s, type: %s, type_addr: 0x%X, offset: %d, addr: 0x%X\n",
			//		field.fieldName.c_str(), field.type.c_str(), field.typeAddr, field.offset, field.addr);
			//}
			//msg("\n\n");
			m_Records.push_back(record);
		}
	}
	return false;
}
bool CDelphiClassAnalyzerX64::extractEnumerationInfo() {
	segment_t* textSeg = getnseg(0);
	ea_t textSegStartAddr = textSeg->start_ea;
	ea_t textSegEndAddr = textSeg->end_ea;
	std::map<qstring, int> enumNameMap;
	for (ea_t i = textSegStartAddr; i < textSegEndAddr; i++) {
		if (get_qword(i) == i + 8 && get_byte(i + 8) == 0x03) {
			DelphiEnumeration enumration;
			enumration.enumAddr = i;
			int8 enumNameLen = get_byte(i + 8 + 1);
			if (enumNameLen > 30) {
				msg("enum name length is too long: 0x%X\n", enumNameLen);
				msg("enum_addr: 0x%X\n", i);
				continue;
			}
			char enumName[128] = { 0 };

			get_bytes(enumName, enumNameLen, i + 8 + 1 + 1);
			qstring enumNameStr(enumName);
			if (enumNameMap.find(enumNameStr) != enumNameMap.end()) {
				enumNameMap[enumNameStr]++;
				enumNameStr.sprnt("%s_%d", enumName, enumNameMap[enumNameStr]);
			}
			else {
				enumNameMap[enumNameStr] = 0;
			}
			enumration.enumName = enumNameStr;
			int enumStartValue = get_dword(i + 8 + 1 + 1 + enumNameLen + 0x1);
			int enumEndValue = get_dword(i + 8 + 1 + 1 + enumNameLen + 0x1 + 0x4);
			ea_t enumAddr = i + 0x8 + 0x1 + 0x1 + enumNameLen + 0x1 + 0x8 + 0x8;
			for (int j = 0; j < enumEndValue - enumStartValue + 1; j++) {
				int EnumValueLen = get_byte(enumAddr);
				char EnumValueArr[128] = { 0 };
				get_bytes(EnumValueArr, EnumValueLen, enumAddr + 0x1);
				qstring EnumValueStr(EnumValueArr);
				enumAddr += 0x1 + EnumValueLen;
				enumration.enumItems.push_back(EnumValueStr);
			}
			m_Enumerations.push_back(enumration);
		}
	}
	return false;
}
bool CDelphiClassAnalyzerX64::addParentFiels() {
	for (auto& vmtMapItem : m_VMTMap) {
		ea_t parentVMT = vmtMapItem.second.parentVMT;
		if (parentVMT == 0x00000000) {
			continue;
		}
		if (m_VMTMap.find(parentVMT) == m_VMTMap.end()) {
			continue;
		}
		auto& parentVMTInfo = m_VMTMap.at(parentVMT);
		for (const auto& field : parentVMTInfo.fields) {
			vmtMapItem.second.fields.push_back(field);
		}
	}
	return true;
}

bool CDelphiClassAnalyzerX64::analyzeParentClass() {
	for (auto& vmtMapItem : m_VMTMap) {
		ea_t parentVMT = vmtMapItem.second.parentVMT;
		if (parentVMT == 0x00000000) {
			msg("class %s has no parent class, class_addr: 0x%X\n", vmtMapItem.second.className.c_str(), vmtMapItem.second.VMTAddr);
			vmtMapItem.second.parentClassName = "TObject";
			continue;
		}
		if (m_VMTMap.find(parentVMT) == m_VMTMap.end()) {
			//msg("parent class of class %s not found, class_addr: 0x%X, parent_addr: 0x%X\n", vmtMapItem.second.className.c_str(), vmtMapItem.second.VMTAddr, parentVMT);
			qstring parentClassName;
			get_name(&parentClassName, parentVMT);
			vmtMapItem.second.parentClassName = parentClassName;
			continue;
		}
		vmtMapItem.second.parentClassName = m_VMTMap.at(parentVMT).className;
	}
	return true;
}
bool CDelphiClassAnalyzerX64::analyzeRecordFields(ea_t firstFieldAddr, DelphiRecord& record) {
	uint16 fieldCount = get_word(firstFieldAddr);
	ea_t fieldAddr = firstFieldAddr + 0x4;//变量个数
	for (int i = 0; i < fieldCount; i++) {
		FieldInfo field;
		field.addr = fieldAddr;
		field.typeAddr = get_qword(fieldAddr);
		analyzeTypeInfo(field.typeAddr, field.type);
		field.offset = get_word(fieldAddr + 0x8);
		int fieldNameLen = get_byte(fieldAddr + +0x8 + 0x9);
		if (fieldNameLen > 30) {
			msg("field name length is too long: 0x%X\n", fieldNameLen);
			msg("field_addr: 0x%X\n", fieldAddr);
			fieldAddr += 0x8 + 0x9 + 0x1 + fieldNameLen + 0x2;
			continue;
		}
		char fieldNameArr[128] = { 0 };
		get_bytes(fieldNameArr, fieldNameLen, fieldAddr + 0x10 + 0x2);
		field.fieldName = fieldNameArr;
		record.fields.push_back(field);
		fieldAddr += 0x8 + 0x9 + 0x1 + fieldNameLen + 0x2;
	}
	return true;
}
bool CDelphiClassAnalyzerX64::analyzeFields(DelphiVMT& vmt) {
	if (vmt.fieldsStartAddr == 0) //有可能类没有区域
	{
		return true;
	}
	uint16 flag = get_word(vmt.fieldsStartAddr);
	ea_t fieldStartAddr;
	if (flag != 0x0000) //不等于00的情况直接标了字段数量
	{
		vmt.fieldCount = flag;
		fieldStartAddr = vmt.fieldsStartAddr + 0xA;//0xA
		for (int i = 0; i < vmt.fieldCount; i++) 
		{
			fieldStartAddr += 0x6;
			int fieldNameLen = get_byte(fieldStartAddr);
			fieldStartAddr += 0x1 + fieldNameLen;
		}
		fieldStartAddr += 0x2;
	}
	else { 
		vmt.fieldCount = get_word(vmt.fieldsStartAddr + 0x6 +0x4);
		fieldStartAddr = vmt.fieldsStartAddr + 0x8 +0x4;//0开头
	}
	for (int i = 0; i < vmt.fieldCount; i++) {
		FieldInfo fieldInfo;
		fieldInfo.addr = fieldStartAddr;
		fieldInfo.typeAddr = get_qword(fieldInfo.addr + 0x1);//这里改成QWORD，获得变量的类型
		analyzeTypeInfo(fieldInfo.typeAddr, fieldInfo.type);
		fieldInfo.offset = get_word(fieldInfo.addr + 0x5 +0x4);//这里也要改,这里是变量在类中的偏移
		int8 fieldNameLen = get_byte(fieldInfo.addr + 0x9 +0X4);//这里是变量的名称长度
		char fieldNameArr[128] = { 0 };
		if (fieldNameLen > 40) {
			msg("field name length is too long: 0x%X\n", fieldNameLen);
			msg("field_addr: 0x%X\n", fieldInfo.addr);
			fieldStartAddr = fieldInfo.addr + 0xA + fieldNameLen + 0x2 +0x4;//变量偏移通通加4
			continue;
		}
		get_bytes(fieldNameArr, fieldNameLen, fieldInfo.addr + 0xA +0x4);//这里也要改
		fieldInfo.fieldName = fieldNameArr;
		vmt.fields.push_back(fieldInfo);
		fieldStartAddr = fieldInfo.addr + 0xE + fieldNameLen + 0x2;
	}
	return true;
}

bool CDelphiClassAnalyzerX64::analyzeTypeInfo(ea_t typeAddr, qstring& typeName) {
	// 检查是否是基本类型（通过检查段名）
	if (typeAddr == 0) {
		typeName = "void";
		return true;
	}
	segment_t* seg = getseg(typeAddr);
	if (!seg) {
		typeName.sprnt("Unknown_0x%X", typeAddr);
		return false;
	}

	qstring segName;
	get_segm_name(&segName, seg);

	// 如果在.idata段，可能是基本类型
	if (segName == ".idata") {
		// 获取符号名称
		qstring name;
		if (get_name(&name, typeAddr)) {
			// 检查是否是Delphi类型符号（以@$xp$开头）
			// 检查常见的Delphi类型标识
			if (name.find("_Z") != qstring::npos) 
			{
				if (name.find("Integer") != qstring::npos) {
					typeName = "int";
					return true;
				}
				if (name.find("Cardinal") != qstring::npos) {
					typeName = "DWORD";
					return true;
				}
				if (name.find("Shortint") != qstring::npos) {
					typeName = "char";
					return true;
				}
				if (name.find("Smallint") != qstring::npos) {
					typeName = "short";
					return true;
				}
				if (name.find("Longint") != qstring::npos) {
					typeName = "_int32";
					return true;
				}
				if (name.find("Int64") != qstring::npos) {
					typeName = "_int64";
					return true;
				}
				if (name.find("Byte") != qstring::npos) {
					typeName = "BYTE";
					return true;
				}
				if (name.find("Word") != qstring::npos) {
					typeName = "WORD";
					return true;
				}
				if (name.find("Longword") != qstring::npos) {
					typeName = "DWORD";
					return true;
				}
				if (name.find("Longword") != qstring::npos) {
					typeName = "DWORD";
					return true;
				}
				if (name.find("AnsiChar") != qstring::npos) {
					typeName = "char";
					return true;
				}
				if (name.find("WideChar") != qstring::npos) {
					typeName = "WCHAR";
					return true;
				}
				if (name.find("Boolean") != qstring::npos) {
					typeName = "BOOL_1bytes";
					return true;
				}
				if (name.find("ByteBool") != qstring::npos) {
					typeName = "BOOL_1bytes";
					return true;
				}
				if (name.find("WordBool") != qstring::npos) {
					typeName = "BOOL_2bytes";
					return true;
				}
				if (name.find("LongBool") != qstring::npos) {
					typeName = "BOOL_4bytes";
					return true;
				}
				if (name.find("Real") != qstring::npos) {
					typeName = "Float_8bytes_plus";
					return true;
				}
				if (name.find("Real48") != qstring::npos) {
					typeName = "Float_6bytes_plus";
					return true;
				}
				if (name.find("Single") != qstring::npos) {
					typeName = "Float_4bytes_plus";
					return true;
				}
				if (name.find("Double") != qstring::npos) {
					typeName = "Float_8bytes_plus";
					return true;
				}
				if (name.find("Extended") != qstring::npos) {
					typeName = "Float_10bytes_plus";
					return true;
				}
				if (name.find("Comp") != qstring::npos) {
					typeName = "Float_10bytes_minus";
					return true;
				}
				if (name.find("Currency") != qstring::npos) {
					typeName = "Float_8bytes_minus";
					return true;
				}
				if (name.find("ShortString") != qstring::npos) {
					typeName = "BOOL_4bytes";
					return true;
				}
				if (name.find("AnsiString") != qstring::npos) {
					typeName = "AnsiString";
					return true;
				}
				if (name.find("WideString") != qstring::npos) {
					typeName = "WideString";
					return true;
				}
			}
		}

		// 如果没有找到匹配的类型，检查符号引用
		xrefblk_t xref;
		for (bool ok = xref.first_to(typeAddr, XREF_DATA); ok; ok = xref.next_to()) {
			qstring refName;
			if (get_name(&refName, xref.from)) {
				if (refName.find("Boolean") != qstring::npos) {
					typeName = "Boolean";
					return true;
				}
				if (refName.find("Integer") != qstring::npos) {
					typeName = "Integer";
					return true;
				}
				if (refName.find("string") != qstring::npos) {
					typeName = "string";
					return true;
				}
			}
		}
	}

	// 如果在.text段，可能是自定义类型
	if (segName == ".text") {
		uint64 magic = get_qword(typeAddr);//
		if (magic == typeAddr + 4) 
		{  // 检查特征：指向自身+8的指针
			uint8 typeKind = get_byte(typeAddr + 8);//kindtype
			int8 classNameLen = get_byte(typeAddr + 5 + 4);//类名的长度

			if (classNameLen > 0 && classNameLen < 128) 
			{
				char typeBuf[128] = { 0 };
				get_bytes(typeBuf, classNameLen, typeAddr + 6 + 4);//获取类名
				switch (typeKind) {
				case 0x03:  // Enum
					typeName.sprnt("Enum_%s", typeBuf);
					return true;
				case 0x06:  // Set
					typeName.sprnt("Set_%s", typeBuf);
					return true;
				case 0x07:  // Class
					typeName = typeBuf;
					return true;
				case 0x08:  // Method
					typeName.sprnt("Method_%s", typeBuf);
					return true;
				case 0x0C:  // Variant
					typeName.sprnt("Variant_%s", typeBuf);
					return true;
				case 0x0D:  // Array
					typeName.sprnt("Array_%s", typeBuf);
					return true;
				case 0x0E:  // Record
					typeName.sprnt("Record_%s", typeBuf);
					return true;
				case 0x0F:  // Interface
					typeName.sprnt("Interface_%s", typeBuf);
					return true;
				default:
					typeName.sprnt("Type_%02X_%s", typeKind, typeBuf);
					return true;
				}
			}
			else 
			{
				typeName.sprnt("Invalid_Name_Len_%d", classNameLen);
				return false;
			}
		}
		else {
			// 尝试获取引用的类型信息
			ea_t refAddr = get_qword(typeAddr);
			if (is_loaded(refAddr)) {
				return analyzeTypeInfo(refAddr, typeName);
			}
		}
	}

	// 如果无法识别类型，返回地址作为类型名
	if (typeName.empty()) {
		get_name(&typeName, typeAddr);
	}
	return false;
}

bool CDelphiClassAnalyzerX64::analyzeTypeSize(DelphiVMT& vmt) {
	for (int i = vmt.fields.size() - 2; i >= 0; i--) {
		vmt.fields.at(i).size = vmt.fields.at(i + 1).offset - vmt.fields.at(i).offset;
	}
	return true;
}

bool CDelphiClassAnalyzerX64::analyzeRecordTypeSize(DelphiRecord& record) {
	for (int i = record.fields.size() - 2; i >= 0; i--) {
		record.fields.at(i).size = record.fields.at(i + 1).offset - record.fields.at(i).offset;
	}
	return true;
}

bool CDelphiClassAnalyzerX64::createClassStructs() {
	for (const auto& vmtMapItem : m_VMTMap) {
		const auto& vmt = vmtMapItem.second;
		// 创建结构体名称
		qstring structName;
		structName.sprnt("S_%s", vmt.className.c_str());

		// 删除已存在的结构体
		tid_t sid = get_struc_id(structName.c_str());
		if (sid != BADADDR) {
			struc_t* sptr = get_struc(sid);
			if (sptr != nullptr) {
				// 先删除所有成员
				while (get_struc_first_offset(sptr) != BADADDR) {
					if (!del_struc_member(sptr, get_struc_first_offset(sptr))) {
						msg("Warning: Failed to delete member in structure %s\n", structName.c_str());
					}
				}
				// 再删除结构体
				if (!del_struc(sptr)) {
					msg("Warning: Failed to delete structure %s\n", structName.c_str());
					continue; // 如果删除失败，跳过这个结构体
				}
			}
		}

		// 创建新的结构体
		sid = add_struc(-1, structName.c_str());
		if (sid == BADADDR) {
			msg("Failed to create structure %s\n", structName.c_str());
			continue;
		}
		struc_t* sptr = get_struc(sid);
		if (sptr == nullptr) {
			msg("Failed to get structure pointer for %s\n", structName.c_str());
			continue;
		}

		// 添加VMT基本信息作为注释
		qstring comment;
		comment.sprnt("Class: %s\nParent Class: %s\nClass Size: %d bytes\n",
			vmt.className.c_str(),
			vmt.parentClassName.c_str(),
			vmt.classSize);
		set_struc_cmt(sid, comment.c_str(), false);

		// 添加字段
		for (const auto& field : vmt.fields) {
			// 获取字段类型信息
			qstring fieldTypeName;
			if (field.typeAddr != BADADDR) {
				analyzeTypeInfo(field.typeAddr, fieldTypeName);
			}
			else {
				fieldTypeName = field.type;
			}

			// 创建字段注释
			qstring fieldComment;
			fieldComment.sprnt("Offset: 0x%X\nType: %s\n",
				field.offset,
				fieldTypeName.c_str());

			// 添加字段到结构体，检查是否成功
			if (add_struc_member(sptr, field.fieldName.c_str(), field.offset,
				getFlags(field.size), nullptr, field.size) != 0) {
				msg("Warning: Failed to add member %s to structure %s\n",
					field.fieldName.c_str(), structName.c_str());
				continue;
			}

			// 获取成员并设置注释
			member_t* member = get_member(sptr, field.offset);
			if (member != nullptr) {
				set_member_cmt(member, fieldComment.c_str(), true);
			}
		}

		// 添加自定义方法信息
		if (!vmt.customMethods.empty()) {
			qstring methodComment;
			methodComment.sprnt("\nCustom Methods:\n");
			for (const auto& method : vmt.customMethods) {
				methodComment.cat_sprnt("\n\t %s  %s (",
					method.returnType.c_str(),
					method.customMethodName.c_str());
				bool hasParam = false;
				for (const auto& param : method.params) {
					methodComment.cat_sprnt("%s %s, ",
						param.paramTypeName.c_str(),
						param.paramName.c_str());
					hasParam = true;
				}
				if (hasParam) {
					//去掉最后一个逗号
					int lastCo = methodComment.rfind(',');
					if (lastCo != qstring::npos) {
						methodComment.remove(lastCo, 1);
					}
				}
				methodComment.cat_sprnt(")\n");
			}
			// 添加到结构体注释
			qstring existingCmt;
			get_struc_cmt(&existingCmt, sid, false);
			existingCmt.append(methodComment);
			set_struc_cmt(sid, existingCmt.c_str(), false);
		}
		createVTables(vmt);
	}
	return true;
}

bool CDelphiClassAnalyzerX64::createRecordStructs() {
	for (const auto& record : m_Records) {
		// 创建结构体名称
		qstring structName;
		structName.sprnt("R_%s", record.recordName.c_str());

		// 删除已存在的结构体
		tid_t sid = get_struc_id(structName.c_str());
		if (sid != BADADDR) {
			struc_t* sptr = get_struc(sid);
			if (sptr != nullptr) {
				// 先删除所有成员
				while (get_struc_first_offset(sptr) != BADADDR) {
					if (!del_struc_member(sptr, get_struc_first_offset(sptr))) {
						msg("Warning: Failed to delete member in structure %s\n", structName.c_str());
					}
				}
				// 再删除结构体
				if (!del_struc(sptr)) {
					msg("Warning: Failed to delete structure %s\n", structName.c_str());
					continue; // 如果删除失败，跳过这个结构体
				}
			}
		}

		// 创建新的结构体
		sid = add_struc(-1, structName.c_str());
		if (sid == BADADDR) {
			msg("Failed to create structure %s\n", structName.c_str());
			continue;
		}
		struc_t* sptr = get_struc(sid);
		if (sptr == nullptr) {
			msg("Failed to get structure pointer for %s\n", structName.c_str());
			continue;
		}

		// 添加Record基本信息作为注释
		qstring comment;
		comment.sprnt("Record: %s\nRecord Address: 0x%X\nRecord Size: %d bytes\n",
			record.recordName.c_str(),
			record.recordAddr,
			record.recordSize);
		set_struc_cmt(sid, comment.c_str(), false);

		// 添加字段
		for (const auto& field : record.fields) {
			// 创建字段注释
			qstring fieldComment;
			fieldComment.sprnt("Offset: 0x%X\nType: %s\n",
				field.offset,
				field.type.c_str());

			// 添加字段到结构体，检查是否成功
			if (add_struc_member(sptr, field.fieldName.c_str(), field.offset,
				getFlags(field.size), nullptr, field.size) != 0) {
				msg("Warning: Failed to add member %s to structure %s, Offset: 0x%X, Type: %s, please check the Record at 0x%X.\n",
					field.fieldName.c_str(), structName.c_str(), field.offset, field.type.c_str(), record.recordAddr);
				continue;
			}

			// 获取成员并设置注释
			member_t* member = get_member(sptr, field.offset);
			if (member != nullptr) {
				set_member_cmt(member, fieldComment.c_str(), true);
			}
		}
	}
	return true;
}

#define ENUM_FLAGS_8BIT    0x00000008  // 8位枚举
#define ENUM_FLAGS_16BIT   0x00000010  // 16位枚举
#define ENUM_FLAGS_32BIT   0x00000018  // 32位枚举
#define ENUM_FLAGS_64BIT   0x00000020  // 64位枚举

bool CDelphiClassAnalyzerX64::createEnumeration() {
	for (const auto& enumeration : m_Enumerations) {
		// 创建枚举名称
		qstring enumName;
		enumName.sprnt("E_%s", enumeration.enumName.c_str());

		// 删除已存在的枚举
		enum_t existingId = get_enum(enumName.c_str());
		if (existingId != BADADDR) {
			del_enum(existingId);
		}

		// 设置枚举标志
		flags64_t enumFlags = 0;

		// 根据枚举项的数量选择合适的位宽
		int maxValue = enumeration.enumItems.size() - 1;
		if (maxValue <= 0xFF) {
			enumFlags |= ENUM_FLAGS_8BIT;  // 8位足够
		}
		else if (maxValue <= 0xFFFF) {
			enumFlags |= ENUM_FLAGS_16BIT;  // 需要16位
		}
		else if (maxValue <= 0xFFFFFFFF) {
			enumFlags |= ENUM_FLAGS_32BIT;  // 需要32位
		}
		else {
			enumFlags |= ENUM_FLAGS_64BIT;  // 需要64位
		}

		// 创建新的枚举
		enum_t enumId = add_enum(-1, enumName.c_str(), enumFlags);
		if (enumId == BADADDR) {
			msg("Failed to create enumeration %s\n", enumName.c_str());
			continue;
		}

		// 添加枚举成员
		int value = 0;
		for (const auto& item : enumeration.enumItems) {
			// 处理可能的命名冲突
			qstring itemName = item;
			itemName.replace(" ", "_");  // 替换空格为下划线
			itemName.replace("-", "_");  // 替换横杠为下划线
			itemName.replace(":", "_");  // 替换冒号为下划线
			itemName.replace(";", "_");  // 替换分号为下划线
			itemName.replace(",", "_");  // 替换逗号为下划线

			// 如果名称已存在，添加数字后缀
			int suffix = 1;
			qstring uniqueName = itemName;
			while (get_enum_member_by_name(uniqueName.c_str()) != BADADDR) {
				uniqueName.sprnt("%s_%d", itemName.c_str(), suffix++);
			}

			// 添加枚举成员
			if (add_enum_member(enumId, uniqueName.c_str(), value, DEFMASK) != 0) {
				msg("Warning: Failed to add enum member %s to enumeration %s\n",
					uniqueName.c_str(), enumName.c_str());
			}
			value++;
		}
	}
	return true;
}

bool CDelphiClassAnalyzerX64::createVTables(const DelphiVMT& vmt) {
	// 创建结构体名称
	qstring structName;
	structName.sprnt("V_%s", vmt.className.c_str());

	// 删除已存在的结构体
	tid_t sid = get_struc_id(structName.c_str());
	if (sid != BADADDR) {
		struc_t* sptr = get_struc(sid);
		if (sptr != nullptr) {
			// 先删除所有成员
			while (get_struc_first_offset(sptr) != BADADDR) {
				if (!del_struc_member(sptr, get_struc_first_offset(sptr))) {
					msg("Warning: Failed to delete member in structure %s\n", structName.c_str());
					break;
				}
			}
			// 再删除结构体
			if (!del_struc(sptr)) {
				msg("Warning: Failed to delete structure %s\n", structName.c_str());
				return false;
			}
		}
	}

	// 创建新的结构体
	sid = add_struc(-1, structName.c_str(), false);
	if (sid == BADADDR) {
		msg("Failed to create structure %s\n", structName.c_str());
		return false;
	}
	struc_t* sptr = get_struc(sid);
	if (sptr == nullptr) {
		msg("Failed to get structure pointer for %s\n", structName.c_str());
		false;
	}

	// 设置结构体注释
	qstring comment;
	comment.sprnt("Virtual Method Table for %s\nVMT Address: 0x%X\nParent VMT: 0x%X\nClass Size: %d bytes\n",
		vmt.className.c_str(),
		vmt.VMTAddr,
		vmt.parentVMT,
		vmt.classSize);
	set_struc_cmt(sid, comment.c_str(), false);

	// 用于跟踪已使用的名称
	std::set<qstring> usedNames;

	// 添加虚函数表成员
	asize_t offset = 0;
	int methodIndex = 0;
	for (const auto& virtualMethod : vmt.virtulMethods) {
		// 处理方法名称
		qstring methodName = virtualMethod.virtulMethodName;

		// 替换不合法字符
		methodName.replace("$", "_");
		methodName.replace("@", "_");
		methodName.replace(" ", "_");
		methodName.replace(":", "_");

		// 如果名称为空或只包含特殊字符，使用索引生成名称
		if (methodName.empty() || methodName == "_") {
			methodName.sprnt("vmethod_%d", methodIndex);
		}

		// 处理重复名称
		qstring uniqueName = methodName;
		int suffix = 1;
		while (usedNames.find(uniqueName) != usedNames.end()) {
			uniqueName.sprnt("%s_%d", methodName.c_str(), suffix++);
		}
		usedNames.insert(uniqueName);

		// 添加字段到结构体
		if (add_struc_member(sptr, uniqueName.c_str(), offset,
			dword_flag(), nullptr, 4) != 0) {
			msg("Warning: Failed to add virtual method %s (renamed to %s) to structure %s\n",
				virtualMethod.virtulMethodName.c_str(), uniqueName.c_str(), structName.c_str());
			continue;
		}

		offset += 4;
		methodIndex++;
	}
	return true;
}

bool CDelphiClassAnalyzerX64::analyzeVirtualMethods(DelphiVMT& vmt) {
	ea_t virtualMethodStartAddr = get_qword(vmt.VMTAddr);   //vmt.VMTAddr + 0x58;
	ea_t pointMethodAddr = virtualMethodStartAddr;
	int sameMethodCount = 2;
	while (is_loaded(get_qword(pointMethodAddr))) //这里也要改
	{
		VirtulMethodInfo virutalMethod;
		ea_t methodAddr = get_qword(pointMethodAddr);//改成qword
		virutalMethod.addr = methodAddr;

		// 获取方法名称
		qstring methodName;
		if (get_name(&methodName, methodAddr)) 
		{
			// 检查是否是自动生成的名称
			if (methodName.find("sub_") == 0 || methodName.find("loc_") == 0) 
			{
				virutalMethod.virtulMethodName.sprnt("virfunc_%d", index++);
			}
			/*else
			{
				// 处理Delphi方法名
				size_t dollarPos = methodName.find("$qqr");
				if (dollarPos != qstring::npos) 
				{
					// 获取$qqr之前的完整名称
					qstring fullName = methodName.substr(0, dollarPos);

					// 找到最后一个@的位置
					size_t lastAtPos = fullName.rfind('@');
					if (lastAtPos != qstring::npos) {
						// 取最后一个@之后的部分作为方法名
						virutalMethod.virtulMethodName = fullName.substr(lastAtPos + 1);
					}
					else {
						// 如果没有@，使用整个名称
						virutalMethod.virtulMethodName = fullName;
					}
				}
				else 
				{
					// 如果之前已经处理过，使用处理过的名称去后缀加数字
					qstring temp;
					temp.sprnt("_%s", vmt.className.c_str());
					size_t tempPos = methodName.find(temp);
					if (tempPos != qstring::npos) {
						qstring fullName = methodName.substr(0, tempPos);
						methodName.sprnt("%s_%d", fullName.c_str(), sameMethodCount++);
						virutalMethod.virtulMethodName = methodName;
						pointMethodAddr += 4;
						vmt.virtulMethods.push_back(virutalMethod);
						continue;
					}
					else 
					{
						virutalMethod.virtulMethodName = methodName;
					}
				}
			}*/

			// 如果提取出的方法名为空，使用原始名称
			if (virutalMethod.virtulMethodName.empty()) {
				virutalMethod.virtulMethodName = methodName;
			}
		}

		// 重命名方法
		/*qstring reNameMethodName;
		reNameMethodName.sprnt("%s_%s", virutalMethod.virtulMethodName.c_str(), vmt.className.c_str());
		reNameMethodName.replace("$", "_");
		reNameMethodName.replace("@", "_");
		reNameMethodName.replace(" ", "_");
		reNameMethodName.replace(":", "_");*/

		// 检查名称是否已存在，如果存在则添加数字后缀
		//todo 名字过长，因为有很多重写
		/*int suffix = 1;
		qstring uniqueName = reNameMethodName;
		while (get_name_ea(BADADDR, uniqueName.c_str()) != BADADDR) {
			qstring temp;
			temp.sprnt("_%s", vmt.className.c_str());
			size_t tempPos = reNameMethodName.find(temp);
			if (tempPos != qstring::npos) {
				qstring fullName = reNameMethodName.substr(0, tempPos);
				uniqueName.sprnt("%s_%d_%s", fullName.c_str(), suffix++, vmt.className.c_str());
			}
			else {
				msg("Warning: Method name %s already exists, adding suffix %d\n");
			}
		}*/

		// 使用唯一的名称进行重命名
		if (set_name(methodAddr, virutalMethod.virtulMethodName.c_str(), SN_CHECK) != 1) {
			msg("Warning: Failed to rename method at 0x%X to %s\n", methodAddr, virutalMethod.virtulMethodName.c_str());
		}

		pointMethodAddr += 8;
		vmt.virtulMethods.push_back(virutalMethod);
	}
	return true;
}

bool CDelphiClassAnalyzerX64::analyzeCustomMethods(DelphiVMT& vmt) {//类自己的函数
	ea_t customMethodStartAddr = vmt.customMethodsStartAddr;//+0x30
	if (customMethodStartAddr == 0) {
		msg("class_name: %s, class_addr: 0x%X, \n", vmt.className.c_str(), vmt.VMTAddr);
		msg("!custom method start address is invalid: 0x%X\n\n", customMethodStartAddr);
		return true;
	}
	uint16 flag = get_word(customMethodStartAddr);
	ea_t customMethodAddr;
	int customMethodCount;
	if (flag != 0x0000) 
	{
		customMethodStartAddr += 0x2;
		for (int i = 0; i < flag; i++) 
		{
			customMethodStartAddr += 0x2 +0x8;
			int customMethodNameLen = get_byte(customMethodStartAddr);
			customMethodStartAddr += 0x1;
			customMethodStartAddr += customMethodNameLen;
		}
		customMethodCount = get_word(customMethodStartAddr);
		customMethodAddr = customMethodStartAddr + 0x2;
	}
	else {
		customMethodCount = get_word(customMethodStartAddr + 0x2);
		customMethodAddr = customMethodStartAddr + 0x4;
	}
	//int customMethodIndex = 2;
	std::map<qstring, int> cusMethodMap;
	for (int j = 0; j < customMethodCount; j++) 
	{
		ea_t methodAddr = get_qword(customMethodAddr); //存函数的位置
		CustomMethodInfo customMethodInfo;
		customMethodInfo.addr = get_qword(methodAddr + 0x2); //函数的地址 
		int customMethodNameLen = get_byte(methodAddr + 0x2 +0x8); //函数名称的长度
		if (customMethodNameLen > 50) {
			msg("Warning: Custom method name length is too long: %d\n", customMethodNameLen);
			msg("class_name: %s, class_addr: 0x%X, custom_method_addr: 0x%X, index: %d\n", vmt.className.c_str(), vmt.VMTAddr, customMethodInfo.addr, j);
			continue;
		}
		char customMethodNameArr[128] = { 0 };
		get_bytes(customMethodNameArr, customMethodNameLen, methodAddr + 0x2 + 0x8 + 0x1);//函数的名称
		qstring customMethodName = customMethodNameArr;
		if (cusMethodMap.find(customMethodName) != cusMethodMap.end()) {
			customMethodName.cat_sprnt("_%d", cusMethodMap[customMethodName]++);
		}
		else {
			cusMethodMap[customMethodName] = 1;
		}
		customMethodInfo.customMethodName = customMethodName;
		ea_t returnTypeAddr = get_qword(methodAddr + 0x2 + 0x8 + 0x1 + customMethodNameLen + 0x2);
		analyzeTypeInfo(returnTypeAddr, customMethodInfo.returnType);
		customMethodInfo.returnTypeAddr = returnTypeAddr;
		customMethodInfo.paramCount = get_byte(methodAddr + 0x7 + customMethodNameLen + 0x2 + 0x8 + 0x2);
		ea_t paramAddr = methodAddr + 0x7 + customMethodNameLen + 0x2 + 0x8 + 0x2 + 0x1;
		for (int i = 0; i < customMethodInfo.paramCount; i++) {
			ParamInfo parmInfo;
			parmInfo.paramTypeAddr = get_qword(paramAddr + 0x1);//参数类型
			analyzeTypeInfo(parmInfo.paramTypeAddr, parmInfo.paramTypeName);
			int paramNameLen = get_byte(paramAddr + 0x1 + 0x8 + 0x2);
			if (paramNameLen == 1) {
				parmInfo.paramName.sprnt("parm_%d", i);
				continue;
			}
			char paramNameArr[128] = { 0 };
			if (paramNameLen > 30) {
				msg("Warning: Param name length is too long: %d\n", paramNameLen);
				msg("class_name: %s, class_addr: 0x%X, custom_method_addr: 0x%X, index: %d\n", vmt.className.c_str(), vmt.VMTAddr, customMethodInfo.addr, j);
				break;
			}
			get_bytes(paramNameArr, paramNameLen, paramAddr + 0x1 + 0x8 + 0x2 + 0x1);
			parmInfo.paramName = paramNameArr;
			customMethodInfo.params.push_back(parmInfo);
			paramAddr += 0x8 + 0x4 + paramNameLen + 0x2;
		}
		vmt.customMethods.push_back(customMethodInfo);
		qstring renameMethodName;
		renameMethodName.sprnt("%s_%s", customMethodInfo.customMethodName.c_str(), vmt.className.c_str());
		set_name(customMethodInfo.addr, renameMethodName.c_str());
		customMethodAddr += 8 + 4;
	}

	return true;
}

flags64_t CDelphiClassAnalyzerX64::getFlags(asize_t size) {
	flags64_t flags = 0;

	// 如果大小大于基本类型的最大尺寸，认为是数组或结构体
	if (size > 16) {
		flags = byte_flag();  // 对于大型数据，使用字节数组
		if (size > 1024) {
			msg("Warning: Large field size detected: %d bytes\n", size);
		}
	}
	else {
		// 根据大小选择合适的标志
		switch (size) {
		case 1:
			flags = byte_flag();
			break;
		case 2:
			flags = word_flag();
			break;
		case 4:
			flags = dword_flag();
			break;
		case 8:
			flags = qword_flag();
			break;
		case 16:
			flags = oword_flag();
			break;
		default:
			flags = byte_flag();
			break;
		}
	}

	return flags;
}

void CDelphiClassAnalyzerX64::output() {
	msg("VMT count: %d\n", m_VMTMap.size());
	for (const auto& vmtMapItem : m_VMTMap) {
		const DelphiVMT& vmt = vmtMapItem.second;
		msg("VMT addr: 0x%X\n", vmt.VMTAddr);
		msg("class name: %s\n", vmt.className.c_str());
		msg("parent VMT addr: 0x%X\n", vmt.parentVMT);
		msg("class size: %d\n", vmt.classSize);
		msg("fields start addr: 0x%X\n", vmt.fieldsStartAddr);
		msg("custom methods start addr: 0x%X\n", vmt.customMethodsStartAddr);
		msg("field count: %d\n", vmt.fieldCount);
		msg("fields:\n");
		for (const auto& field : vmt.fields) {
			msg("field name: %s\n", field.fieldName.c_str());
			msg("field offset: %d\n", field.offset);
			msg("field type: %s\n", field.type.c_str());
			msg("field type addr: 0x%X\n", field.typeAddr);
			msg("field size: %d\n", field.size);
			msg("\n");
		}
		msg("\n\n");
	}
}

// 插件加载入口
plugmod_t* idaapi init() {
	msg("DelphiClassAnalyzer Plugin: Initialized.\n");
	return new CDelphiClassAnalyzerX64();
}

bool idaapi CDelphiClassAnalyzerX64::run(size_t) {
	msg("start analyze Delphi class...\n");
	analyzeProgram();

	msg("end analyze Delphi class...\n");
	return true;
}

CDelphiClassAnalyzerX64::CDelphiClassAnalyzerX64()
{
	msg("CopyRight X64:2025/2/18");
}

CDelphiClassAnalyzerX64::~CDelphiClassAnalyzerX64() {
	m_VMTMap.clear(); 
	m_VMTAddrs.clear();
	m_classNames.clear();
	m_Records.clear();
	m_Enumerations.clear();
}

// 插件信息结构
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION, // IDA SDK 版本
	PLUGIN_MULTI,                     // 插件标志
	init,                  // 初始化函数
	nullptr,               // 退出函数
	nullptr,               // 处理消息函数
	PLUGIN_COMMENT,        // 插件描述
	PLUGIN_COMMENT,        // 多行注释
	PLUGIN_NAME,           // 插件名
	PLUGIN_HOTKEY          // 热键
};