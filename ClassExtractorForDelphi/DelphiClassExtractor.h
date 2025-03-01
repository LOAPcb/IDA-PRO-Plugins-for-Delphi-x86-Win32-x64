#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <enum.hpp>

// �ֶ���Ϣ�ṹ
struct FieldInfo {
	ea_t addr;
	qstring fieldName;
	uint16 offset;
	ea_t typeAddr;
	qstring type;
	asize_t size = 4;
};

struct VirtulMethodInfo {
	qstring virtulMethodName;
	ea_t addr;
};

struct ParamInfo {
	ea_t paramTypeAddr;
	qstring paramTypeName;
	qstring paramName;
};

struct CustomMethodInfo {
	ea_t addr;
	ea_t returnTypeAddr;
	qstring returnType;
	qstring customMethodName;
	uint16 paramCount;
	qvector<ParamInfo> params;
};
struct DelphiRecord {
	qstring recordName;
	uint32 recordSize;
	ea_t recordAddr;
	qvector<FieldInfo> fields;
};

struct DelphiEnumeration {
	uint32 enumCount;
	ea_t enumAddr;
	qstring enumName;
	qvector<qstring> enumItems;
};
// Delphi VMT�ṹ
struct DelphiVMT {
	int index; //���
	ea_t VMTAddr; //VMT ��ַ
	ea_t fieldsStartAddr;
	ea_t customMethodsStartAddr;
	qstring className; //����
	ea_t parentVMT; //����VMT��ַ
	qstring parentClassName; //������
	uint32 classSize; //���С
	qvector<VirtulMethodInfo> virtulMethods; //�����б�
	qvector<CustomMethodInfo> customMethods;
	int64 fieldCount = -1;
	qvector<FieldInfo> fields;
};
class DelphiClassAnalyzer : public plugmod_t {
public:
	bool analyzeProgram();
	bool idaapi run(size_t) override;
	~DelphiClassAnalyzer() override;
private:
	std::map<ea_t, DelphiVMT> m_VMTMap;
	qvector<DelphiRecord> m_Records;
	qvector<ea_t> m_VMTAddrs;
	qvector<qstring> m_classNames;
	qvector<DelphiEnumeration> m_Enumerations;
	void getVMTAddrs();
	bool extractClassInfo();
	bool analyzeVMT(DelphiVMT& vmt);
	bool extractRecordInfo();
	bool extractEnumerationInfo();
	bool addParentFiels();
	bool analyzeParentClass();
	bool analyzeFields(DelphiVMT& vmt);
	bool analyzeRecordFields(ea_t firstFieldAddr, DelphiRecord& record);
	bool analyzeTypeInfo(ea_t typeAddr, qstring& typeName);
	bool analyzeTypeSize(DelphiVMT& vmt);
	bool analyzeRecordTypeSize(DelphiRecord& record);
	bool createClassStructs();
	bool createRecordStructs();
	bool createEnumeration();
	bool createVTables(const DelphiVMT& vmt);
	bool analyzeVirtualMethods(DelphiVMT& vmt);
	bool analyzeCustomMethods(DelphiVMT& vmt);
	flags64_t getFlags(asize_t size);
	void output();
};
