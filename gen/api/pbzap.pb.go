// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: api/pbzap.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MaskType int32

const (
	MaskType_MASK_NONE        MaskType = 0 // Не маскировать
	MaskType_MASK_FULL        MaskType = 1 // "John" → "***"
	MaskType_MASK_PARTIAL     MaskType = 2 // "John Smith" → "Jo** Sm***"
	MaskType_MASK_HASH        MaskType = 3 // "password123" → "sha256:abc123..."
	MaskType_MASK_REDACTED    MaskType = 4 // "secret" → "[REDACTED]"
	MaskType_MASK_EMAIL       MaskType = 5 // "user@example.com" → "u***@ex***le.com"
	MaskType_MASK_PHONE       MaskType = 6 // "+1-555-123-4567" → "+1-***-***-4567"
	MaskType_MASK_CREDIT_CARD MaskType = 7 // "4111111111111111" → "**** **** **** 1111"
	MaskType_MASK_SSN         MaskType = 8 // "123-45-6789" → "***-**-6789"
	MaskType_MASK_CUSTOM      MaskType = 9 // "custom" → "***"
)

// Enum value maps for MaskType.
var (
	MaskType_name = map[int32]string{
		0: "MASK_NONE",
		1: "MASK_FULL",
		2: "MASK_PARTIAL",
		3: "MASK_HASH",
		4: "MASK_REDACTED",
		5: "MASK_EMAIL",
		6: "MASK_PHONE",
		7: "MASK_CREDIT_CARD",
		8: "MASK_SSN",
		9: "MASK_CUSTOM",
	}
	MaskType_value = map[string]int32{
		"MASK_NONE":        0,
		"MASK_FULL":        1,
		"MASK_PARTIAL":     2,
		"MASK_HASH":        3,
		"MASK_REDACTED":    4,
		"MASK_EMAIL":       5,
		"MASK_PHONE":       6,
		"MASK_CREDIT_CARD": 7,
		"MASK_SSN":         8,
		"MASK_CUSTOM":      9,
	}
)

func (x MaskType) Enum() *MaskType {
	p := new(MaskType)
	*p = x
	return p
}

func (x MaskType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MaskType) Descriptor() protoreflect.EnumDescriptor {
	return file_api_pbzap_proto_enumTypes[0].Descriptor()
}

func (MaskType) Type() protoreflect.EnumType {
	return &file_api_pbzap_proto_enumTypes[0]
}

func (x MaskType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MaskType.Descriptor instead.
func (MaskType) EnumDescriptor() ([]byte, []int) {
	return file_api_pbzap_proto_rawDescGZIP(), []int{0}
}

type LogLevel int32

const (
	LogLevel_LOG_TRACE LogLevel = 0 // Самый детальный: "Entering function X"
	LogLevel_LOG_DEBUG LogLevel = 1 // Отладка: "Processing user request"
	LogLevel_LOG_INFO  LogLevel = 2 // Информация: "User created"
	LogLevel_LOG_WARN  LogLevel = 3 // Предупреждения: "Slow database query"
	LogLevel_LOG_ERROR LogLevel = 4 // Ошибки: "Database connection failed"
	LogLevel_LOG_FATAL LogLevel = 5 // Критические: "Cannot start server"
)

// Enum value maps for LogLevel.
var (
	LogLevel_name = map[int32]string{
		0: "LOG_TRACE",
		1: "LOG_DEBUG",
		2: "LOG_INFO",
		3: "LOG_WARN",
		4: "LOG_ERROR",
		5: "LOG_FATAL",
	}
	LogLevel_value = map[string]int32{
		"LOG_TRACE": 0,
		"LOG_DEBUG": 1,
		"LOG_INFO":  2,
		"LOG_WARN":  3,
		"LOG_ERROR": 4,
		"LOG_FATAL": 5,
	}
)

func (x LogLevel) Enum() *LogLevel {
	p := new(LogLevel)
	*p = x
	return p
}

func (x LogLevel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogLevel) Descriptor() protoreflect.EnumDescriptor {
	return file_api_pbzap_proto_enumTypes[1].Descriptor()
}

func (LogLevel) Type() protoreflect.EnumType {
	return &file_api_pbzap_proto_enumTypes[1]
}

func (x LogLevel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogLevel.Descriptor instead.
func (LogLevel) EnumDescriptor() ([]byte, []int) {
	return file_api_pbzap_proto_rawDescGZIP(), []int{1}
}

var file_api_pbzap_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*MaskType)(nil),
		Field:         50000,
		Name:          "pbzap.mask_type",
		Tag:           "varint,50000,opt,name=mask_type,enum=pbzap.MaskType",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         50001,
		Name:          "pbzap.custom_mask_pattern",
		Tag:           "bytes,50001,opt,name=custom_mask_pattern",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*LogLevel)(nil),
		Field:         50002,
		Name:          "pbzap.log_level",
		Tag:           "varint,50002,opt,name=log_level,enum=pbzap.LogLevel",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         50006,
		Name:          "pbzap.log_field_name",
		Tag:           "bytes,50006,opt,name=log_field_name",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50007,
		Name:          "pbzap.hide_log_field",
		Tag:           "varint,50007,opt,name=hide_log_field",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50008,
		Name:          "pbzap.omit_empty",
		Tag:           "varint,50008,opt,name=omit_empty",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50009,
		Name:          "pbzap.flatten",
		Tag:           "varint,50009,opt,name=flatten",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         50010,
		Name:          "pbzap.format_template",
		Tag:           "bytes,50010,opt,name=format_template",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50011,
		Name:          "pbzap.lazy_eval",
		Tag:           "varint,50011,opt,name=lazy_eval",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*int32)(nil),
		Field:         50012,
		Name:          "pbzap.max_length",
		Tag:           "varint,50012,opt,name=max_length",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50013,
		Name:          "pbzap.pii_data",
		Tag:           "varint,50013,opt,name=pii_data",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         50014,
		Name:          "pbzap.sensitive",
		Tag:           "varint,50014,opt,name=sensitive",
		Filename:      "api/pbzap.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: ([]string)(nil),
		Field:         50015,
		Name:          "pbzap.compliance_tags",
		Tag:           "bytes,50015,rep,name=compliance_tags",
		Filename:      "api/pbzap.proto",
	},
}

// Extension fields to descriptorpb.FieldOptions.
var (
	// optional pbzap.MaskType mask_type = 50000;
	E_MaskType = &file_api_pbzap_proto_extTypes[0]
	// optional string custom_mask_pattern = 50001;
	E_CustomMaskPattern = &file_api_pbzap_proto_extTypes[1] // e.g., "***" or "[HIDDEN]"
	// Logging control
	//
	// optional pbzap.LogLevel log_level = 50002;
	E_LogLevel = &file_api_pbzap_proto_extTypes[2]
	// optional string log_field_name = 50006;
	E_LogFieldName = &file_api_pbzap_proto_extTypes[3] // Custom field name in logs
	// optional bool hide_log_field = 50007;
	E_HideLogField = &file_api_pbzap_proto_extTypes[4] // Hide log field in logs
	// Validation and formatting
	//
	// optional bool omit_empty = 50008;
	E_OmitEmpty = &file_api_pbzap_proto_extTypes[5] // Skip empty values in logs
	// optional bool flatten = 50009;
	E_Flatten = &file_api_pbzap_proto_extTypes[6] // Flatten nested objects
	// optional string format_template = 50010;
	E_FormatTemplate = &file_api_pbzap_proto_extTypes[7] // Custom format: "User: {name} ({id})"
	// Performance options
	//
	// optional bool lazy_eval = 50011;
	E_LazyEval = &file_api_pbzap_proto_extTypes[8] // Lazy evaluation for expensive computations
	// optional int32 max_length = 50012;
	E_MaxLength = &file_api_pbzap_proto_extTypes[9] // Truncate long strings/arrays
	// Security and compliance
	//
	// optional bool pii_data = 50013;
	E_PiiData = &file_api_pbzap_proto_extTypes[10] // Mark as Personally Identifiable Information
	// optional bool sensitive = 50014;
	E_Sensitive = &file_api_pbzap_proto_extTypes[11] // Generic sensitive data marker
	// repeated string compliance_tags = 50015;
	E_ComplianceTags = &file_api_pbzap_proto_extTypes[12] // ["GDPR", "HIPAA", "PCI"]    // Skip empty values in logs
)

var File_api_pbzap_proto protoreflect.FileDescriptor

var file_api_pbzap_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x62, 0x7a, 0x61, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x05, 0x70, 0x62, 0x7a, 0x61, 0x70, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0xb1, 0x01, 0x0a, 0x08, 0x4d,
	0x61, 0x73, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x41, 0x53, 0x4b, 0x5f,
	0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x41, 0x53, 0x4b, 0x5f, 0x46,
	0x55, 0x4c, 0x4c, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x4d, 0x41, 0x53, 0x4b, 0x5f, 0x50, 0x41,
	0x52, 0x54, 0x49, 0x41, 0x4c, 0x10, 0x02, 0x12, 0x0d, 0x0a, 0x09, 0x4d, 0x41, 0x53, 0x4b, 0x5f,
	0x48, 0x41, 0x53, 0x48, 0x10, 0x03, 0x12, 0x11, 0x0a, 0x0d, 0x4d, 0x41, 0x53, 0x4b, 0x5f, 0x52,
	0x45, 0x44, 0x41, 0x43, 0x54, 0x45, 0x44, 0x10, 0x04, 0x12, 0x0e, 0x0a, 0x0a, 0x4d, 0x41, 0x53,
	0x4b, 0x5f, 0x45, 0x4d, 0x41, 0x49, 0x4c, 0x10, 0x05, 0x12, 0x0e, 0x0a, 0x0a, 0x4d, 0x41, 0x53,
	0x4b, 0x5f, 0x50, 0x48, 0x4f, 0x4e, 0x45, 0x10, 0x06, 0x12, 0x14, 0x0a, 0x10, 0x4d, 0x41, 0x53,
	0x4b, 0x5f, 0x43, 0x52, 0x45, 0x44, 0x49, 0x54, 0x5f, 0x43, 0x41, 0x52, 0x44, 0x10, 0x07, 0x12,
	0x0c, 0x0a, 0x08, 0x4d, 0x41, 0x53, 0x4b, 0x5f, 0x53, 0x53, 0x4e, 0x10, 0x08, 0x12, 0x0f, 0x0a,
	0x0b, 0x4d, 0x41, 0x53, 0x4b, 0x5f, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x10, 0x09, 0x2a, 0x62,
	0x0a, 0x08, 0x4c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x0d, 0x0a, 0x09, 0x4c, 0x4f,
	0x47, 0x5f, 0x54, 0x52, 0x41, 0x43, 0x45, 0x10, 0x00, 0x12, 0x0d, 0x0a, 0x09, 0x4c, 0x4f, 0x47,
	0x5f, 0x44, 0x45, 0x42, 0x55, 0x47, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x4c, 0x4f, 0x47, 0x5f,
	0x49, 0x4e, 0x46, 0x4f, 0x10, 0x02, 0x12, 0x0c, 0x0a, 0x08, 0x4c, 0x4f, 0x47, 0x5f, 0x57, 0x41,
	0x52, 0x4e, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x4c, 0x4f, 0x47, 0x5f, 0x45, 0x52, 0x52, 0x4f,
	0x52, 0x10, 0x04, 0x12, 0x0d, 0x0a, 0x09, 0x4c, 0x4f, 0x47, 0x5f, 0x46, 0x41, 0x54, 0x41, 0x4c,
	0x10, 0x05, 0x3a, 0x4d, 0x0a, 0x09, 0x6d, 0x61, 0x73, 0x6b, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x12,
	0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd0,
	0x86, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x70, 0x62, 0x7a, 0x61, 0x70, 0x2e, 0x4d,
	0x61, 0x73, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x52, 0x08, 0x6d, 0x61, 0x73, 0x6b, 0x54, 0x79, 0x70,
	0x65, 0x3a, 0x4f, 0x0a, 0x13, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f, 0x6d, 0x61, 0x73, 0x6b,
	0x5f, 0x70, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64,
	0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd1, 0x86, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x11, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x4d, 0x61, 0x73, 0x6b, 0x50, 0x61, 0x74, 0x74, 0x65,
	0x72, 0x6e, 0x3a, 0x4d, 0x0a, 0x09, 0x6c, 0x6f, 0x67, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12,
	0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd2,
	0x86, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x70, 0x62, 0x7a, 0x61, 0x70, 0x2e, 0x4c,
	0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x08, 0x6c, 0x6f, 0x67, 0x4c, 0x65, 0x76, 0x65,
	0x6c, 0x3a, 0x45, 0x0a, 0x0e, 0x6c, 0x6f, 0x67, 0x5f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x18, 0xd6, 0x86, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x6c, 0x6f, 0x67, 0x46,
	0x69, 0x65, 0x6c, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x3a, 0x45, 0x0a, 0x0e, 0x68, 0x69, 0x64, 0x65,
	0x5f, 0x6c, 0x6f, 0x67, 0x5f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65,
	0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd7, 0x86, 0x03, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0c, 0x68, 0x69, 0x64, 0x65, 0x4c, 0x6f, 0x67, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x3a,
	0x3e, 0x0a, 0x0a, 0x6f, 0x6d, 0x69, 0x74, 0x5f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x1d, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd8, 0x86, 0x03,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x6f, 0x6d, 0x69, 0x74, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x3a,
	0x39, 0x0a, 0x07, 0x66, 0x6c, 0x61, 0x74, 0x74, 0x65, 0x6e, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65,
	0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xd9, 0x86, 0x03, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x07, 0x66, 0x6c, 0x61, 0x74, 0x74, 0x65, 0x6e, 0x3a, 0x48, 0x0a, 0x0f, 0x66, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x5f, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xda, 0x86, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x54, 0x65, 0x6d, 0x70,
	0x6c, 0x61, 0x74, 0x65, 0x3a, 0x3c, 0x0a, 0x09, 0x6c, 0x61, 0x7a, 0x79, 0x5f, 0x65, 0x76, 0x61,
	0x6c, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0xdb, 0x86, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x6c, 0x61, 0x7a, 0x79, 0x45, 0x76,
	0x61, 0x6c, 0x3a, 0x3e, 0x0a, 0x0a, 0x6d, 0x61, 0x78, 0x5f, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
	0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0xdc, 0x86, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x6d, 0x61, 0x78, 0x4c, 0x65, 0x6e, 0x67,
	0x74, 0x68, 0x3a, 0x3a, 0x0a, 0x08, 0x70, 0x69, 0x69, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1d,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xdd, 0x86,
	0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x70, 0x69, 0x69, 0x44, 0x61, 0x74, 0x61, 0x3a, 0x3d,
	0x0a, 0x09, 0x73, 0x65, 0x6e, 0x73, 0x69, 0x74, 0x69, 0x76, 0x65, 0x12, 0x1d, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xde, 0x86, 0x03, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x09, 0x73, 0x65, 0x6e, 0x73, 0x69, 0x74, 0x69, 0x76, 0x65, 0x3a, 0x48, 0x0a,
	0x0f, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x74, 0x61, 0x67, 0x73,
	0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0xdf, 0x86, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0e, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61,
	0x6e, 0x63, 0x65, 0x54, 0x61, 0x67, 0x73, 0x42, 0x6d, 0x0a, 0x09, 0x63, 0x6f, 0x6d, 0x2e, 0x70,
	0x62, 0x7a, 0x61, 0x70, 0x42, 0x0a, 0x50, 0x62, 0x7a, 0x61, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64,
	0x61, 0x6e, 0x65, 0x65, 0x71, 0x78, 0x2f, 0x70, 0x62, 0x7a, 0x61, 0x70, 0x2f, 0x67, 0x65, 0x6e,
	0x2f, 0x61, 0x70, 0x69, 0xa2, 0x02, 0x03, 0x50, 0x58, 0x58, 0xaa, 0x02, 0x05, 0x50, 0x62, 0x7a,
	0x61, 0x70, 0xca, 0x02, 0x05, 0x50, 0x62, 0x7a, 0x61, 0x70, 0xe2, 0x02, 0x11, 0x50, 0x62, 0x7a,
	0x61, 0x70, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02,
	0x05, 0x50, 0x62, 0x7a, 0x61, 0x70, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_pbzap_proto_rawDescOnce sync.Once
	file_api_pbzap_proto_rawDescData = file_api_pbzap_proto_rawDesc
)

func file_api_pbzap_proto_rawDescGZIP() []byte {
	file_api_pbzap_proto_rawDescOnce.Do(func() {
		file_api_pbzap_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_pbzap_proto_rawDescData)
	})
	return file_api_pbzap_proto_rawDescData
}

var file_api_pbzap_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_api_pbzap_proto_goTypes = []any{
	(MaskType)(0),                     // 0: pbzap.MaskType
	(LogLevel)(0),                     // 1: pbzap.LogLevel
	(*descriptorpb.FieldOptions)(nil), // 2: google.protobuf.FieldOptions
}
var file_api_pbzap_proto_depIdxs = []int32{
	2,  // 0: pbzap.mask_type:extendee -> google.protobuf.FieldOptions
	2,  // 1: pbzap.custom_mask_pattern:extendee -> google.protobuf.FieldOptions
	2,  // 2: pbzap.log_level:extendee -> google.protobuf.FieldOptions
	2,  // 3: pbzap.log_field_name:extendee -> google.protobuf.FieldOptions
	2,  // 4: pbzap.hide_log_field:extendee -> google.protobuf.FieldOptions
	2,  // 5: pbzap.omit_empty:extendee -> google.protobuf.FieldOptions
	2,  // 6: pbzap.flatten:extendee -> google.protobuf.FieldOptions
	2,  // 7: pbzap.format_template:extendee -> google.protobuf.FieldOptions
	2,  // 8: pbzap.lazy_eval:extendee -> google.protobuf.FieldOptions
	2,  // 9: pbzap.max_length:extendee -> google.protobuf.FieldOptions
	2,  // 10: pbzap.pii_data:extendee -> google.protobuf.FieldOptions
	2,  // 11: pbzap.sensitive:extendee -> google.protobuf.FieldOptions
	2,  // 12: pbzap.compliance_tags:extendee -> google.protobuf.FieldOptions
	0,  // 13: pbzap.mask_type:type_name -> pbzap.MaskType
	1,  // 14: pbzap.log_level:type_name -> pbzap.LogLevel
	15, // [15:15] is the sub-list for method output_type
	15, // [15:15] is the sub-list for method input_type
	13, // [13:15] is the sub-list for extension type_name
	0,  // [0:13] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_api_pbzap_proto_init() }
func file_api_pbzap_proto_init() {
	if File_api_pbzap_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_pbzap_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   0,
			NumExtensions: 13,
			NumServices:   0,
		},
		GoTypes:           file_api_pbzap_proto_goTypes,
		DependencyIndexes: file_api_pbzap_proto_depIdxs,
		EnumInfos:         file_api_pbzap_proto_enumTypes,
		ExtensionInfos:    file_api_pbzap_proto_extTypes,
	}.Build()
	File_api_pbzap_proto = out.File
	file_api_pbzap_proto_rawDesc = nil
	file_api_pbzap_proto_goTypes = nil
	file_api_pbzap_proto_depIdxs = nil
}
