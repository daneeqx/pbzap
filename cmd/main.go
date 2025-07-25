package main

import (
	"fmt"

	pbzap "github.com/daneeqx/pbzap/gen"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

const (
	zapcorePkg = protogen.GoImportPath("go.uber.org/zap/zapcore")
	fmtPkg     = protogen.GoImportPath("fmt")
	stringsPkg = protogen.GoImportPath("strings")
	sha256Pkg  = protogen.GoImportPath("crypto/sha256")
	hexPkg     = protogen.GoImportPath("encoding/hex")
)

type PBZapPlugin struct {
	plugin *protogen.Plugin
}

type MessageField struct {
	Field   *protogen.Field
	Options *descriptorpb.FieldOptions
}

func maskField(field *protogen.Field, g *protogen.GeneratedFile, maskType pbzap.MaskType) {
	fieldName := string(field.Desc.Name())

	// Проверяем log_field_name опцию
	logFieldName, hasLogFieldName := proto.GetExtension(field.Desc.Options(), pbzap.E_LogFieldName).(string)
	if hasLogFieldName && logFieldName != "" {
		// Используем кастомное имя поля
		fieldName = logFieldName
	}

	switch maskType {
	case pbzap.MaskType_MASK_NONE:
		// Не маскировать - выводим как есть
		g.P("enc.AddString(\"", fieldName, "\", x.", field.GoName, ")")
	case pbzap.MaskType_MASK_FULL:
		// "John" → "***"
		g.P("enc.AddString(\"", fieldName, "\", \"***\")")
	case pbzap.MaskType_MASK_PARTIAL:
		// "John Smith" → "Jo** Sm***" - частичная маскировка
		g.P("if len(x.", field.GoName, ") > 0 {")
		g.P("words := ", g.QualifiedGoIdent(stringsPkg.Ident("Fields")), "(x.", field.GoName, ")")
		g.P("maskedWords := make([]string, len(words))")
		g.P("for i, word := range words {")
		g.P("if len(word) <= 2 {")
		g.P("maskedWords[i] = word")
		g.P("} else {")
		g.P("maskedWords[i] = word[:2] + ", g.QualifiedGoIdent(stringsPkg.Ident("Repeat")), "(\"*\", len(word)-2)")
		g.P("}")
		g.P("}")
		g.P("enc.AddString(\"", fieldName, "\", ", g.QualifiedGoIdent(stringsPkg.Ident("Join")), "(maskedWords, \" \"))")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_HASH:
		// "password123" → "sha256:abc123..." - хеширование
		g.P("if x.", field.GoName, " != \"\" {")
		g.P("hash := ", g.QualifiedGoIdent(sha256Pkg.Ident("Sum256")), "([]byte(x.", field.GoName, "))")
		g.P("enc.AddString(\"", fieldName, "\", \"sha256:\" + ", g.QualifiedGoIdent(hexPkg.Ident("EncodeToString")), "(hash[:]))")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_REDACTED:
		// "secret" → "[REDACTED]"
		g.P("enc.AddString(\"", fieldName, "\", \"[REDACTED]\")")
	case pbzap.MaskType_MASK_EMAIL:
		// "user@example.com" → "u***@ex***le.com"
		g.P("if x.", field.GoName, " != \"\" {")
		g.P("parts := ", g.QualifiedGoIdent(stringsPkg.Ident("Split")), "(x.", field.GoName, ", \"@\")")
		g.P("if len(parts) == 2 {")
		g.P("username := parts[0]")
		g.P("domain := parts[1]")
		g.P("var maskedUsername string")
		g.P("if len(username) > 0 {")
		g.P("maskedUsername = username[:1] + ", g.QualifiedGoIdent(stringsPkg.Ident("Repeat")), "(\"*\", len(username)-1)")
		g.P("} else {")
		g.P("maskedUsername = \"*\"")
		g.P("}")
		g.P("var maskedDomain string")
		g.P("if len(domain) > 2 {")
		g.P("maskedDomain = domain[:2] + ", g.QualifiedGoIdent(stringsPkg.Ident("Repeat")), "(\"*\", len(domain)-2)")
		g.P("} else {")
		g.P("maskedDomain = domain")
		g.P("}")
		g.P("enc.AddString(\"", fieldName, "\", maskedUsername + \"@\" + maskedDomain)")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"[INVALID_EMAIL]\")")
		g.P("}")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_PHONE:
		// "+1-555-123-4567" → "+1-***-***-4567" или "77778488383" → "777****8383"
		g.P("if x.", field.GoName, " != \"\" {")
		g.P("// Сначала пробуем формат с дефисами")
		g.P("parts := ", g.QualifiedGoIdent(stringsPkg.Ident("Split")), "(x.", field.GoName, ", \"-\")")
		g.P("if len(parts) >= 4 {")
		g.P("// Формат с дефисами: +1-555-123-4567 → +1-***-***-4567")
		g.P("maskedParts := make([]string, len(parts))")
		g.P("maskedParts[0] = parts[0]") // код страны
		g.P("for i := 1; i < len(parts)-1; i++ {")
		g.P("maskedParts[i] = \"***\"")
		g.P("}")
		g.P("maskedParts[len(parts)-1] = parts[len(parts)-1]") // последние 4 цифры
		g.P("enc.AddString(\"", fieldName, "\", ", g.QualifiedGoIdent(stringsPkg.Ident("Join")), "(maskedParts, \"-\"))")
		g.P("} else {")
		g.P("// Формат без дефисов: 77778488383 → 777****8383")
		g.P("phone := ", g.QualifiedGoIdent(stringsPkg.Ident("ReplaceAll")), "(x.", field.GoName, ", \" \", \"\")")
		g.P("phone = ", g.QualifiedGoIdent(stringsPkg.Ident("ReplaceAll")), "(phone, \"-\", \"\")")
		g.P("phone = ", g.QualifiedGoIdent(stringsPkg.Ident("ReplaceAll")), "(phone, \"(\", \"\")")
		g.P("phone = ", g.QualifiedGoIdent(stringsPkg.Ident("ReplaceAll")), "(phone, \")\", \"\")")
		g.P("if len(phone) >= 7 {")
		g.P("if len(phone) == 11 && phone[0] == '7' {") // российский формат
		g.P("enc.AddString(\"", fieldName, "\", phone[:3] + \"****\" + phone[7:])")
		g.P("} else if len(phone) >= 10 {") // международный формат
		g.P("enc.AddString(\"", fieldName, "\", phone[:len(phone)-7] + \"****\" + phone[len(phone)-3:])")
		g.P("} else {") // короткий формат
		g.P("enc.AddString(\"", fieldName, "\", phone[:3] + \"****\" + phone[len(phone)-3:])")
		g.P("}")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"[INVALID_PHONE]\")")
		g.P("}")
		g.P("}")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_CREDIT_CARD:
		// "4111111111111111" → "**** **** **** 1111"
		g.P("if x.", field.GoName, " != \"\" {")
		g.P("card := ", g.QualifiedGoIdent(stringsPkg.Ident("ReplaceAll")), "(x.", field.GoName, ", \" \", \"\")")
		g.P("if len(card) >= 4 {")
		g.P("enc.AddString(\"", fieldName, "\", \"**** **** **** \" + card[len(card)-4:])")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"[INVALID_CARD]\")")
		g.P("}")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_SSN:
		// "123-45-6789" → "***-**-6789"
		g.P("if x.", field.GoName, " != \"\" {")
		g.P("parts := strings.Split(x.", field.GoName, ", \"-\")")
		g.P("if len(parts) == 3 {")
		g.P("enc.AddString(\"", fieldName, "\", \"***-**-\" + parts[2])")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"[INVALID_SSN]\")")
		g.P("}")
		g.P("} else {")
		g.P("enc.AddString(\"", fieldName, "\", \"\")")
		g.P("}")
	case pbzap.MaskType_MASK_CUSTOM:
		// Проверяем custom_mask_pattern
		customPattern, hasCustom := proto.GetExtension(field.Desc.Options(), pbzap.E_CustomMaskPattern).(string)
		if hasCustom && customPattern != "" {
			g.P("enc.AddString(\"", fieldName, "\", \"", customPattern, "\")")
		} else {
			g.P("enc.AddString(\"", fieldName, "\", \"***\")")
		}
	}
}

func logField(field *protogen.Field, g *protogen.GeneratedFile, logLevel pbzap.LogLevel) {
	fieldName := string(field.Desc.Name())

	// Проверяем log_field_name опцию
	logFieldName, hasLogFieldName := proto.GetExtension(field.Desc.Options(), pbzap.E_LogFieldName).(string)
	if hasLogFieldName && logFieldName != "" {
		fieldName = logFieldName
	}

	// Генерируем код с проверкой уровня логирования
	switch logLevel {
	case pbzap.LogLevel_LOG_TRACE:
		g.P("// TRACE level field - always logged")
		g.P("enc.AddString(\"", fieldName, "_trace\", x.", field.GoName, ")")
	case pbzap.LogLevel_LOG_DEBUG:
		g.P("// DEBUG level field - only in debug mode")
		g.P("if enc.Level() <= ", g.QualifiedGoIdent(zapcorePkg.Ident("DebugLevel")), " {")
		g.P("enc.AddString(\"", fieldName, "_debug\", x.", field.GoName, ")")
		g.P("}")
	case pbzap.LogLevel_LOG_INFO:
		g.P("// INFO level field - only in info mode and above")
		g.P("if enc.Level() <= ", g.QualifiedGoIdent(zapcorePkg.Ident("InfoLevel")), " {")
		g.P("enc.AddString(\"", fieldName, "_info\", x.", field.GoName, ")")
		g.P("}")
	case pbzap.LogLevel_LOG_WARN:
		g.P("// WARN level field - only in warn mode and above")
		g.P("if enc.Level() <= ", g.QualifiedGoIdent(zapcorePkg.Ident("WarnLevel")), " {")
		g.P("enc.AddString(\"", fieldName, "_warn\", x.", field.GoName, ")")
		g.P("}")
	case pbzap.LogLevel_LOG_ERROR:
		g.P("// ERROR level field - only in error mode and above")
		g.P("if enc.Level() <= ", g.QualifiedGoIdent(zapcorePkg.Ident("ErrorLevel")), " {")
		g.P("enc.AddString(\"", fieldName, "_error\", x.", field.GoName, ")")
		g.P("}")
	case pbzap.LogLevel_LOG_FATAL:
		g.P("// FATAL level field - only in fatal mode")
		g.P("if enc.Level() <= ", g.QualifiedGoIdent(zapcorePkg.Ident("FatalLevel")), " {")
		g.P("enc.AddString(\"", fieldName, "_fatal\", x.", field.GoName, ")")
		g.P("}")
	}
}

func (f *MessageField) generateField(g *protogen.GeneratedFile) {
	fieldName := string(f.Field.Desc.Name())

	// Добавляем отладочную информацию
	g.P("// Processing field: ", fieldName)

	// Проверяем hide_log_field опцию
	hideLogField, hasHideLogField := proto.GetExtension(f.Field.Desc.Options(), pbzap.E_HideLogField).(bool)
	if hasHideLogField && hideLogField {
		g.P("// Field ", fieldName, " is hidden")
		return
	}

	// Проверяем log_level опцию ПЕРЕД маскировкой
	logLevel, hasLogLevelType := proto.GetExtension(f.Field.Desc.Options(), pbzap.E_LogLevel).(pbzap.LogLevel)
	if hasLogLevelType {
		g.P("// Field ", fieldName, " has log level: ", logLevel)
		logField(f.Field, g, logLevel)
		return // Если есть уровень логирования, не применяем маскировку
	}

	// Проверяем маскировку
	maskType, hasMaskType := proto.GetExtension(f.Field.Desc.Options(), pbzap.E_MaskType).(pbzap.MaskType)
	if hasMaskType {
		g.P("// Field ", fieldName, " has mask type: ", maskType)
		maskField(f.Field, g, maskType)
		return // Если есть маскировка, не применяем обычное логирование
	}

	// Обычное поле без специальных опций
	g.P("// Field ", fieldName, " is regular field")

	// Проверяем log_field_name опцию
	logFieldName, hasLogFieldName := proto.GetExtension(f.Field.Desc.Options(), pbzap.E_LogFieldName).(string)
	if hasLogFieldName && logFieldName != "" {
		g.P("enc.AddString(\"", logFieldName, "\", x.", f.Field.GoName, ")")
	} else {
		g.P("enc.AddString(\"", fieldName, "\", x.", f.Field.GoName, ")")
	}
}

func (p *PBZapPlugin) generateFile(file *protogen.File) *protogen.GeneratedFile {
	if len(file.Messages) == 0 && len(file.Services) == 0 {
		return nil
	}

	filename := fmt.Sprintf("%s.pb.pbzap.go", file.GeneratedFilenamePrefix)

	g := p.plugin.NewGeneratedFile(filename, file.GoImportPath)

	g.P("// Code generated by protoc-gen-pbzap. DO NOT EDIT.")
	g.P("//")
	g.P("// source: ", file.Desc.Path())
	g.P()
	g.P("package ", file.GoPackageName)
	g.P()

	p.generateFileContent(file, g)

	return g
}

func (p *PBZapPlugin) generateMessage(message *protogen.Message, g *protogen.GeneratedFile) {

	ident := g.QualifiedGoIdent(message.GoIdent)
	g.P("func (x *", ident, ") MarshalLogObject(enc ", g.QualifiedGoIdent(zapcorePkg.Ident("ObjectEncoder")), ") error {")
	g.P("if x == nil {")
	g.P("return nil")
	g.P("}")
	g.P()

	for _, field := range message.Fields {
		field := &MessageField{
			Field:   field,
			Options: field.Desc.Options().(*descriptorpb.FieldOptions),
		}

		field.generateField(g)
	}
	g.P("return nil")
	g.P("}")
	g.P()
}

func (p *PBZapPlugin) generateFileContent(file *protogen.File, g *protogen.GeneratedFile) {
	for _, message := range file.Messages {
		p.generateMessage(message, g)
	}
}

func (p *PBZapPlugin) Run() error {
	for _, file := range p.plugin.FilesByPath {
		if !file.Generate {
			continue
		}

		p.generateFile(file)
	}

	return nil
}

func main() {
	protogen.Options{}.Run(func(plugin *protogen.Plugin) error {
		plugin.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)
		pbzapPlugin := &PBZapPlugin{plugin: plugin}

		err := pbzapPlugin.Run()

		if err != nil {
			return err
		}

		return nil
	})
}
