package cel

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_xray/structs"
	exprPb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	StrStrMapType = decls.NewMapType(decls.String, decls.String)
	RequestType   = decls.NewObjectType("structs.Request")
	ResponseType  = decls.NewObjectType("structs.Response")
	ReverseType   = decls.NewObjectType("structs.Reverse")
	UrlTypeType   = decls.NewObjectType("structs.UrlType")

	StandardEnvOptions = []cel.EnvOption{
		cel.Container("structs"),
		cel.Types(
			&structs.UrlType{},
			&structs.Request{},
			&structs.Response{},
			&structs.Reverse{},
			StrStrMapType,
		),
		cel.Declarations(
			decls.NewVar("request", RequestType),
			decls.NewVar("response", ResponseType),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprPb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("ibcontains",
				decls.NewInstanceOverload("bytes_ibcontains_bytes",
					[]*exprPb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("icontains_string",
					[]*exprPb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("bstartsWith",
				decls.NewInstanceOverload("bytes_bstartsWith_bytes",
					[]*exprPb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("submatch",
				decls.NewInstanceOverload("string_submatch_string",
					[]*exprPb.Type{decls.String, decls.String},
					StrStrMapType,
				)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprPb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bsubmatch",
				decls.NewInstanceOverload("string_bsubmatch_bytes",
					[]*exprPb.Type{decls.String, decls.Bytes},
					StrStrMapType,
				)),
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprPb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("newReverse",
				decls.NewOverload("newReverse",
					[]*exprPb.Type{},
					ReverseType)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprPb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprPb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprPb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprPb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprPb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprPb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprPb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("replaceAll",
				decls.NewOverload("replaceAll_string_string_string",
					[]*exprPb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			decls.NewFunction("printable",
				decls.NewOverload("printable_string",
					[]*exprPb.Type{decls.String},
					decls.String)),
			decls.NewFunction("sleep",
				decls.NewOverload("sleep_int",
					[]*exprPb.Type{decls.Int},
					decls.Bool)),
			decls.NewFunction("faviconHash",
				decls.NewOverload("faviconHash_stringOrBytes",
					[]*exprPb.Type{decls.Any},
					decls.Int)),
			decls.NewFunction("toUintString",
				decls.NewOverload("toUintString_string_string",
					[]*exprPb.Type{decls.String, decls.String},
					decls.String)),
		),
	}
)

func NewFunctionDefineOptions(reg ref.TypeRegistry) []cel.EnvOption {
	newOptions := []cel.EnvOption{
		cel.CustomTypeAdapter(reg),
		cel.CustomTypeProvider(reg),
	}
	newOptions = append(newOptions, StandardEnvOptions...)

	return newOptions
}
