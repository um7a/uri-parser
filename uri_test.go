package urip

import (
	"fmt"
	"testing"
)

func byteEquals(testName string, t *testing.T, expected []byte, actual []byte) {
	if len(actual) != len(expected) {
		t.Logf("expected: %s, actual %s", expected, actual)
		t.Errorf("%v: len(expected): %v, len(actual): %v", testName, len(expected), len(actual))
		return
	}
	for i, e := range expected {
		if e != actual[i] {
			t.Logf("expected: %s, actual %s", expected, actual)
			t.Errorf("%v: expected[%v]: %v, actual[%v]): %v", testName, i, expected, i, actual)
			return
		}
	}
}

func TestUri(t *testing.T) {
	type TestCase struct {
		testName            string
		data                []byte
		expectedScheme      []byte
		expectedDoubleSlash []byte
		expectedUserInfo    []byte
		expectedAtSign      []byte
		expectedHost        []byte
		expectedPort        []byte
		expectedPath        []byte
		expectedQuestion    []byte
		expectedQuery       []byte
		expectedSharp       []byte
		expectedFragment    []byte
	}

	tests := []TestCase{
		// hier-part test - authority test: host validation
		{
			testName:            "data: []byte(\"http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:                []byte("http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://[v1F.a,:]\")",
			data:                []byte("http://[v1F.a,:]"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("[v1F.a,:]"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://255.255.255.255\")",
			data:                []byte("http://255.255.255.255"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("255.255.255.255"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com\")",
			data:                []byte("http://example.com"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - authority test: with userinfo
		{
			testName:            "data: []byte(\"http://user:pass@example.com\")",
			data:                []byte("http://user:pass@example.com"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte("user:pass"),
			expectedAtSign:      []byte("@"),
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - authority test: with port
		{
			testName:            "data: []byte(\"http://example.com:80\")",
			data:                []byte("http://example.com:80"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte("80"),
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - path-abempty test
		{
			testName:            "data: []byte(\"http://example.com\")",
			data:                []byte("http://example.com"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/\")",
			data:                []byte("http://example.com/"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/path\")",
			data:                []byte("http://example.com/path"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/path1/path2\")",
			data:                []byte("http://example.com/path1/path2"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - path-absolute test
		{
			testName:            "data: []byte(\"http:/\")",
			data:                []byte("http:/"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte("/"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http:/path\")",
			data:                []byte("http:/path"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte("/path"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http:/path1/path2\")",
			data:                []byte("http:/path1/path2"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - path-rootless test
		{
			testName:            "data: []byte(\"http:path\")",
			data:                []byte("http:path"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte("path"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http:path1/path2\")",
			data:                []byte("http:path1/path2"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte("path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// hier-part test - path-empty test
		{
			testName:            "data: []byte(\"http:\")",
			data:                []byte("http:"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte{},
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte{},
			expectedPort:        []byte{},
			expectedPath:        []byte{},
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// [ "?" query ] test
		{
			testName:            "data: []byte(\"http://example.com/path1/path2?\")",
			data:                []byte("http://example.com/path1/path2?"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte("?"),
			expectedQuery:       []byte{},
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:                []byte("http://example.com/path1/path2?key=value"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte("?"),
			expectedQuery:       []byte("key=value"),
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/path1/path2?key1=value1&key2=value2\")",
			data:                []byte("http://example.com/path1/path2?key1=value1&key2=value2"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte("?"),
			expectedQuery:       []byte("key1=value1&key2=value2"),
			expectedSharp:       []byte{},
			expectedFragment:    []byte{},
		},
		// [ "#" fragment ] test
		{
			testName:            "data: []byte(\"http://example.com/path1/path2#\")",
			data:                []byte("http://example.com/path1/path2#"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte("#"),
			expectedFragment:    []byte{},
		},
		{
			testName:            "data: []byte(\"http://example.com/path1/path2#key=value\")",
			data:                []byte("http://example.com/path1/path2#key=value"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte("#"),
			expectedFragment:    []byte("key=value"),
		},
		{
			testName:            "data: []byte(\"http://example.com/path1/path2#key1=value1&key2=value2\")",
			data:                []byte("http://example.com/path1/path2#key1=value1&key2=value2"),
			expectedScheme:      []byte("http"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte{},
			expectedAtSign:      []byte{},
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte{},
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte{},
			expectedQuery:       []byte{},
			expectedSharp:       []byte("#"),
			expectedFragment:    []byte("key1=value1&key2=value2"),
		},
		// All component test
		{
			testName:            "data: []byte(\"https://user:pass@example.com:443/path1/path2?key=value#key=value\")",
			data:                []byte("https://user:pass@example.com:443/path1/path2?key1=value1&key2=value2#key3=value3&key4=value4"),
			expectedScheme:      []byte("https"),
			expectedDoubleSlash: []byte("//"),
			expectedUserInfo:    []byte("user:pass"),
			expectedAtSign:      []byte("@"),
			expectedHost:        []byte("example.com"),
			expectedPort:        []byte("443"),
			expectedPath:        []byte("/path1/path2"),
			expectedQuestion:    []byte("?"),
			expectedQuery:       []byte("key1=value1&key2=value2"),
			expectedSharp:       []byte("#"),
			expectedFragment:    []byte("key3=value3&key4=value4"),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			uri, err := Parse(testCase.data)
			if err != nil {
				t.Errorf("Failed to parse Uri: %v", err.Error())
				return
			}
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Scheme"),
				t,
				testCase.expectedScheme,
				uri.Scheme,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "DoubleSlash"),
				t,
				testCase.expectedDoubleSlash,
				uri.DoubleSlash,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "UserInfo"),
				t,
				testCase.expectedUserInfo,
				uri.UserInfo,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "AtSign"),
				t,
				testCase.expectedAtSign,
				uri.AtSign,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Host"),
				t,
				testCase.expectedHost,
				uri.Host,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Port"),
				t,
				testCase.expectedPort,
				uri.Port,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Path"),
				t,
				testCase.expectedPath,
				uri.Path,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Question"),
				t,
				testCase.expectedQuestion,
				uri.Question,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Query"),
				t,
				testCase.expectedQuery,
				uri.Query,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Sharp"),
				t,
				testCase.expectedSharp,
				uri.Sharp,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "Fragment"),
				t,
				testCase.expectedFragment,
				uri.Fragment,
			)
			byteEquals(
				fmt.Sprintf("%s(%s)", testCase.testName, "String"),
				t,
				testCase.data,
				[]byte(uri.String()),
			)
		})
	}
}
