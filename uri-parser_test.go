package urip

import (
	"testing"

	abnfp "github.com/um7a/abnf-parser"
)

type TestCase struct {
	testName     string
	data         []byte
	findFunc     abnfp.FindFunc
	expectedEnds []int
}

func sliceHasSameElem[C comparable](testName string, t *testing.T, expected []C, actual []C) {
	for _, e := range expected {
		has := false
		for _, a := range actual {
			if e == a {
				has = true
				break
			}
		}
		if !has {
			t.Errorf("%v: actual %v does not have expected element %v", testName, actual, e)
		}
	}
	if len(expected) != len(actual) {
		t.Errorf("%v: expected: %v, actual: %v", testName, expected, actual)
	}
}

func execTest(tests []TestCase, t *testing.T) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			actualEnds := testCase.findFunc(testCase.data)
			sliceHasSameElem(testCase.testName, t, testCase.expectedEnds, actualEnds)
		})
	}
}

func TestFindPctEncoded(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPctEncoded,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"abc\")",
			data:         []byte("abc"),
			findFunc:     FindPctEncoded,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"%1A\")",
			data:         []byte("%1A"),
			findFunc:     FindPctEncoded,
			expectedEnds: []int{3},
		},
	}
	execTest(tests, t)
}

func TestFindReserved(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindReserved,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{},
			findFunc:     FindReserved,
			expectedEnds: []int{},
		},
		// gen-delims
		{
			testName:     "data: []byte{'!'}",
			data:         []byte{'!'},
			findFunc:     FindReserved,
			expectedEnds: []int{1},
		},
		// sub-delims
		{
			testName:     "data: []byte{'!'}",
			data:         []byte{'!'},
			findFunc:     FindReserved,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindGenDelims(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindGenDelims,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{},
			findFunc:     FindGenDelims,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{':'}",
			data:         []byte{':'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'/'}",
			data:         []byte{'/'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'?'}",
			data:         []byte{'?'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'#'}",
			data:         []byte{'#'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'['}",
			data:         []byte{'['},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{']'}",
			data:         []byte{']'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'@'}",
			data:         []byte{'@'},
			findFunc:     FindGenDelims,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindSubDelims(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindSubDelims,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{},
			findFunc:     FindSubDelims,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'!'}",
			data:         []byte{'!'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'$'}",
			data:         []byte{'$'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'&'}",
			data:         []byte{'&'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'''}",
			data:         []byte{'\''},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'('}",
			data:         []byte{'('},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{')'}",
			data:         []byte{')'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'*'}",
			data:         []byte{'*'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'+'}",
			data:         []byte{'+'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{','}",
			data:         []byte{','},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{';'}",
			data:         []byte{';'},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'='}",
			data:         []byte{'='},
			findFunc:     FindSubDelims,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindUnreserved(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindUnreserved,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'#'}",
			data:         []byte{'#'},
			findFunc:     FindUnreserved,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindUnreserved,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'1'}",
			data:         []byte{'1'},
			findFunc:     FindUnreserved,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'-'}",
			data:         []byte{'-'},
			findFunc:     FindUnreserved,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindUri,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindUri,
			expectedEnds: []int{},
		},
		// hier-part test - authority test: host validation
		{
			testName: "data: []byte(\"http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:     []byte("http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			findFunc: FindUri,
			expectedEnds: []int{
				5, // "http:" ==> scheme ":" path-empty
				6, // "http:/" ==> scheme ":" path-absolute
				7, // "http://" ==>  scheme ":" "//" reg-name
				48,
			},
		},
		{
			testName: "data: []byte(\"http://255.255.255.255\")",
			data:     []byte("http://255.255.255.255"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==>  scheme ":" "//" reg-name
				8,  // "http://2" ==>  scheme ":" "//" reg-name
				9,  // "http://25" ==>  scheme ":" "//" reg-name
				10, // "http://255" ==>  scheme ":" "//" reg-name
				11, // "http://255." ==>  scheme ":" "//" reg-name
				12, // "http://255.2" ==>  scheme ":" "//" reg-name
				13, // "http://255.25" ==>  scheme ":" "//" reg-name
				14, // "http://255.255" ==>  scheme ":" "//" reg-name
				15, // "http://255.255." ==>  scheme ":" "//" reg-name
				16, // "http://255.255.2" ==>  scheme ":" "//" reg-name
				17, // "http://255.255.25" ==>  scheme ":" "//" reg-name
				18, // "http://255.255.255" ==>  scheme ":" "//" reg-name
				19, // "http://255.255.255." ==> scheme ":" "//" reg-name
				20, // "http://255.255.255.2" ==> scheme ":" "//" reg-name
				21, // "http://255.255.255.25" ==> scheme ":" "//" reg-name
				22,
			},
		},
		{
			testName: "data: []byte(\"http://example.com\")",
			data:     []byte("http://example.com"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18,
			},
		},
		// hier-part test - authority test: with userinfo
		{
			testName: "data: []byte(\"http://user:pass@example.com\")",
			data:     []byte("http://user:pass@example.com"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://u" ==> scheme ":" "//" reg-name
				9,  // "http://us" ==> scheme ":" "//" reg-name
				10, // "http://use" ==> scheme ":" "//" reg-name
				11, // "http://user" ==> scheme ":" "//" reg-name
				12, // "http://user:" ==> scheme ":" "//" host ":" port
				17, // "http://user:pass@" ==> scheme ":" "//" userinfo "@" reg-name
				18, // "http://user:pass@e" ==> scheme ":" "//" userinfo "@" reg-name
				19, // "http://user:pass@ex" ==> scheme ":" "//" userinfo "@" reg-name
				20, // "http://user:pass@exa" ==> scheme ":" "//" userinfo "@" reg-name
				21, // "http://user:pass@exam" ==> scheme ":" "//" userinfo "@" reg-name
				22, // "http://user:pass@examp" ==> scheme ":" "//" userinfo "@" reg-name
				23, // "http://user:pass@exampl" ==> scheme ":" "//" userinfo "@" reg-name
				24, // "http://user:pass@example" ==> scheme ":" "//" userinfo "@" reg-name
				25, // "http://user:pass@example." ==> scheme ":" "//" userinfo "@" reg-name
				26, // "http://user:pass@example.c" ==> scheme ":" "//" userinfo "@" reg-name
				27, // "http://user:pass@example.co" ==> scheme ":" "//" userinfo "@" reg-name
				28,
			},
		},
		// hier-part test - authority test: with port
		{
			testName: "data: []byte(\"http://example.com:80\")",
			data:     []byte("http://example.com:80"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com:" ==> scheme ":" "//" "host" ":" port
				20, // "http://example.com:8" ==> scheme ":" "//" "host" ":" port
				21,
			},
		},
		// hier-part test - path-abempty test
		{
			testName: "data: []byte(\"http://example.com\")",
			data:     []byte("http://example.com"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18,
			},
		},
		{
			testName: "data: []byte(\"http://example.com/\")",
			data:     []byte("http://example.com/"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19,
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path\")",
			data:     []byte("http://example.com/path"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23,
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2\")",
			data:     []byte("http://example.com/path1/path2"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30,
			},
		},
		// hier-part test - path-absolute test
		{
			testName: "data: []byte(\"http:/\")",
			data:     []byte("http:/"),
			findFunc: FindUri,
			expectedEnds: []int{
				5, // "http:" ==> scheme ":" path-empty
				6, // "http:/" ==> scheme ":" path-absolute
			},
		},
		{
			testName: "data: []byte(\"http:/path\")",
			data:     []byte("http:/path"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http:/p" ==> scheme ":" path-absolute
				8,  // "http:/pa" ==> scheme ":" path-absolute
				9,  // "http:/pat" ==> scheme ":" path-absolute
				10, // "http:/path" ==> scheme ":" path-absolute
			},
		},
		{
			testName: "data: []byte(\"http:/path1/path2\")",
			data:     []byte("http:/path1/path2"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http:/p" ==> scheme ":" path-absolute
				8,  // "http:/pa" ==> scheme ":" path-absolute
				9,  // "http:/pat" ==> scheme ":" path-absolute
				10, // "http:/path" ==> scheme ":" path-absolute
				11, // "http:/path1" ==> scheme ":" path-absolute
				12, // "http:/path1/" ==> scheme ":" path-absolute
				13, // "http:/path1/p" ==> scheme ":" path-absolute
				14, // "http:/path1/pa" ==> scheme ":" path-absolute
				15, // "http:/path1/pat" ==> scheme ":" path-absolute
				16, // "http:/path1/path" ==> scheme ":" path-absolute
				17, // "http:/path1/path2" ==> scheme ":" path-absolute
			},
		},
		// hier-part test - path-rootless test
		{
			testName: "data: []byte(\"http:path\")",
			data:     []byte("http:path"),
			findFunc: FindUri,
			expectedEnds: []int{
				5, // "http:" ==> scheme ":" path-empty
				6, // "http:p" ==> scheme ":" path-rootless
				7, // "http:pa" ==> scheme ":" path-rootless
				8, // "http:pat" ==> scheme ":" path-rootless
				9, // "http:path" ==> scheme ":" path-rootless
			},
		},
		{
			testName: "data: []byte(\"http:path1/path2\")",
			data:     []byte("http:path1/path2"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:p" ==> scheme ":" path-rootless
				7,  // "http:pa" ==> scheme ":" path-rootless
				8,  // "http:pat" ==> scheme ":" path-rootless
				9,  // "http:path" ==> scheme ":" path-rootless
				10, // "http:path1" ==> scheme ":" path-rootless
				11, // "http:path1/" ==> scheme ":" path-rootless
				12, // "http:path1/p" ==> scheme ":" path-rootless
				13, // "http:path1/pa" ==> scheme ":" path-rootless
				14, // "http:path1/pat" ==> scheme ":" path-rootless
				15, // "http:path1/path" ==> scheme ":" path-rootless
				16, // "http:path1/path2" ==> scheme ":" path-rootless
			},
		},
		// hier-part test - path-empty test
		{
			testName: "data: []byte(\"http:\")",
			data:     []byte("http:"),
			findFunc: FindUri,
			expectedEnds: []int{
				5, // "http:" ==> scheme ":" path-empty
			},
		},
		// [ "?" query ] test
		{
			testName: "data: []byte(\"http://example.com/path1/path2?\")",
			data:     []byte("http://example.com/path1/path2?"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2?" ==> scheme ":" "//" authority path-abempty "?" query
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:     []byte("http://example.com/path1/path2?key=value"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2?" ==> scheme ":" "//" authority path-abempty "?" query
				32, // "http://example.com/path1/path2?k" ==> scheme ":" "//" authority path-abempty "?" query
				33, // "http://example.com/path1/path2?ke" ==> scheme ":" "//" authority path-abempty "?" query
				34, // "http://example.com/path1/path2?key" ==> scheme ":" "//" authority path-abempty "?" query
				35, // "http://example.com/path1/path2?key=" ==> scheme ":" "//" authority path-abempty "?" query
				36, // "http://example.com/path1/path2?key=v" ==> scheme ":" "//" authority path-abempty "?" query
				37, // "http://example.com/path1/path2?key=va" ==> scheme ":" "//" authority path-abempty "?" query
				38, // "http://example.com/path1/path2?key=val" ==> scheme ":" "//" authority path-abempty "?" query
				39, // "http://example.com/path1/path2?key=valu" ==> scheme ":" "//" authority path-abempty "?" query
				40, // "http://example.com/path1/path2?key=value" ==> scheme ":" "//" authority path-abempty "?" query
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2?key1=value1&key2=value2\")",
			data:     []byte("http://example.com/path1/path2?key1=value1&key2=value2"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2?" ==> scheme ":" "//" authority path-abempty "?" query
				32, // "http://example.com/path1/path2?k" ==> scheme ":" "//" authority path-abempty "?" query
				33, // "http://example.com/path1/path2?ke" ==> scheme ":" "//" authority path-abempty "?" query
				34, // "http://example.com/path1/path2?key" ==> scheme ":" "//" authority path-abempty "?" query
				35, // "http://example.com/path1/path2?key1" ==> scheme ":" "//" authority path-abempty "?" query
				36, // "http://example.com/path1/path2?key1=" ==> scheme ":" "//" authority path-abempty "?" query
				37, // "http://example.com/path1/path2?key1=v" ==> scheme ":" "//" authority path-abempty "?" query
				38, // "http://example.com/path1/path2?key1=va" ==> scheme ":" "//" authority path-abempty "?" query
				39, // "http://example.com/path1/path2?key1=val" ==> scheme ":" "//" authority path-abempty "?" query
				40, // "http://example.com/path1/path2?key1=valu" ==> scheme ":" "//" authority path-abempty "?" query
				41, // "http://example.com/path1/path2?key1=value" ==> scheme ":" "//" authority path-abempty "?" query
				42, // "http://example.com/path1/path2?key1=value1" ==> scheme ":" "//" authority path-abempty "?" query
				43, // "http://example.com/path1/path2?key1=value1&" ==> scheme ":" "//" authority path-abempty "?" query
				44, // "http://example.com/path1/path2?key1=value1&k" ==> scheme ":" "//" authority path-abempty "?" query
				45, // "http://example.com/path1/path2?key1=value1&ke" ==> scheme ":" "//" authority path-abempty "?" query
				46, // "http://example.com/path1/path2?key1=value1&key" ==> scheme ":" "//" authority path-abempty "?" query
				47, // "http://example.com/path1/path2?key1=value1&key2" ==> scheme ":" "//" authority path-abempty "?" query
				48, // "http://example.com/path1/path2?key1=value1&key2=" ==> scheme ":" "//" authority path-abempty "?" query
				49, // "http://example.com/path1/path2?key1=value1&key2=v" ==> scheme ":" "//" authority path-abempty "?" query
				50, // "http://example.com/path1/path2?key1=value1&key2=va" ==> scheme ":" "//" authority path-abempty "?" query
				51, // "http://example.com/path1/path2?key1=value1&key2=val" ==> scheme ":" "//" authority path-abempty "?" query
				52, // "http://example.com/path1/path2?key1=value1&key2=valu" ==> scheme ":" "//" authority path-abempty "?" query
				53, // "http://example.com/path1/path2?key1=value1&key2=value" ==> scheme ":" "//" authority path-abempty "?" query
				54, // "http://example.com/path1/path2?key1=value1&key2=value2" ==> scheme ":" "//" authority path-abempty "?" query
			},
		},
		// [ "#" fragment ] test
		{
			testName: "data: []byte(\"http://example.com/path1/path2#\")",
			data:     []byte("http://example.com/path1/path2#"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2#" ==> scheme ":" "//" authority path-abempty "#" fragment
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2#key=value\")",
			data:     []byte("http://example.com/path1/path2#key=value"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2#" ==> scheme ":" "//" authority path-abempty "?" fragment
				32, // "http://example.com/path1/path2#k" ==> scheme ":" "//" authority path-abempty "?" fragment
				33, // "http://example.com/path1/path2#ke" ==> scheme ":" "//" authority path-abempty "?" fragment
				34, // "http://example.com/path1/path2#key" ==> scheme ":" "//" authority path-abempty "?" fragment
				35, // "http://example.com/path1/path2#key=" ==> scheme ":" "//" authority path-abempty "?" fragment
				36, // "http://example.com/path1/path2#key=v" ==> scheme ":" "//" authority path-abempty "?" fragment
				37, // "http://example.com/path1/path2#key=va" ==> scheme ":" "//" authority path-abempty "?" fragment
				38, // "http://example.com/path1/path2#key=val" ==> scheme ":" "//" authority path-abempty "?" fragment
				39, // "http://example.com/path1/path2#key=valu" ==> scheme ":" "//" authority path-abempty "?" fragment
				40, // "http://example.com/path1/path2#key=value" ==> scheme ":" "//" authority path-abempty "?" fragment
			},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2#key1=value1&key2=value2\")",
			data:     []byte("http://example.com/path1/path2#key1=value1&key2=value2"),
			findFunc: FindUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" reg-name
				8,  // "http://e" ==> scheme ":" "//" reg-name
				9,  // "http://ex" ==> scheme ":" "//" reg-name
				10, // "http://exa" ==> scheme ":" "//" reg-name
				11, // "http://exam" ==> scheme ":" "//" reg-name
				12, // "http://examp" ==> scheme ":" "//" reg-name
				13, // "http://exampl" ==> scheme ":" "//" reg-name
				14, // "http://example" ==> scheme ":" "//" reg-name
				15, // "http://example." ==> scheme ":" "//" reg-name
				16, // "http://example.c" ==> scheme ":" "//" reg-name
				17, // "http://example.co" ==> scheme ":" "//" reg-name
				18, // "http://example.com" ==> scheme ":" "//" reg-name
				19, // "http://example.com/" ==> scheme ":" "//" authority path-abempty
				20, // "http://example.com/p" ==> scheme ":" "//" authority path-abempty
				21, // "http://example.com/pa" ==> scheme ":" "//" authority path-abempty
				22, // "http://example.com/pat" ==> scheme ":" "//" authority path-abempty
				23, // "http://example.com/path" ==> scheme ":" "//" authority path-abempty
				24, // "http://example.com/path1" ==> scheme ":" "//" authority path-abempty
				25, // "http://example.com/path1/" ==> scheme ":" "//" authority path-abempty
				26, // "http://example.com/path1/p" ==> scheme ":" "//" authority path-abempty
				27, // "http://example.com/path1/pa" ==> scheme ":" "//" authority path-abempty
				28, // "http://example.com/path1/pat" ==> scheme ":" "//" authority path-abempty
				29, // "http://example.com/path1/path" ==> scheme ":" "//" authority path-abempty
				30, // "http://example.com/path1/path2" ==> scheme ":" "//" authority path-abempty
				31, // "http://example.com/path1/path2#" ==> scheme ":" "//" authority path-abempty "#" fragment
				32, // "http://example.com/path1/path2#k" ==> scheme ":" "//" authority path-abempty "#" fragment
				33, // "http://example.com/path1/path2#ke" ==> scheme ":" "//" authority path-abempty "#" fragment
				34, // "http://example.com/path1/path2#key" ==> scheme ":" "//" authority path-abempty "#" fragment
				35, // "http://example.com/path1/path2#key1" ==> scheme ":" "//" authority path-abempty "#" fragment
				36, // "http://example.com/path1/path2#key1=" ==> scheme ":" "//" authority path-abempty "#" fragment
				37, // "http://example.com/path1/path2#key1=v" ==> scheme ":" "//" authority path-abempty "#" fragment
				38, // "http://example.com/path1/path2#key1=va" ==> scheme ":" "//" authority path-abempty "#" fragment
				39, // "http://example.com/path1/path2#key1=val" ==> scheme ":" "//" authority path-abempty "#" fragment
				40, // "http://example.com/path1/path2#key1=valu" ==> scheme ":" "//" authority path-abempty "#" fragment
				41, // "http://example.com/path1/path2#key1=value" ==> scheme ":" "//" authority path-abempty "#" fragment
				42, // "http://example.com/path1/path2#key1=value1" ==> scheme ":" "//" authority path-abempty "#" fragment
				43, // "http://example.com/path1/path2#key1=value1&" ==> scheme ":" "//" authority path-abempty "#" fragment
				44, // "http://example.com/path1/path2#key1=value1&k" ==> scheme ":" "//" authority path-abempty "#" fragment
				45, // "http://example.com/path1/path2#key1=value1&ke" ==> scheme ":" "//" authority path-abempty "#" fragment
				46, // "http://example.com/path1/path2#key1=value1&key" ==> scheme ":" "//" authority path-abempty "#" fragment
				47, // "http://example.com/path1/path2#key1=value1&key2" ==> scheme ":" "//" authority path-abempty "#" fragment
				48, // "http://example.com/path1/path2#key1=value1&key2=" ==> scheme ":" "//" authority path-abempty "#" fragment
				49, // "http://example.com/path1/path2#key1=value1&key2=v" ==> scheme ":" "//" authority path-abempty "#" fragment
				50, // "http://example.com/path1/path2#key1=value1&key2=va" ==> scheme ":" "//" authority path-abempty "#" fragment
				51, // "http://example.com/path1/path2#key1=value1&key2=val" ==> scheme ":" "//" authority path-abempty "#" fragment
				52, // "http://example.com/path1/path2#key1=value1&key2=valu" ==> scheme ":" "//" authority path-abempty "#" fragment
				53, // "http://example.com/path1/path2#key1=value1&key2=value" ==> scheme ":" "//" authority path-abempty "#" fragment
				54, // "http://example.com/path1/path2#key1=value1&key2=value2" ==> scheme ":" "//" authority path-abempty "#" fragment
			},
		},
	}
	execTest(tests, t)
}

func TestFindHierPart(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindHierPart,
			expectedEnds: []int{
				0, // "" ==> path-empty
			},
		},
		{
			testName: "data: []byte(\"a\")",
			data:     []byte("a"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0, // "" ==> path-empty
				1, // "" ==> path-rootless
			},
		},
		{
			testName: "data: []byte(\"//example.com\")",
			data:     []byte("//example.com"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e" ==> "//" authority path-abempty
				4,  // "//ex" ==> "//" authority path-abempty
				5,  // "//exa" ==> "//" authority path-abempty
				6,  // "//exam" ==> "//" authority path-abempty
				7,  // "//examp" ==> "//" authority path-abempty
				8,  // "//exampl" ==> "//" authority path-abempty
				9,  // "//example" ==> "//" authority path-abempty
				10, // "//example." ==> "//" authority path-abempty
				11, // "//example.c" ==> "//" authority path-abempty
				12, // "//example.co" ==> "//" authority path-abempty
				13, // "//example.com" ==> "//" authority path-abempty
			},
		},
		{
			testName: "data: []byte(\"//example.com/\")",
			data:     []byte("//example.com/"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e" ==> "//" authority path-abempty
				4,  // "//ex" ==> "//" authority path-abempty
				5,  // "//exa" ==> "//" authority path-abempty
				6,  // "//exam" ==> "//" authority path-abempty
				7,  // "//examp" ==> "//" authority path-abempty
				8,  // "//exampl" ==> "//" authority path-abempty
				9,  // "//example" ==> "//" authority path-abempty
				10, // "//example." ==> "//" authority path-abempty
				11, // "//example.c" ==> "//" authority path-abempty
				12, // "//example.co" ==> "//" authority path-abempty
				13, // "//example.com" ==> "//" authority path-abempty
				14, // "//example.com/" ==> "//" authority path-abempty
			},
		},
		{
			testName: "data: []byte(\"//example.com/index.html\")",
			data:     []byte("//example.com/index.html"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e" ==> "//" authority path-abempty
				4,  // "//ex" ==> "//" authority path-abempty
				5,  // "//exa" ==> "//" authority path-abempty
				6,  // "//exam" ==> "//" authority path-abempty
				7,  // "//examp" ==> "//" authority path-abempty
				8,  // "//exampl" ==> "//" authority path-abempty
				9,  // "//example" ==> "//" authority path-abempty
				10, // "//example." ==> "//" authority path-abempty
				11, // "//example.c" ==> "//" authority path-abempty
				12, // "//example.co" ==> "//" authority path-abempty
				13, // "//example.com" ==> "//" authority path-abempty
				14, // "//example.com/" ==> "//" authority path-abempty
				15, // "//example.com/i" ==> "//" authority path-abempty
				16, // "//example.com/in" ==> "//" authority path-abempty
				17, // "//example.com/ind" ==> "//" authority path-abempty
				18, // "//example.com/inde" ==> "//" authority path-abempty
				19, // "//example.com/index" ==> "//" authority path-abempty
				20, // "//example.com/index." ==> "//" authority path-abempty
				21, // "//example.com/index.h" ==> "//" authority path-abempty
				22, // "//example.com/index.ht" ==> "//" authority path-abempty
				23, // "//example.com/index.htm" ==> "//" authority path-abempty
				24, // "//example.com/index.html" ==> "//" authority path-abempty
			},
		},
		{
			testName: "data: []byte(\"/\")",
			data:     []byte("/"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0, // "" ==> path-empty
				1, // "/" ==> path-absolute
			},
		},
		{
			testName: "data: []byte(\"/index.html\")",
			data:     []byte("/index.html"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "/i" ==> path-absolute
				3,  // "/in" ==> path-absolute
				4,  // "/ind" ==> path-absolute
				5,  // "/inde" ==> path-absolute
				6,  // "/index" ==> path-absolute
				7,  // "/index." ==> path-absolute
				8,  // "/index.h" ==> path-absolute
				9,  // "/index.ht" ==> path-absolute
				10, // "/index.htm" ==> path-absolute
				11, // "/index.html" ==> path-absolute
			},
		},
		{
			testName: "data: []byte(\"index.html\")",
			data:     []byte("index.html"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "i" ==> path-rootless
				2,  // "in" ==> path-rootless
				3,  // "ind" ==> path-rootless
				4,  // "inde" ==> path-rootless
				5,  // "index" ==> path-rootless
				6,  // "index." ==> path-rootless
				7,  // "index.h" ==> path-rootless
				8,  // "index.ht" ==> path-rootless
				9,  // "index.htm" ==> path-rootless
				10, // "index.html" ==> path-rootless
			},
		},
		{
			testName: "data: []byte(\"path/index.html\")",
			data:     []byte("path/index.html"),
			findFunc: FindHierPart,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "p" ==> path-rootless
				2,  // "pa" ==> path-rootless
				3,  // "pat" ==> path-rootless
				4,  // "path" ==> path-rootless
				5,  // "path/" ==> path-rootless
				6,  // "path/i" ==> path-rootless
				7,  // "path/in" ==> path-rootless
				8,  // "path/ind" ==> path-rootless
				9,  // "path/inde" ==> path-rootless
				10, // "path/index" ==> path-rootless
				11, // "path/index." ==> path-rootless
				12, // "path/index.h" ==> path-rootless
				13, // "path/index.ht" ==> path-rootless
				14, // "path/index.htm" ==> path-rootless
				15, // "path/index.html" ==> path-rootless
			},
		},
	}
	execTest(tests, t)
}

func TestFindScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindScheme,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{'a'}",
			data:     []byte{'a'},
			findFunc: FindScheme,
			expectedEnds: []int{
				1,
			},
		},
		{
			testName: "data: []byte(\"http\")",
			data:     []byte("http"),
			findFunc: FindScheme,
			expectedEnds: []int{
				1, // "h"
				2, // "ht"
				3, // "htt"
				4, // "http"
			},
		},
		{
			testName: "data: []byte(\"http:\")",
			data:     []byte("http:"),
			findFunc: FindScheme,
			expectedEnds: []int{
				1, // "h"
				2, // "ht"
				3, // "htt"
				4, // "http"
			},
		},
	}
	execTest(tests, t)
}

func TestFindAuthority(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindAuthority,
			expectedEnds: []int{
				0, // "" ==> host
			},
		},
		{
			testName: "data: []byte(\"a\")",
			data:     []byte("a"),
			findFunc: FindAuthority,
			expectedEnds: []int{
				0, // "" ==> host
				1, // "a" ==> host
			},
		},
		{
			testName: "data: []byte(\"example.com\")",
			data:     []byte("example.com"),
			findFunc: FindAuthority,
			expectedEnds: []int{
				0,  // "" ==> host
				1,  // "e" ==> host
				2,  // "ex" ==> host
				3,  // "exa" ==> host
				4,  // "exam" ==> host
				5,  // "examp" ==> host
				6,  // "exampl" ==> host
				7,  // "example" ==> host
				8,  // "example." ==> host
				9,  // "example.c" ==> host
				10, // "example.co" ==> host
				11, // "example.com" ==> host
			},
		},
		{
			testName: "data: []byte(\"user:pass@example.com\")",
			data:     []byte("user:pass@example.com"),
			findFunc: FindAuthority,
			expectedEnds: []int{
				0,  // "" ==> host
				1,  // "u" ==> host
				2,  // "us" ==> host
				3,  // "use" ==> host
				4,  // "user" ==> host
				5,  // "user:" ==> host ":" port
				10, // "user:pass@" ==> userinfo "@" host
				11, // "user:pass@e" ==> userinfo "@" host
				12, // "user:pass@ex" ==> userinfo "@" host
				13, // "user:pass@exa" ==> userinfo "@" host
				14, // "user:pass@exam" ==> userinfo "@" host
				15, // "user:pass@examp" ==> userinfo "@" host
				16, // "user:pass@exampl" ==> userinfo "@" host
				17, // "user:pass@example" ==> userinfo "@" host
				18, // "user:pass@example." ==> userinfo "@" host
				19, // "user:pass@example.c" ==> userinfo "@" host
				20, // "user:pass@example.co" ==> userinfo "@" host
				21, // "user:pass@example.com" ==> userinfo "@" host
			},
		},
		{
			testName: "data: []byte(\"user:pass@example.com:443\")",
			data:     []byte("user:pass@example.com:443"),
			findFunc: FindAuthority,
			expectedEnds: []int{
				0,  // "" ==> host
				1,  // "u" ==> host
				2,  // "us" ==> host
				3,  // "use" ==> host
				4,  // "user" ==> host
				5,  // "user:" ==> host ":" port
				10, // "user:pass@" ==> userinfo "@" host
				11, // "user:pass@e" ==> userinfo "@" host
				12, // "user:pass@ex" ==> userinfo "@" host
				13, // "user:pass@exa" ==> userinfo "@" host
				14, // "user:pass@exam" ==> userinfo "@" host
				15, // "user:pass@examp" ==> userinfo "@" host
				16, // "user:pass@exampl" ==> userinfo "@" host
				17, // "user:pass@example" ==> userinfo "@" host
				18, // "user:pass@example." ==> userinfo "@" host
				19, // "user:pass@example.c" ==> userinfo "@" host
				20, // "user:pass@example.co" ==> userinfo "@" host
				21, // "user:pass@example.com" ==> userinfo "@" host
				22, // "user:pass@example.com:" ==> userinfo "@" host ":" port
				23, // "user:pass@example.com:4" ==> userinfo "@" host ":" port
				24, // "user:pass@example.com:44" ==> userinfo "@" host ":" port
				25, // "user:pass@example.com:443" ==> userinfo "@" host ":" port
			},
		},
	}
	execTest(tests, t)
}

func TestFindHost(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindHost,
			expectedEnds: []int{
				0, // "" ==> reg-name
			},
		},
		{
			testName: "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:     []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			findFunc: FindHost,
			expectedEnds: []int{
				0,  // "" ==> reg-name
				41, // "[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]" ==> IP-literal
			},
		},
		{
			testName: "data: []byte(\"255.255.255.255\")",
			data:     []byte("255.255.255.255"),
			findFunc: FindHost,
			expectedEnds: []int{
				0,  // "" ==> reg-name
				1,  // "2" ==> reg-name
				2,  // "25" ==> reg-name
				3,  // "255" ==> reg-name
				4,  // "255." ==> reg-name
				5,  // "255.2" ==> reg-name
				6,  // "255.25" ==> reg-name
				7,  // "255.255" ==> reg-name
				8,  // "255.255." ==> reg-name
				9,  // "255.255.2" ==> reg-name
				10, // "255.255.25" ==> reg-name
				11, // "255.255.255" ==> reg-name
				12, // "255.255.255." ==> reg-name
				13, // "255.255.255.2" ==> reg-name or IPv4address
				14, // "255.255.255.25" ==> reg-name or IPv4address
				15, // "255.255.255.255" ==> reg-name or IPv4address
			},
		},
		{
			testName: "data: []byte(\"www.example.com\")",
			data:     []byte("www.example.com"),
			findFunc: FindHost,
			expectedEnds: []int{
				0,  // "" ==> reg-name
				1,  // "w" ==> reg-name
				2,  // "ww" ==> reg-name
				3,  // "www" ==> reg-name
				4,  // "www." ==> reg-name
				5,  // "www.e" ==> reg-name
				6,  // "www.ex" ==> reg-name
				7,  // "www.exa" ==> reg-name
				8,  // "www.exam" ==> reg-name
				9,  // "www.examp" ==> reg-name
				10, // "www.exampl" ==> reg-name
				11, // "www.example" ==> reg-name
				12, // "www.example." ==> reg-name
				13, // "www.example.c" ==> reg-name
				14, // "www.example.co" ==> reg-name
				15, // "www.example.com" ==> reg-name
			},
		},
	}
	execTest(tests, t)
}

func TestFindUserInfo(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindUserInfo,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName: "data: []byte(\"user\")",
			data:     []byte("user"),
			findFunc: FindUserInfo,
			expectedEnds: []int{
				0,
				1, // "u" ==> unreserved
				2, // "us" ==> unreserved
				3, // "use" ==> unreserved
				4, // "user" ==> unreserved
			},
		},
		{
			testName: "data: []byte(\"user:pass\")",
			data:     []byte("user:pass"),
			findFunc: FindUserInfo,
			expectedEnds: []int{
				0,
				1, // "u" ==> unreserved
				2, // "us" ==> unreserved
				3, // "use" ==> unreserved
				4, // "user" ==> unreserved
				5, // "user:" ==> unreserved ":"
				6, // "user:p" ==> unreserved ":" unreserved
				7, // "user:pa" ==> unreserved ":" unreserved
				8, // "user:pas" ==> unreserved ":" unreserved
				9, // "user:pass" ==> unreserved ":" unreserved
			},
		},
		{
			testName: "data: []byte(\"user:pass@\")",
			data:     []byte("user:pass@"),
			findFunc: FindUserInfo,
			expectedEnds: []int{
				0,
				1, // "u" ==> unreserved
				2, // "us" ==> unreserved
				3, // "use" ==> unreserved
				4, // "user" ==> unreserved
				5, // "user:" ==> unreserved ":" unreserved
				6, // "user:p" ==> unreserved ":" unreserved
				7, // "user:pa" ==> unreserved ":" unreserved
				8, // "user:pas" ==> unreserved ":" unreserved
				9, // "user:pass" ==> unreserved ":" unreserved
			},
		},
	}
	execTest(tests, t)
}

func TestFindIpLiteral(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindIpLiteral,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindIpLiteral,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:     []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			findFunc: FindIpLiteral,
			expectedEnds: []int{
				41,
			},
		},
		{
			testName: "data: []byte(\"[v1.a]\")",
			data:     []byte("[v1.a]"),
			findFunc: FindIpLiteral,
			expectedEnds: []int{
				6,
			},
		},
	}
	execTest(tests, t)
}

func TestFindIpVFuture(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindIpVFuture,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindIpVFuture,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"v1.a\")",
			data:     []byte("v1.a"),
			findFunc: FindIpVFuture,
			expectedEnds: []int{
				4,
			},
		},
		{
			testName: "data: []byte(\"v1F.a,:\")",
			data:     []byte("v1F.a,:"),
			findFunc: FindIpVFuture,
			expectedEnds: []int{
				5, // "v1F.a"
				6, // "v1F.a,"
				7, // "v1F.a,:"
			},
		},
	}
	execTest(tests, t)
}

func TestFindIpV6Address(t *testing.T) {
	tests := []TestCase{
		// 6( h16 ":" ) ls32
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				36, // "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:F"
				37, // "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FF"
				38, // "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFF"
				39, // "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				43, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.2
				44, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.25
				45, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		// "::" 5( h16 ":" ) ls32
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:F
				19, // ::FFFF:FFFF:FFFF:FF
				20, // ::FFFF:FFFF:FFFF:FFF
				21, // ::FFFF:FFFF:FFFF:FFFF
				23, // ::FFFF:FFFF:FFFF:FFFF:F
				24, // ::FFFF:FFFF:FFFF:FFFF:FF
				25, // ::FFFF:FFFF:FFFF:FFFF:FFF
				26, // ::FFFF:FFFF:FFFF:FFFF:FFFF
				28, // ::FFFF:FFFF:FFFF:FFFF:FFFF:F
				29, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FF
				30, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFF
				31, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
				33, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:F
				34, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FF
				35, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFF
				36, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:F
				19, // ::FFFF:FFFF:FFFF:FF
				20, // ::FFFF:FFFF:FFFF:FFF
				21, // ::FFFF:FFFF:FFFF:FFFF
				23, // ::FFFF:FFFF:FFFF:FFFF:F
				24, // ::FFFF:FFFF:FFFF:FFFF:FF
				25, // ::FFFF:FFFF:FFFF:FFFF:FFF
				26, // ::FFFF:FFFF:FFFF:FFFF:FFFF
				28, // ::FFFF:FFFF:FFFF:FFFF:FFFF:2
				29, // ::FFFF:FFFF:FFFF:FFFF:FFFF:25
				30, // ::FFFF:FFFF:FFFF:FFFF:FFFF:255
				40, // ::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.2
				41, // ::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.25
				42, // ::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		// [               h16 ] "::" 4( h16 ":" ) ls32
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
				22, // FFFF::FFFF:FFFF:FFFF:F
				23, // FFFF::FFFF:FFFF:FFFF:FF
				24, // FFFF::FFFF:FFFF:FFFF:FFF
				25, // FFFF::FFFF:FFFF:FFFF:FFFF
				27, // FFFF::FFFF:FFFF:FFFF:FFFF:F
				28, // FFFF::FFFF:FFFF:FFFF:FFFF:FF
				29, // FFFF::FFFF:FFFF:FFFF:FFFF:FFF
				30, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF
				32, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:F
				33, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FF
				34, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFF
				35, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
				22, // FFFF::FFFF:FFFF:FFFF:F
				23, // FFFF::FFFF:FFFF:FFFF:FF
				24, // FFFF::FFFF:FFFF:FFFF:FFF
				25, // FFFF::FFFF:FFFF:FFFF:FFFF
				27, // FFFF::FFFF:FFFF:FFFF:FFFF:2
				28, // FFFF::FFFF:FFFF:FFFF:FFFF:25
				29, // FFFF::FFFF:FFFF:FFFF:FFFF:255
				39, // FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.2
				40, // FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.25
				41, // FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:F
				19, // ::FFFF:FFFF:FFFF:FF
				20, // ::FFFF:FFFF:FFFF:FFF
				21, // ::FFFF:FFFF:FFFF:FFFF
				23, // ::FFFF:FFFF:FFFF:FFFF:F
				24, // ::FFFF:FFFF:FFFF:FFFF:FF
				25, // ::FFFF:FFFF:FFFF:FFFF:FFF
				26, // ::FFFF:FFFF:FFFF:FFFF:FFFF
				28, // ::FFFF:FFFF:FFFF:FFFF:FFFF:F
				29, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FF
				30, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFF
				31, // ::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:F
				19, // ::FFFF:FFFF:FFFF:FF
				20, // ::FFFF:FFFF:FFFF:FFF
				21, // ::FFFF:FFFF:FFFF:FFFF
				23, // ::FFFF:FFFF:FFFF:FFFF:2
				24, // ::FFFF:FFFF:FFFF:FFFF:25
				25, // ::FFFF:FFFF:FFFF:FFFF:255
				35, // ::FFFF:FFFF:FFFF:FFFF:255.255.255.2
				36, // ::FFFF:FFFF:FFFF:FFFF:255.255.255.25
				37, // ::FFFF:FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
				22, // FFFF:FFFF::FFFF:FFFF:F
				23, // FFFF:FFFF::FFFF:FFFF:FF
				24, // FFFF:FFFF::FFFF:FFFF:FFF
				25, // FFFF:FFFF::FFFF:FFFF:FFFF
				27, // FFFF:FFFF::FFFF:FFFF:FFFF:F
				28, // FFFF:FFFF::FFFF:FFFF:FFFF:FF
				29, // FFFF:FFFF::FFFF:FFFF:FFFF:FFF
				30, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF
				32, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:F
				33, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FF
				34, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFF
				35, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
				22, // FFFF:FFFF::FFFF:FFFF:F
				23, // FFFF:FFFF::FFFF:FFFF:FF
				24, // FFFF:FFFF::FFFF:FFFF:FFF
				25, // FFFF:FFFF::FFFF:FFFF:FFFF
				27, // FFFF:FFFF::FFFF:FFFF:FFFF.2
				28, // FFFF:FFFF::FFFF:FFFF:FFFF.25
				29, // FFFF:FFFF::FFFF:FFFF:FFFF.255
				39, // FFFF:FFFF::FFFF:FFFF:FFFF.255.255.255.2
				40, // FFFF:FFFF::FFFF:FFFF:FFFF.255.255.255.25
				41, // FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
				22, // FFFF::FFFF:FFFF:FFFF:F
				23, // FFFF::FFFF:FFFF:FFFF:FF
				24, // FFFF::FFFF:FFFF:FFFF:FFF
				25, // FFFF::FFFF:FFFF:FFFF:FFFF
				27, // FFFF::FFFF:FFFF:FFFF:FFFF:F
				28, // FFFF::FFFF:FFFF:FFFF:FFFF:FF
				29, // FFFF::FFFF:FFFF:FFFF:FFFF:FFF
				30, // FFFF::FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
				22, // FFFF::FFFF:FFFF:FFFF:2
				23, // FFFF::FFFF:FFFF:FFFF:25
				24, // FFFF::FFFF:FFFF:FFFF:255
				34, // FFFF::FFFF:FFFF:FFFF:255.255.255.2
				35, // FFFF::FFFF:FFFF:FFFF:255.255.255.25
				36, // FFFF::FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("::FFFF:FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:F
				19, // ::FFFF:FFFF:FFFF:FF
				20, // ::FFFF:FFFF:FFFF:FFF
				21, // ::FFFF:FFFF:FFFF:FFFF
				23, // ::FFFF:FFFF:FFFF:FFFF:F
				24, // ::FFFF:FFFF:FFFF:FFFF:FF
				25, // ::FFFF:FFFF:FFFF:FFFF:FFF
				26, // ::FFFF:FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:     []byte("::FFFF:FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
				18, // ::FFFF:FFFF:FFFF:2
				19, // ::FFFF:FFFF:FFFF:25
				20, // ::FFFF:FFFF:FFFF:255
				30, // ::FFFF:FFFF:FFFF:255.255.255.2
				31, // ::FFFF:FFFF:FFFF:255.255.255.25
				32, // ::FFFF:FFFF:FFFF:255.255.255.255
			},
		},
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:F
				23, // FFFF:FFFF:FFFF::FFFF:FF
				24, // FFFF:FFFF:FFFF::FFFF:FFF
				25, // FFFF:FFFF:FFFF::FFFF:FFFF
				27, // FFFF:FFFF:FFFF::FFFF:FFFF:F
				28, // FFFF:FFFF:FFFF::FFFF:FFFF:FF
				29, // FFFF:FFFF:FFFF::FFFF:FFFF:FFF
				30, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF
				32, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:F
				33, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FF
				34, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFF
				35, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:F
				23, // FFFF:FFFF:FFFF::FFFF:FF
				24, // FFFF:FFFF:FFFF::FFFF:FFF
				25, // FFFF:FFFF:FFFF::FFFF:FFFF
				27, // FFFF:FFFF:FFFF::FFFF:FFFF:2
				28, // FFFF:FFFF:FFFF::FFFF:FFFF:25
				29, // FFFF:FFFF:FFFF::FFFF:FFFF:255
				39, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.2
				40, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.25
				41, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
				22, // FFFF:FFFF::FFFF:FFFF:F
				23, // FFFF:FFFF::FFFF:FFFF:FF
				24, // FFFF:FFFF::FFFF:FFFF:FFF
				25, // FFFF:FFFF::FFFF:FFFF:FFFF
				27, // FFFF:FFFF::FFFF:FFFF:FFFF:F
				28, // FFFF:FFFF::FFFF:FFFF:FFFF:FF
				29, // FFFF:FFFF::FFFF:FFFF:FFFF:FFF
				30, // FFFF:FFFF::FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:F
				23, // FFFF:FFFF:FFFF::FFFF:FF
				24, // FFFF:FFFF:FFFF::FFFF:FFF
				25, // FFFF:FFFF:FFFF::FFFF:FFFF
				27, // FFFF:FFFF:FFFF::FFFF:FFFF:2
				28, // FFFF:FFFF:FFFF::FFFF:FFFF:25
				29, // FFFF:FFFF:FFFF::FFFF:FFFF:255
				39, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.2
				40, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.25
				41, // FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
				22, // FFFF::FFFF:FFFF:FFFF:F
				23, // FFFF::FFFF:FFFF:FFFF:FF
				24, // FFFF::FFFF:FFFF:FFFF:FFF
				25, // FFFF::FFFF:FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
				22, // FFFF:FFFF::FFFF:FFFF:2
				23, // FFFF:FFFF::FFFF:FFFF:25
				24, // FFFF:FFFF::FFFF:FFFF:255
				34, // FFFF:FFFF::FFFF:FFFF:255.255.255.2
				35, // FFFF:FFFF::FFFF:FFFF:255.255.255.25
				36, // FFFF:FFFF::FFFF:FFFF:255.255.255.255
			},
		},
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				21, // FFFF:FFFF:FFFF:FFFF::
				22, // FFFF:FFFF:FFFF:FFFF::F
				23, // FFFF:FFFF:FFFF:FFFF::FF
				24, // FFFF:FFFF:FFFF:FFFF::FFF
				25, // FFFF:FFFF:FFFF:FFFF::FFFF
				27, // FFFF:FFFF:FFFF:FFFF::FFFF:F
				28, // FFFF:FFFF:FFFF:FFFF::FFFF:FF
				29, // FFFF:FFFF:FFFF:FFFF::FFFF:FFF
				30, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF
				32, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:F
				33, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FF
				34, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFF
				35, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				21, // FFFF:FFFF:FFFF:FFFF::
				22, // FFFF:FFFF:FFFF:FFFF::F
				23, // FFFF:FFFF:FFFF:FFFF::FF
				24, // FFFF:FFFF:FFFF:FFFF::FFF
				25, // FFFF:FFFF:FFFF:FFFF::FFFF
				27, // FFFF:FFFF:FFFF:FFFF::FFFF:2
				28, // FFFF:FFFF:FFFF:FFFF::FFFF:25
				29, // FFFF:FFFF:FFFF:FFFF::FFFF:255
				39, // FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.2
				40, // FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.25
				41, // FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:F
				23, // FFFF:FFFF:FFFF::FFFF:FF
				24, // FFFF:FFFF:FFFF::FFFF:FFF
				25, // FFFF:FFFF:FFFF::FFFF:FFFF
				27, // FFFF:FFFF:FFFF::FFFF:FFFF:F
				28, // FFFF:FFFF:FFFF::FFFF:FFFF:FF
				29, // FFFF:FFFF:FFFF::FFFF:FFFF:FFF
				30, // FFFF:FFFF:FFFF::FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:2
				23, // FFFF:FFFF:FFFF::FFFF:25
				24, // FFFF:FFFF:FFFF::FFFF:255
				34, // FFFF:FFFF:FFFF::FFFF:255.255.255.2
				35, // FFFF:FFFF:FFFF::FFFF:255.255.255.25
				36, // FFFF:FFFF:FFFF::FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
				22, // FFFF:FFFF::FFFF:FFFF:F
				23, // FFFF:FFFF::FFFF:FFFF:FF
				24, // FFFF:FFFF::FFFF:FFFF:FFF
				25, // FFFF:FFFF::FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:255.255.255.255\")",
			data:     []byte("FFFF:FFFF::FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:2
				18, // FFFF:FFFF::FFFF:25
				19, // FFFF:FFFF::FFFF:255
				29, // FFFF:FFFF::FFFF:255.255.255.2
				30, // FFFF:FFFF::FFFF:255.255.255.25
				31, // FFFF:FFFF::FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF:FFFF\")",
			data:     []byte("FFFF::FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
				17, // FFFF::FFFF:FFFF:F
				18, // FFFF::FFFF:FFFF:FF
				19, // FFFF::FFFF:FFFF:FFF
				20, // FFFF::FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:255.255.255.255\")",
			data:     []byte("FFFF::FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:2
				13, // FFFF::FFFF:25
				14, // FFFF::FFFF:255
				24, // FFFF::FFFF:255.255.255.2
				25, // FFFF::FFFF:255.255.255.25
				26, // FFFF::FFFF:255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF:FFFF\")",
			data:     []byte("::FFFF:FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
				13, // ::FFFF:FFFF:F
				14, // ::FFFF:FFFF:FF
				15, // ::FFFF:FFFF:FFF
				16, // ::FFFF:FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"::FFFF:255.255.255.255\")",
			data:     []byte("::FFFF:255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:2
				9,  // ::FFFF:25
				10, // ::FFFF:255
				20, // ::FFFF:255.255.255.2
				21, // ::FFFF:255.255.255.25
				22, // ::FFFF:255.255.255.255
			},
		},
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				26, // FFFF:FFFF:FFFF:FFFF:FFFF::
				27, // FFFF:FFFF:FFFF:FFFF:FFFF::F
				28, // FFFF:FFFF:FFFF:FFFF:FFFF::FF
				29, // FFFF:FFFF:FFFF:FFFF:FFFF::FFF
				30, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF
				32, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:F
				33, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FF
				34, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFF
				35, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				26, // FFFF:FFFF:FFFF:FFFF:FFFF::
				27, // FFFF:FFFF:FFFF:FFFF:FFFF::2
				28, // FFFF:FFFF:FFFF:FFFF:FFFF::25
				29, // FFFF:FFFF:FFFF:FFFF:FFFF::255
				39, // FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.2
				40, // FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.25
				41, // FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				21, // FFFF:FFFF:FFFF:FFFF::
				22, // FFFF:FFFF:FFFF:FFFF::F
				23, // FFFF:FFFF:FFFF:FFFF::FF
				24, // FFFF:FFFF:FFFF:FFFF::FFF
				25, // FFFF:FFFF:FFFF:FFFF::FFFF
				27, // FFFF:FFFF:FFFF:FFFF::FFFF:F
				28, // FFFF:FFFF:FFFF:FFFF::FFFF:FF
				29, // FFFF:FFFF:FFFF:FFFF::FFFF:FFF
				30, // FFFF:FFFF:FFFF:FFFF::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				21, // FFFF:FFFF:FFFF:FFFF::
				22, // FFFF:FFFF:FFFF:FFFF::2
				23, // FFFF:FFFF:FFFF:FFFF::25
				24, // FFFF:FFFF:FFFF:FFFF::255
				34, // FFFF:FFFF:FFFF:FFFF::255.255.255.2
				35, // FFFF:FFFF:FFFF:FFFF::255.255.255.25
				36, // FFFF:FFFF:FFFF:FFFF::255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
				22, // FFFF:FFFF:FFFF::FFFF:F
				23, // FFFF:FFFF:FFFF::FFFF:FF
				24, // FFFF:FFFF:FFFF::FFFF:FFF
				25, // FFFF:FFFF:FFFF::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::255.255.255.255\")",
			data:     []byte("FFFF:FFFF:FFFF::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::2
				18, // FFFF:FFFF:FFFF::25
				19, // FFFF:FFFF:FFFF::255
				29, // FFFF:FFFF:FFFF::255.255.255.2
				30, // FFFF:FFFF:FFFF::255.255.255.25
				31, // FFFF:FFFF:FFFF::255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF:FFFF\")",
			data:     []byte("FFFF:FFFF::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
				17, // FFFF:FFFF::FFFF:F
				18, // FFFF:FFFF::FFFF:FF
				19, // FFFF:FFFF::FFFF:FFF
				20, // FFFF:FFFF::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::255.255.255.255\")",
			data:     []byte("FFFF:FFFF::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::2
				13, // FFFF:FFFF::25
				14, // FFFF:FFFF::255
				24, // FFFF:FFFF::255.255.255.2
				25, // FFFF:FFFF::255.255.255.25
				26, // FFFF:FFFF::255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF:FFFF\")",
			data:     []byte("FFFF::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
				12, // FFFF::FFFF:F
				13, // FFFF::FFFF:FF
				14, // FFFF::FFFF:FFF
				15, // FFFF::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF::255.255.255.255\")",
			data:     []byte("FFFF::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::2
				8,  // FFFF::25
				9,  // FFFF::255
				19, // FFFF::255.255.255.2
				20, // FFFF::255.255.255.25
				21, // FFFF::255.255.255.255
			},
		},
		{
			testName: "data: []byte(\"::FFFF:FFFF\")",
			data:     []byte("::FFFF:FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::F
				4,  // ::FF
				5,  // ::FFF
				6,  // ::FFFF
				8,  // ::FFFF:F
				9,  // ::FFFF:FF
				10, // ::FFFF:FFF
				11, // ::FFFF:FFFF
			},
		},
		{
			testName: "data: []byte(\"::255.255.255.255\")",
			data:     []byte("::255.255.255.255"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2,  // ::
				3,  // ::2
				4,  // ::25
				5,  // ::255
				15, // ::255.255.255.2
				16, // ::255.255.255.25
				17, // ::255.255.255.255
			},
		},
		// [ *5( h16 ":" ) h16 ] "::"              h16
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				31, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::
				32, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::F
				33, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FF
				34, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFF
				35, // FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				26, // FFFF:FFFF:FFFF:FFFF:FFFF::
				27, // FFFF:FFFF:FFFF:FFFF:FFFF::F
				28, // FFFF:FFFF:FFFF:FFFF:FFFF::FF
				29, // FFFF:FFFF:FFFF:FFFF:FFFF::FFF
				30, // FFFF:FFFF:FFFF:FFFF:FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF:FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				21, // FFFF:FFFF:FFFF:FFFF::
				22, // FFFF:FFFF:FFFF:FFFF::F
				23, // FFFF:FFFF:FFFF:FFFF::FF
				24, // FFFF:FFFF:FFFF:FFFF::FFF
				25, // FFFF:FFFF:FFFF:FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF:FFFF::FFFF\")",
			data:     []byte("FFFF:FFFF:FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				16, // FFFF:FFFF:FFFF::
				17, // FFFF:FFFF:FFFF::F
				18, // FFFF:FFFF:FFFF::FF
				19, // FFFF:FFFF:FFFF::FFF
				20, // FFFF:FFFF:FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF:FFFF::FFFF\")",
			data:     []byte("FFFF:FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				11, // FFFF:FFFF::
				12, // FFFF:FFFF::F
				13, // FFFF:FFFF::FF
				14, // FFFF:FFFF::FFF
				15, // FFFF:FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"FFFF::FFFF\")",
			data:     []byte("FFFF::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				6,  // FFFF::
				7,  // FFFF::F
				8,  // FFFF::FF
				9,  // FFFF::FFF
				10, // FFFF::FFFF
			},
		},
		{
			testName: "data: []byte(\"::FFFF\")",
			data:     []byte("::FFFF"),
			findFunc: FindIpV6Address,
			expectedEnds: []int{
				2, // ::
				3, // ::F
				4, // ::FF
				5, // ::FFF
				6, // ::FFFF
			},
		},
		// [ *6( h16 ":" ) h16 ] "::"
		{
			testName:     "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{36},
		},
		{
			testName:     "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{31},
		},
		{
			testName:     "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF:FFFF:FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{26},
		},
		{
			testName:     "data: []byte(\"FFFF:FFFF:FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF:FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{21},
		},
		{
			testName:     "data: []byte(\"FFFF:FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{16},
		},
		{
			testName:     "data: []byte(\"FFFF:FFFF::\")",
			data:         []byte("FFFF:FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{11},
		},
		{
			testName:     "data: []byte(\"FFFF::\")",
			data:         []byte("FFFF::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{6},
		},
		{
			testName:     "data: []byte(\"::\")",
			data:         []byte("::"),
			findFunc:     FindIpV6Address,
			expectedEnds: []int{2},
		},
	}
	execTest(tests, t)
}

func TestFindLs32(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindLs32,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindLs32,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"12AB:34CD\")",
			data:     []byte("12AB:34CD"),
			findFunc: FindLs32,
			expectedEnds: []int{
				6, // 12AB:3
				7, // 12AB:34
				8, // 12AB:34C
				9, // 12AB:34CD
			},
		},
		{
			testName:     "data: []byte(1.2.3.4)",
			data:         []byte("1.2.3.4"),
			findFunc:     FindLs32,
			expectedEnds: []int{7},
		},
	}
	execTest(tests, t)
}

func TestFindH16(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindH16,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindH16,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"1\")",
			data:         []byte("1"),
			findFunc:     FindH16,
			expectedEnds: []int{1},
		},
		{
			testName: "data: []byte(\"12AB\")",
			data:     []byte("12AB"),
			findFunc: FindH16,
			expectedEnds: []int{
				1, // 1
				2, // 12
				3, // 12A
				4, // 12AB
			},
		},
		{
			testName: "data: []byte(\"12ABC\")",
			data:     []byte("12ABC"),
			findFunc: FindH16,
			expectedEnds: []int{
				1, // 1
				2, // 12
				3, // 12A
				4, // 12AB
			},
		},
	}
	execTest(tests, t)
}

func TestFindIpV4Address(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindIpV4Address,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindIpV4Address,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"1.2.3.4\")",
			data:         []byte("1.2.3.4"),
			findFunc:     FindIpV4Address,
			expectedEnds: []int{7},
		},
		{
			testName: "data: []byte(\"101.102.103.104\")",
			data:     []byte("101.102.103.104"),
			findFunc: FindIpV4Address,
			expectedEnds: []int{
				13, // 101.102.103.1
				14, // 101.102.103.10
				15, // 101.102.103.104
			},
		},
	}
	execTest(tests, t)
}

func TestFindDecOctet(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindDecOctet,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"0\")",
			data:         []byte("0"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte(\"9\")",
			data:         []byte("9"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte(\"10\")",
			data:         []byte("10"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2},
		},
		{
			testName:     "data: []byte(\"99\")",
			data:         []byte("99"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2},
		},
		{
			testName:     "data: []byte(\"100\")",
			data:         []byte("100"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"199\")",
			data:         []byte("199"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"200\")",
			data:         []byte("200"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"249\")",
			data:         []byte("249"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"250\")",
			data:         []byte("250"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"255\")",
			data:         []byte("255"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2, 3},
		},
		{
			testName:     "data: []byte(\"256\")",
			data:         []byte("256"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1, 2},
		},
		{
			testName:     "data: []byte(\"1.2\")",
			data:         []byte("1.2"),
			findFunc:     FindDecOctet,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindRegName(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRegName,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindRegName,
			expectedEnds: []int{0, 1},
		},
		{
			testName:     "data: []byte(\"%1A\")",
			data:         []byte("%1A"),
			findFunc:     FindRegName,
			expectedEnds: []int{0, 3},
		},
		{
			testName:     "data: []byte(\"!\")",
			data:         []byte("!"),
			findFunc:     FindRegName,
			expectedEnds: []int{0, 1},
		},
	}
	execTest(tests, t)
}

func TestFindPort(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPort,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"1\")",
			data:         []byte("1"),
			findFunc:     FindPort,
			expectedEnds: []int{0, 1},
		},
		{
			testName:     "data: []byte(\"80\")",
			data:         []byte("80"),
			findFunc:     FindPort,
			expectedEnds: []int{0, 1, 2},
		},
		{
			testName:     "data: []byte(\"443\")",
			data:         []byte("443"),
			findFunc:     FindPort,
			expectedEnds: []int{0, 1, 2, 3},
		},
	}
	execTest(tests, t)
}

func TestFindPath(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPath,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"/path\")",
			data:         []byte("/path"),
			findFunc:     FindPath,
			expectedEnds: []int{0, 1, 2, 3, 4, 5},
		},
		{
			testName:     "data: []byte(\"path\")",
			data:         []byte("path"),
			findFunc:     FindPath,
			expectedEnds: []int{0, 1, 2, 3, 4},
		},
		{
			testName:     "data: []byte(\"/path1/path2\")",
			data:         []byte("/path1/path2"),
			findFunc:     FindPath,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
		{
			testName:     "data: []byte(\"path1/path2\")",
			data:         []byte("path1/path2"),
			findFunc:     FindPath,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		},
		{
			testName:     "data: []byte(\":path1/path2\")",
			data:         []byte(":path1/path2"),
			findFunc:     FindPath,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
	}
	execTest(tests, t)
}

func TestFindPathAbempty(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindPathAbempty,
			expectedEnds: []int{
				0, // "" ==> path-abempty
			},
		},
		{
			testName: "data: []byte(\"/path\")",
			data:     []byte("/path"),
			findFunc: FindPathAbempty,
			expectedEnds: []int{
				0, // "" ==> path-abempty
				1, // "/" ==> path-abempty
				2, // "/p" ==> path-abempty
				3, // "/pa" ==> path-abempty
				4, // "/pat" ==> path-abempty
				5,
			},
		},
		{
			testName: "data: []byte(\"path\")",
			data:     []byte("path"),
			findFunc: FindPathAbempty,
			expectedEnds: []int{
				0, // "" ==> path-abempty
			},
		},
		{
			testName: "data: []byte(\"/path1/path2\")",
			data:     []byte("/path1/path2"),
			findFunc: FindPathAbempty,
			expectedEnds: []int{
				0,  // "" ==> path-abempty
				1,  // "/"" ==> path-abempty
				2,  // "/p" ==> path-abempty
				3,  // "/pa" ==> path-abempty
				4,  // "/pat" ==> path-abempty
				5,  // "/path" ==> path-abempty
				6,  // "/path1" ==> path-abempty
				7,  // "/path1/" ==> path-abempty
				8,  // "/path1/p" ==> path-abempty
				9,  // "/path1/pa" ==> path-abempty
				10, // "/path1/pat" ==> path-abempty
				11, // "/path1/path" ==> path-abempty
				12,
			},
		},
		{
			testName: "data: []byte(\":path1/path2\")",
			data:     []byte(":path1/path2"),
			findFunc: FindPathAbempty,
			expectedEnds: []int{
				0, // "" ==> path-abempty
			},
		},
	}
	execTest(tests, t)
}

func TestFindPathAbsolute(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/path\")",
			data:         []byte("/path"),
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{1, 2, 3, 4, 5},
		},
		{
			testName:     "data: []byte(\"path\")",
			data:         []byte("path"),
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/path1/path2\")",
			data:         []byte("/path1/path2"),
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
		{
			testName:     "data: []byte(\"path1/path2\")",
			data:         []byte("path1/path2"),
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\":path1/path2\")",
			data:         []byte(":path1/path2"),
			findFunc:     FindPathAbsolute,
			expectedEnds: []int{},
		},
	}
	execTest(tests, t)
}

func TestFindPathNoScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/path\")",
			data:         []byte("/path"),
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"path\")",
			data:         []byte("path"),
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{1, 2, 3, 4},
		},
		{
			testName:     "data: []byte(\"/path1/path2\")",
			data:         []byte("/path1/path2"),
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"path1/path2\")",
			data:         []byte("path1/path2"),
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		},
		{
			testName:     "data: []byte(\":path1/path2\")",
			data:         []byte(":path1/path2"),
			findFunc:     FindPathNoScheme,
			expectedEnds: []int{},
		},
	}
	execTest(tests, t)
}

func TestFindPathRootless(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPathRootless,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"/path\")",
			data:         []byte("/path"),
			findFunc:     FindPathRootless,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"path\")",
			data:         []byte("path"),
			findFunc:     FindPathRootless,
			expectedEnds: []int{1, 2, 3, 4},
		},
		{
			testName:     "data: []byte(\"/path1/path2\")",
			data:         []byte("/path1/path2"),
			findFunc:     FindPathRootless,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"path1/path2\")",
			data:         []byte("path1/path2"),
			findFunc:     FindPathRootless,
			expectedEnds: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		},
		{
			testName:     "data: []byte(\":path1/path2\")",
			data:         []byte(":path1/path2"),
			findFunc:     FindPathRootless,
			expectedEnds: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
	}
	execTest(tests, t)
}

func TestFindPathEmpty(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPathEmpty,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"/path\")",
			data:         []byte("/path"),
			findFunc:     FindPathEmpty,
			expectedEnds: []int{0},
		},
	}
	execTest(tests, t)
}

func TestFindSegment(t *testing.T) {
	tests := []TestCase{
		{
			testName: "data: []byte{}",
			data:     []byte{},
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
			},
		},
		{
			testName: "data: []byte{'a'}",
			data:     []byte{'a'},
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte(\"%1A\")",
			data:     []byte("%1A"),
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
				3,
			},
		},
		{
			testName: "data: []byte{'!'}",
			data:     []byte{'!'},
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte{':'}",
			data:     []byte{':'},
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte{'@'}",
			data:     []byte{'@'},
			findFunc: FindSegment,
			expectedEnds: []int{
				0,
				1,
			},
		},
	}
	execTest(tests, t)
}

func TestFindSegmentNz(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindSegmentNz,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindSegmentNz,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte(\"%1A\")",
			data:         []byte("%1A"),
			findFunc:     FindSegmentNz,
			expectedEnds: []int{3},
		},
		{
			testName:     "data: []byte{'!'}",
			data:         []byte{'!'},
			findFunc:     FindSegmentNz,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{':'}",
			data:         []byte{':'},
			findFunc:     FindSegmentNz,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte{'@'}",
			data:         []byte{'@'},
			findFunc:     FindSegmentNz,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindSegmentNzNc(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte(\"%1A\")",
			data:         []byte("%1A"),
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{3},
		},
		{
			testName:     "data: []byte(\"!\")",
			data:         []byte("!"),
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{1},
		},
		{
			testName:     "data: []byte(\":\")",
			data:         []byte(":"),
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"@\")",
			data:         []byte("@"),
			findFunc:     FindSegmentNzNc,
			expectedEnds: []int{1},
		},
	}
	execTest(tests, t)
}

func TestFindPchar(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindPchar,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte{'a'}",
			data:     []byte{'a'},
			findFunc: FindPchar,
			expectedEnds: []int{
				1, // "a" ==> unreserved
			},
		},
		{
			testName: "data: []byte(\"%1A\")",
			data:     []byte("%1A"),
			findFunc: FindPchar,
			expectedEnds: []int{
				3, // "%1A" ==> pct-encoded
			},
		},
		{
			testName: "data: []byte(\"!\")",
			data:     []byte("!"),
			findFunc: FindPchar,
			expectedEnds: []int{
				1, // "!" ==> sub-delims
			},
		},
		{
			testName: "data: []byte(\":\")",
			data:     []byte(":"),
			findFunc: FindPchar,
			expectedEnds: []int{
				1, // ":" ==> ":"
			},
		},
		{
			testName: "data: []byte(\"@\")",
			data:     []byte("@"),
			findFunc: FindPchar,
			expectedEnds: []int{
				1, // "@" ==> "@"
			},
		},
	}
	execTest(tests, t)
}

func TestFindQuery(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindQuery,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindQuery,
			expectedEnds: []int{0, 1},
		},
		{
			testName:     "data: []byte(\"key=value\")",
			data:         []byte("key=value"),
			findFunc:     FindQuery,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			testName:     "data: []byte(\"key1=value1&key2=value2\")",
			data:         []byte("ke1y=value1&key2=value2"),
			findFunc:     FindQuery,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
	}
	execTest(tests, t)
}

func TestFindFragment(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindFragment,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte{'a'}",
			data:         []byte{'a'},
			findFunc:     FindFragment,
			expectedEnds: []int{0, 1},
		},
		{
			testName:     "data: []byte(\"key=value\")",
			data:         []byte("key=value"),
			findFunc:     FindFragment,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			testName:     "data: []byte(\"key1=value1&key2=value2\")",
			data:         []byte("ke1y=value1&key2=value2"),
			findFunc:     FindFragment,
			expectedEnds: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
		},
	}
	execTest(tests, t)
}

func TestFindUriReference(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindUriReference,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindUriReference,
			expectedEnds: []int{0, 1},
		},
		// URI
		{
			testName: "data: []byte(\"http://example.com/index.html?key1=value1#key2=value2\")",
			data:     []byte("http://example.com/index.html?key1=value1#key2=value2"),
			findFunc: FindUriReference,
			expectedEnds: []int{
				0,
				1,  // "h" ==> path-noscheme
				2,  // "ht" ==> path-noscheme
				3,  // "htt" ==> path-noscheme
				4,  // "http" ==> path-noscheme
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" authority path-abempty
				8,  // "http://e"
				9,  // "http://ex"
				10, // "http://exa"
				11, // "http://exam"
				12, // "http://examp"
				13, // "http://exampl"
				14, // "http://example"
				15, // "http://example."
				16, // "http://example.c"
				17, // "http://example.co"
				18, // "http://example.com"
				19, // "http://example.com/"
				20, // "http://example.com/i"
				21, // "http://example.com/in"
				22, // "http://example.com/ind"
				23, // "http://example.com/inde"
				24, // "http://example.com/index"
				25, // "http://example.com/index."
				26, // "http://example.com/index.h"
				27, // "http://example.com/index.ht"
				28, // "http://example.com/index.htm"
				29, // "http://example.com/index.html"
				30, // "http://example.com/index.html?"
				31, // "http://example.com/index.html?k"
				32, // "http://example.com/index.html?ke"
				33, // "http://example.com/index.html?key"
				34, // "http://example.com/index.html?key1"
				35, // "http://example.com/index.html?key1="
				36, // "http://example.com/index.html?key1=v"
				37, // "http://example.com/index.html?key1=va"
				38, // "http://example.com/index.html?key1=val"
				39, // "http://example.com/index.html?key1=valu"
				40, // "http://example.com/index.html?key1=value"
				41, // "http://example.com/index.html?key1=value1"
				42, // "http://example.com/index.html?key1=value1#"
				43, // "http://example.com/index.html?key1=value1#k"
				44, // "http://example.com/index.html?key1=value1#ke"
				45, // "http://example.com/index.html?key1=value1#key"
				46, // "http://example.com/index.html?key1=value1#key2"
				47, // "http://example.com/index.html?key1=value1#key2="
				48, // "http://example.com/index.html?key1=value1#key2=v"
				49, // "http://example.com/index.html?key1=value1#key2=va"
				50, // "http://example.com/index.html?key1=value1#key2=val"
				51, // "http://example.com/index.html?key1=value1#key2=valu"
				52, // "http://example.com/index.html?key1=value1#key2=value"
				53, // "http://example.com/index.html?key1=value1#key2=value2"
			},
		},
		// relative-ref
		{
			testName: "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:     []byte("//example.com/index.html?key1=value1#key2=value2"),
			findFunc: FindUriReference,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e"
				4,  // "//ex"
				5,  // "//exa"
				6,  // "//exam"
				7,  // "//examp"
				8,  // "//exampl"
				9,  // "//example"
				10, // "//example."
				11, // "//example.c"
				12, // "//example.co"
				13, // "//example.com"
				14, // "//example.com/"
				15, // "//example.com/i"
				16, // "//example.com/in"
				17, // "//example.com/ind"
				18, // "//example.com/inde"
				19, // "//example.com/index"
				20, // "//example.com/index."
				21, // "//example.com/index.h"
				22, // "//example.com/index.ht"
				23, // "//example.com/index.htm"
				24, // "//example.com/index.html"
				25, // "//example.com/index.html?"
				26, // "//example.com/index.html?k"
				27, // "//example.com/index.html?ke"
				28, // "//example.com/index.html?key"
				29, // "//example.com/index.html?key1"
				30, // "//example.com/index.html?key1="
				31, // "//example.com/index.html?key1=v"
				32, // "//example.com/index.html?key1=va"
				33, // "//example.com/index.html?key1=val"
				34, // "//example.com/index.html?key1=valu"
				35, // "//example.com/index.html?key1=value"
				36, // "//example.com/index.html?key1=value1"
				37, // "//example.com/index.html?key1=value1#"
				38, // "//example.com/index.html?key1=value1#k"
				39, // "//example.com/index.html?key1=value1#ke"
				40, // "//example.com/index.html?key1=value1#key"
				41, // "//example.com/index.html?key1=value1#key2"
				42, // "//example.com/index.html?key1=value1#key2="
				43, // "//example.com/index.html?key1=value1#key2=v"
				44, // "//example.com/index.html?key1=value1#key2=va"
				45, // "//example.com/index.html?key1=value1#key2=val"
				46, // "//example.com/index.html?key1=value1#key2=valu"
				47, // "//example.com/index.html?key1=value1#key2=value"
				48, // "//example.com/index.html?key1=value1#key2=value2"
			},
		},
	}
	execTest(tests, t)
}

func TestFindRelativeRef(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRelativeRef,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindRelativeRef,
			expectedEnds: []int{0, 1},
		},
		{
			testName: "data: []byte(\"//example.com/index.html\")",
			data:     []byte("//example.com/index.html"),
			findFunc: FindRelativeRef,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
				14,
				15,
				16,
				17,
				18,
				19,
				20,
				21,
				22,
				23,
				24,
			},
		},
		{
			testName: "data: []byte(\"//example.com/index.html?key=value\")",
			data:     []byte("//example.com/index.html?key=value"),
			findFunc: FindRelativeRef,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e"
				4,  // "//ex"
				5,  // "//exa"
				6,  // "//exam"
				7,  // "//examp"
				8,  // "//exampl"
				9,  // "//example"
				10, // "//example."
				11, // "//example.c"
				12, // "//example.co"
				13, // "//example.com"
				14, // "//example.com/"
				15, // "//example.com/i"
				16, // "//example.com/in"
				17, // "//example.com/ind"
				18, // "//example.com/inde"
				19, // "//example.com/index"
				20, // "//example.com/index."
				21, // "//example.com/index.h"
				22, // "//example.com/index.ht"
				23, // "//example.com/index.htm"
				24, // "//example.com/index.html"
				25, // "//example.com/index.html?"
				26, // "//example.com/index.html?k"
				27, // "//example.com/index.html?ke"
				28, // "//example.com/index.html?key"
				29, // "//example.com/index.html?key="
				30, // "//example.com/index.html?key=v"
				31, // "//example.com/index.html?key=va"
				32, // "//example.com/index.html?key=val"
				33, // "//example.com/index.html?key=valu"
				34, // "//example.com/index.html?key=value"
			},
		},
		{
			testName: "data: []byte(\"//example.com/index.html#key=value\")",
			data:     []byte("//example.com/index.html#key=value"),
			findFunc: FindRelativeRef,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e"
				4,  // "//ex"
				5,  // "//exa"
				6,  // "//exam"
				7,  // "//examp"
				8,  // "//exampl"
				9,  // "//example"
				10, // "//example."
				11, // "//example.c"
				12, // "//example.co"
				13, // "//example.com"
				14, // "//example.com/"
				15, // "//example.com/i"
				16, // "//example.com/in"
				17, // "//example.com/ind"
				18, // "//example.com/inde"
				19, // "//example.com/index"
				20, // "//example.com/index."
				21, // "//example.com/index.h"
				22, // "//example.com/index.ht"
				23, // "//example.com/index.htm"
				24, // "//example.com/index.html"
				25, // "//example.com/index.html#"
				26, // "//example.com/index.html#k"
				27, // "//example.com/index.html#ke"
				28, // "//example.com/index.html#key"
				29, // "//example.com/index.html#key="
				30, // "//example.com/index.html#key=v"
				31, // "//example.com/index.html#key=va"
				32, // "//example.com/index.html#key=val"
				33, // "//example.com/index.html#key=valu"
				34, // "//example.com/index.html#key=value"
			},
		},
		{
			testName: "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:     []byte("//example.com/index.html?key1=value1#key2=value2"),
			findFunc: FindRelativeRef,
			expectedEnds: []int{
				0,  // "" ==> path-empty
				1,  // "/" ==> path-absolute
				2,  // "//" ==> "//" authority path-abempty
				3,  // "//e"
				4,  // "//ex"
				5,  // "//exa"
				6,  // "//exam"
				7,  // "//examp"
				8,  // "//exampl"
				9,  // "//example"
				10, // "//example."
				11, // "//example.c"
				12, // "//example.co"
				13, // "//example.com"
				14, // "//example.com/"
				15, // "//example.com/i"
				16, // "//example.com/in"
				17, // "//example.com/ind"
				18, // "//example.com/inde"
				19, // "//example.com/index"
				20, // "//example.com/index."
				21, // "//example.com/index.h"
				22, // "//example.com/index.ht"
				23, // "//example.com/index.htm"
				24, // "//example.com/index.html"
				25, // "//example.com/index.html?"
				26, // "//example.com/index.html?k"
				27, // "//example.com/index.html?ke"
				28, // "//example.com/index.html?key"
				29, // "//example.com/index.html?key1"
				30, // "//example.com/index.html?key1="
				31, // "//example.com/index.html?key1=v"
				32, // "//example.com/index.html?key1=va"
				33, // "//example.com/index.html?key1=val"
				34, // "//example.com/index.html?key1=valu"
				35, // "//example.com/index.html?key1=value"
				36, // "//example.com/index.html?key1=value1"
				37, // "//example.com/index.html?key1=value1#"
				38, // "//example.com/index.html?key1=value1#k"
				39, // "//example.com/index.html?key1=value1#ke"
				40, // "//example.com/index.html?key1=value1#key"
				41, // "//example.com/index.html?key1=value1#key2"
				42, // "//example.com/index.html?key1=value1#key2="
				43, // "//example.com/index.html?key1=value1#key2=v"
				44, // "//example.com/index.html?key1=value1#key2=va"
				45, // "//example.com/index.html?key1=value1#key2=val"
				46, // "//example.com/index.html?key1=value1#key2=valu"
				47, // "//example.com/index.html?key1=value1#key2=value"
				48, // "//example.com/index.html?key1=value1#key2=value2"
			},
		},
	}
	execTest(tests, t)
}

func TestFindRelativePart(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindRelativePart,
			expectedEnds: []int{0},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindRelativePart,
			expectedEnds: []int{0, 1},
		},
		{
			testName: "data: []byte(\"//example.com\")",
			data:     []byte("//example.com"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
			},
		},
		{
			testName: "data: []byte(\"//example.com/\")",
			data:     []byte("//example.com/"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
				14,
			},
		},
		{
			testName: "data: []byte(\"//example.com/index.html\")",
			data:     []byte("//example.com/index.html"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
				14,
				15,
				16,
				17,
				18,
				19,
				20,
				21,
				22,
				23,
				24,
			},
		},
		{
			testName: "data: []byte(\"/\")",
			data:     []byte("/"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
			},
		},
		{
			testName: "data: []byte(\"/index.html\")",
			data:     []byte("/index.html"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
			},
		},
		{
			testName: "data: []byte(\"index.html\")",
			data:     []byte("index.html"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
			},
		},
		{
			testName: "data: []byte(\"path/index.html\")",
			data:     []byte("path/index.html"),
			findFunc: FindRelativePart,
			expectedEnds: []int{
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
				14,
				15,
			},
		},
	}
	execTest(tests, t)
}

func TestFindAbsoluteUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:     "data: []byte{}",
			data:         []byte{},
			findFunc:     FindAbsoluteUri,
			expectedEnds: []int{},
		},
		{
			testName:     "data: []byte(\"a\")",
			data:         []byte("a"),
			findFunc:     FindAbsoluteUri,
			expectedEnds: []int{},
		},
		{
			testName: "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:     []byte("http://example.com/path1/path2?key=value"),
			findFunc: FindAbsoluteUri,
			expectedEnds: []int{
				5,  // "http:" ==> scheme ":" path-empty
				6,  // "http:/" ==> scheme ":" path-absolute
				7,  // "http://" ==> scheme ":" "//" authority path-abempty
				8,  // "http://e"
				9,  // "http://ex"
				10, // "http://exa"
				11, // "http://exam"
				12, // "http://examp"
				13, // "http://exampl"
				14, // "http://example"
				15, // "http://example."
				16, // "http://example.c"
				17, // "http://example.co"
				18, // "http://example.com"
				19, // "http://example.com/"
				20, // "http://example.com/p"
				21, // "http://example.com/pa"
				22, // "http://example.com/pat"
				23, // "http://example.com/path"
				24, // "http://example.com/path1"
				25, // "http://example.com/path1/"
				26, // "http://example.com/path1/p"
				27, // "http://example.com/path1/pa"
				28, // "http://example.com/path1/pat"
				29, // "http://example.com/path1/path"
				30, // "http://example.com/path1/path2"
				31, // "http://example.com/path1/path2?"
				32, // "http://example.com/path1/path2?k"
				33, // "http://example.com/path1/path2?ke"
				34, // "http://example.com/path1/path2?key"
				35, // "http://example.com/path1/path2?key="
				36, // "http://example.com/path1/path2?key=v"
				37, // "http://example.com/path1/path2?key=va"
				38, // "http://example.com/path1/path2?key=val"
				39, // "http://example.com/path1/path2?key=valu"
				40, // "http://example.com/path1/path2?key=value"
			},
		},
	}
	execTest(tests, t)
}
