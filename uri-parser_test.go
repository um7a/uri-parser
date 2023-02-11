package urip

import (
	"testing"

	abnfp "github.com/um7a/abnf-parser"
)

type TestCase struct {
	testName      string
	data          []byte
	finder        abnfp.Finder
	expectedFound bool
	expectedEnd   int
}

func equals[C comparable](testName string, t *testing.T, expected C, actual C) {
	if actual != expected {
		t.Errorf("%v: expected: %v, actual: %v", testName, expected, actual)
	}
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
			found, end := testCase.finder.Find(testCase.data)
			equals(testCase.testName, t, testCase.expectedFound, found)
			equals(testCase.testName, t, testCase.expectedEnd, end)
		})
	}
}

func TestPctEncodedFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPctEncodedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"abc\")",
			data:          []byte("abc"),
			finder:        NewPctEncodedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewPctEncodedFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
	}
	execTest(tests, t)
}

func TestReservedFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewReservedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			finder:        NewReservedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		// gen-delims
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			finder:        NewReservedFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		// sub-delims
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			finder:        NewReservedFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestGenDelimsFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewGenDelimsFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			finder:        NewGenDelimsFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'/'}",
			data:          []byte{'/'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'?'}",
			data:          []byte{'?'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'#'}",
			data:          []byte{'#'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'['}",
			data:          []byte{'['},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{']'}",
			data:          []byte{']'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			finder:        NewGenDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestSubDelimsFinder(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewSubDelimsFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			finder:        NewSubDelimsFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'$'}",
			data:          []byte{'$'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'&'}",
			data:          []byte{'&'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'''}",
			data:          []byte{'\''},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'('}",
			data:          []byte{'('},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{')'}",
			data:          []byte{')'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'*'}",
			data:          []byte{'*'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'+'}",
			data:          []byte{'+'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{','}",
			data:          []byte{','},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{';'}",
			data:          []byte{';'},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'='}",
			data:          []byte{'='},
			finder:        NewSubDelimsFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindUnreserved(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewUnreservedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'#'}",
			data:          []byte{'#'},
			finder:        NewUnreservedFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewUnreservedFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'1'}",
			data:          []byte{'1'},
			finder:        NewUnreservedFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'-'}",
			data:          []byte{'-'},
			finder:        NewUnreservedFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewUriFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewUriFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		// hier-part test - authority test: host validation
		{
			testName:      "data: []byte(\"http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   48,
		},
		{
			testName:      "data: []byte(\"http://255.255.255.255\")",
			data:          []byte("http://255.255.255.255"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   22,
		},
		{
			testName:      "data: []byte(\"http://example.com\")",
			data:          []byte("http://example.com"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   18,
		},
		// hier-part test - authority test: with userinfo
		{
			testName:      "data: []byte(\"http://user:pass@example.com\")",
			data:          []byte("http://user:pass@example.com"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   28,
		},
		// hier-part test - authority test: with port
		{
			testName:      "data: []byte(\"http://example.com:80\")",
			data:          []byte("http://example.com:80"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   21,
		},
		// hier-part test - path-abempty test
		{
			testName:      "data: []byte(\"http://example.com\")",
			data:          []byte("http://example.com"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   18,
		},
		{
			testName:      "data: []byte(\"http://example.com/\")",
			data:          []byte("http://example.com/"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   19,
		},
		{
			testName:      "data: []byte(\"http://example.com/path\")",
			data:          []byte("http://example.com/path"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   23,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2\")",
			data:          []byte("http://example.com/path1/path2"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		// hier-part test - path-absolute test
		{
			testName:      "data: []byte(\"http:/\")",
			data:          []byte("http:/"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   6,
		},
		{
			testName:      "data: []byte(\"http:/path\")",
			data:          []byte("http:/path"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"http:/path1/path2\")",
			data:          []byte("http:/path1/path2"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   17,
		},
		// hier-part test - path-rootless test
		{
			testName:      "data: []byte(\"http:path\")",
			data:          []byte("http:path"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"http:path1/path2\")",
			data:          []byte("http:path1/path2"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   16,
		},
		// hier-part test - path-empty test
		{
			testName:      "data: []byte(\"http:\")",
			data:          []byte("http:"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
		// [ "?" query ] test
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?\")",
			data:          []byte("http://example.com/path1/path2?"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   40,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key1=value1&key2=value2\")",
			data:          []byte("http://example.com/path1/path2?key1=value1&key2=value2"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   54,
		},
		// [ "#" fragment ] test
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#\")",
			data:          []byte("http://example.com/path1/path2#"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#key=value\")",
			data:          []byte("http://example.com/path1/path2#key=value"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   40,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#key1=value1&key2=value2\")",
			data:          []byte("http://example.com/path1/path2#key1=value1&key2=value2"),
			finder:        NewUriFinder(),
			expectedFound: true,
			expectedEnd:   54,
		},
	}
	execTest(tests, t)
}

func TestFindHierPart(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com\")",
			data:          []byte("//example.com"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   13,
		},
		{
			testName:      "data: []byte(\"//example.com/\")",
			data:          []byte("//example.com/"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   14,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"/\")",
			data:          []byte("/"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"index.html\")",
			data:          []byte("index.html"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"path/index.html\")",
			data:          []byte("path/index.html"),
			finder:        NewHierPartFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestFindScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewSchemeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewSchemeFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"http\")",
			data:          []byte("http"),
			finder:        NewSchemeFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"http:\")",
			data:          []byte("http:"),
			finder:        NewSchemeFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
	}
	execTest(tests, t)
}

func TestFindAuthority(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAuthorityFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewAuthorityFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"example.com\")",
			data:          []byte("example.com"),
			finder:        NewAuthorityFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"user:pass@example.com\")",
			data:          []byte("user:pass@example.com"),
			finder:        NewAuthorityFinder(),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"user:pass@example.com:443\")",
			data:          []byte("user:pass@example.com:443"),
			finder:        NewAuthorityFinder(),
			expectedFound: true,
			expectedEnd:   25,
		},
	}
	execTest(tests, t)
}

func TestFindHost(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewHostFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			finder:        NewHostFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"255.255.255.255\")",
			data:          []byte("255.255.255.255"),
			finder:        NewHostFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"www.example.com\")",
			data:          []byte("www.example.com"),
			finder:        NewHostFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestFindUserInfo(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewUserInfoFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"user\")",
			data:          []byte("user"),
			finder:        NewUserInfoFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"user:pass\")",
			data:          []byte("user:pass"),
			finder:        NewUserInfoFinder(),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"user:pass@\")",
			data:          []byte("user:pass@"),
			finder:        NewUserInfoFinder(),
			expectedFound: true,
			expectedEnd:   9,
		},
	}
	execTest(tests, t)
}

func TestFindIpLiteral(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewIpLiteralFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewIpLiteralFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			finder:        NewIpLiteralFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"[v1.a]\")",
			data:          []byte("[v1.a]"),
			finder:        NewIpLiteralFinder(),
			expectedFound: true,
			expectedEnd:   6,
		},
	}
	execTest(tests, t)
}

func TestFindIpVFuture(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewIpVFutureFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewIpVFutureFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"v1.a\")",
			data:          []byte("v1.a"),
			finder:        NewIpVFutureFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"v1F.a,:\")",
			data:          []byte("v1F.a,:"),
			finder:        NewIpVFutureFinder(),
			expectedFound: true,
			expectedEnd:   7,
		},
	}
	execTest(tests, t)
}

func TestFindIpV6Address(t *testing.T) {
	tests := []TestCase{
		// 6( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   39,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   45,
		},
		// "::" 5( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   42,
		},
		// [               h16 ] "::" 4( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   37,
		},
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   32,
		},
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   16,
		},
		{
			testName:      "data: []byte(\"::FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   22,
		},
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"FFFF::255.255.255.255\")",
			data:          []byte("FFFF::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"::255.255.255.255\")",
			data:          []byte("::255.255.255.255"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   17,
		},
		// [ *5( h16 ":" ) h16 ] "::"              h16
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF\")",
			data:          []byte("FFFF::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"::FFFF\")",
			data:          []byte("::FFFF"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   6,
		},
		// [ *6( h16 ":" ) h16 ] "::"
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   16,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"FFFF::\")",
			data:          []byte("FFFF::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   6,
		},
		{
			testName:      "data: []byte(\"::\")",
			data:          []byte("::"),
			finder:        NewIpV6AddressFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
	}
	execTest(tests, t)
}

func TestFindLs32(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewLs32Finder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewLs32Finder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"12AB:34CD\")",
			data:          []byte("12AB:34CD"),
			finder:        NewLs32Finder(),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(1.2.3.4)",
			data:          []byte("1.2.3.4"),
			finder:        NewLs32Finder(),
			expectedFound: true,
			expectedEnd:   7,
		},
	}
	execTest(tests, t)
}

func TestFindH16(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewH16Finder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewH16Finder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"1\")",
			data:          []byte("1"),
			finder:        NewH16Finder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"12AB\")",
			data:          []byte("12AB"),
			finder:        NewH16Finder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"12ABC\")",
			data:          []byte("12ABC"),
			finder:        NewH16Finder(),
			expectedFound: true,
			expectedEnd:   4,
		},
	}
	execTest(tests, t)
}

func TestFindIpV4Address(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewIpV4AddressFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewIpV4AddressFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"1.2.3.4\")",
			data:          []byte("1.2.3.4"),
			finder:        NewIpV4AddressFinder(),
			expectedFound: true,
			expectedEnd:   7,
		},
		{
			testName:      "data: []byte(\"101.102.103.104\")",
			data:          []byte("101.102.103.104"),
			finder:        NewIpV4AddressFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestFindDecOctet(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewDecOctetFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewDecOctetFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"0\")",
			data:          []byte("0"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"9\")",
			data:          []byte("9"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"10\")",
			data:          []byte("10"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"99\")",
			data:          []byte("99"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"100\")",
			data:          []byte("100"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"199\")",
			data:          []byte("199"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"200\")",
			data:          []byte("200"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"249\")",
			data:          []byte("249"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"250\")",
			data:          []byte("250"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"255\")",
			data:          []byte("255"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"256\")",
			data:          []byte("256"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"1.2\")",
			data:          []byte("1.2"),
			finder:        NewDecOctetFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindRegName(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRegNameFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewRegNameFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewRegNameFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			finder:        NewRegNameFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindPort(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPortFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"1\")",
			data:          []byte("1"),
			finder:        NewPortFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"80\")",
			data:          []byte("80"),
			finder:        NewPortFinder(),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"443\")",
			data:          []byte("443"),
			finder:        NewPortFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
	}
	execTest(tests, t)
}

func TestFindPath(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			finder:        NewPathFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
	}
	execTest(tests, t)
}

func TestFindPathAbempty(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathAbemptyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathAbemptyFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			finder:        NewPathAbemptyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewPathAbemptyFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			finder:        NewPathAbemptyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
	}
	execTest(tests, t)
}

func TestFindPathAbsolute(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathAbsoluteFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathAbsoluteFinder(),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			finder:        NewPathAbsoluteFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewPathAbsoluteFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			finder:        NewPathAbsoluteFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			finder:        NewPathAbsoluteFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
	}
	execTest(tests, t)
}

func TestFindPathNoScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathNoSchemeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathNoSchemeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			finder:        NewPathNoSchemeFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewPathNoSchemeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			finder:        NewPathNoSchemeFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			finder:        NewPathNoSchemeFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
	}
	execTest(tests, t)
}

func TestFindPathRootless(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathRootlessFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathRootlessFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			finder:        NewPathRootlessFinder(),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			finder:        NewPathRootlessFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			finder:        NewPathRootlessFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			finder:        NewPathRootlessFinder(),
			expectedFound: true,
			expectedEnd:   12,
		},
	}
	execTest(tests, t)
}

func TestFindPathEmpty(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPathEmptyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			finder:        NewPathEmptyFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
	}
	execTest(tests, t)
}

func TestFindSegment(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			finder:        NewSegmentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindSegmentNz(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewSegmentNzFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewSegmentNzFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewSegmentNzFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			finder:        NewSegmentNzFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			finder:        NewSegmentNzFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			finder:        NewSegmentNzFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindSegmentNzNc(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewSegmentNzNcFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewSegmentNzNcFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewSegmentNzNcFinder(),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			finder:        NewSegmentNzNcFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\":\")",
			data:          []byte(":"),
			finder:        NewSegmentNzNcFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"@\")",
			data:          []byte("@"),
			finder:        NewSegmentNzNcFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
	}
	execTest(tests, t)
}

func TestFindPchar(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewPcharFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewPcharFinder(),
			expectedFound: true,
			expectedEnd:   1, // "a" ==> unreserved
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			finder:        NewPcharFinder(),
			expectedFound: true,
			expectedEnd:   3, // "%1A" ==> pct-encoded
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			finder:        NewPcharFinder(),
			expectedFound: true,
			expectedEnd:   1, // "!" ==> sub-delims
		},
		{
			testName:      "data: []byte(\":\")",
			data:          []byte(":"),
			finder:        NewPcharFinder(),
			expectedFound: true,
			expectedEnd:   1, // ":" ==> ":"
		},
		{
			testName:      "data: []byte(\"@\")",
			data:          []byte("@"),
			finder:        NewPcharFinder(),
			expectedFound: true,
			expectedEnd:   1, // "@" ==> "@"
		},
	}
	execTest(tests, t)
}

func TestFindQuery(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewQueryFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewQueryFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"key=value\")",
			data:          []byte("key=value"),
			finder:        NewQueryFinder(),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"key1=value1&key2=value2\")",
			data:          []byte("ke1y=value1&key2=value2"),
			finder:        NewQueryFinder(),
			expectedFound: true,
			expectedEnd:   23,
		},
	}
	execTest(tests, t)
}

func TestFindFragment(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewFragmentFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			finder:        NewFragmentFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"key=value\")",
			data:          []byte("key=value"),
			finder:        NewFragmentFinder(),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"key1=value1&key2=value2\")",
			data:          []byte("ke1y=value1&key2=value2"),
			finder:        NewFragmentFinder(),
			expectedFound: true,
			expectedEnd:   23,
		},
	}
	execTest(tests, t)
}

func TestFindUriReference(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewUriReferenceFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewUriReferenceFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		// URI
		{
			testName:      "data: []byte(\"http://example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("http://example.com/index.html?key1=value1#key2=value2"),
			finder:        NewUriReferenceFinder(),
			expectedFound: true,
			expectedEnd:   53,
		},
		// relative-ref
		{
			testName:      "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("//example.com/index.html?key1=value1#key2=value2"),
			finder:        NewUriReferenceFinder(),
			expectedFound: true,
			expectedEnd:   48,
		},
	}
	execTest(tests, t)
}

func TestFindRelativeRef(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html?key=value\")",
			data:          []byte("//example.com/index.html?key=value"),
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   34,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html#key=value\")",
			data:          []byte("//example.com/index.html#key=value"),
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   34,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("//example.com/index.html?key1=value1#key2=value2"),
			finder:        NewRelativeRefFinder(),
			expectedFound: true,
			expectedEnd:   48,
		},
	}
	execTest(tests, t)
}

func TestFindRelativePart(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com\")",
			data:          []byte("//example.com"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   13,
		},
		{
			testName:      "data: []byte(\"//example.com/\")",
			data:          []byte("//example.com/"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   14,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"/\")",
			data:          []byte("/"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"index.html\")",
			data:          []byte("index.html"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"path/index.html\")",
			data:          []byte("path/index.html"),
			finder:        NewRelativePartFinder(),
			expectedFound: true,
			expectedEnd:   15,
		},
	}
	execTest(tests, t)
}

func TestFindAbsoluteUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			finder:        NewAbsoluteUriFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			finder:        NewAbsoluteUriFinder(),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			finder:        NewAbsoluteUriFinder(),
			expectedFound: true,
			expectedEnd:   40,
		},
	}
	execTest(tests, t)
}
