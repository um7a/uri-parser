package urip

import (
	"testing"

	abnfp "github.com/um7a/abnf-parser"
)

type TestCase struct {
	testName      string
	data          []byte
	expectedFound bool
	expectedEnd   int
}

func execTest(tests []TestCase, t *testing.T, findFunc abnfp.FindFunc) {
	for _, testCase := range tests {
		t.Run(testCase.testName, func(t *testing.T) {
			actualFound, actualEnd := findFunc(testCase.data)
			equals(testCase.testName, t, testCase.expectedFound, actualFound)
			equals(testCase.testName, t, testCase.expectedEnd, actualEnd)
		})
	}
}

func equals[C comparable](testName string, t *testing.T, expected C, actual C) {
	if actual != expected {
		t.Errorf("%v: expected: %v, actual: %v", testName, expected, actual)
	}
}

func FindPctEncodedTest(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"abc\")",
			data:          []byte("abc"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
	}

	execTest(tests, t, FindPctEncoded)
}

func TestFindGenDelims(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'/'}",
			data:          []byte{'/'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'?'}",
			data:          []byte{'?'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'#'}",
			data:          []byte{'#'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'['}",
			data:          []byte{'['},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{']'}",
			data:          []byte{']'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindGenDelims)
}

func TestFindReserved(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		// gen-delims
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
		// sub-delims
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindReserved)
}

func TestFindSubDelims(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'$'}",
			data:          []byte{'$'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'&'}",
			data:          []byte{'&'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'''}",
			data:          []byte{'\''},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'('}",
			data:          []byte{'('},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{')'}",
			data:          []byte{')'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'*'}",
			data:          []byte{'*'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'+'}",
			data:          []byte{'+'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{','}",
			data:          []byte{','},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{';'}",
			data:          []byte{';'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'='}",
			data:          []byte{'='},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindSubDelims)
}

func TestFindUnreserved(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'#'}",
			data:          []byte{'#'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'1'}",
			data:          []byte{'1'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'-'}",
			data:          []byte{'-'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindUnreserved)
}

func TestFindUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		// hier-part test - authority test: host validation
		{
			testName:      "data: []byte(\"http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("http://[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			expectedFound: true,
			expectedEnd:   48,
		},
		{
			testName:      "data: []byte(\"http://[v1F.a,:]\")",
			data:          []byte("http://[v1F.a,:]"),
			expectedFound: true,
			expectedEnd:   16,
		},
		{
			testName:      "data: []byte(\"http://255.255.255.255\")",
			data:          []byte("http://255.255.255.255"),
			expectedFound: true,
			expectedEnd:   22,
		},
		{
			testName:      "data: []byte(\"http://example.com\")",
			data:          []byte("http://example.com"),
			expectedFound: true,
			expectedEnd:   18,
		},
		// hier-part test - authority test: with userinfo
		{
			testName:      "data: []byte(\"http://user:pass@example.com\")",
			data:          []byte("http://user:pass@example.com"),
			expectedFound: true,
			expectedEnd:   28,
		},
		// hier-part test - authority test: with port
		{
			testName:      "data: []byte(\"http://example.com:80\")",
			data:          []byte("http://example.com:80"),
			expectedFound: true,
			expectedEnd:   21,
		},
		// hier-part test - path-abempty test
		{
			testName:      "data: []byte(\"http://example.com\")",
			data:          []byte("http://example.com"),
			expectedFound: true,
			expectedEnd:   18,
		},
		{
			testName:      "data: []byte(\"http://example.com/\")",
			data:          []byte("http://example.com/"),
			expectedFound: true,
			expectedEnd:   19,
		},
		{
			testName:      "data: []byte(\"http://example.com/path\")",
			data:          []byte("http://example.com/path"),
			expectedFound: true,
			expectedEnd:   23,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2\")",
			data:          []byte("http://example.com/path1/path2"),
			expectedFound: true,
			expectedEnd:   30,
		},
		// hier-part test - path-absolute test
		{
			testName:      "data: []byte(\"http:/\")",
			data:          []byte("http:/"),
			expectedFound: true,
			expectedEnd:   6,
		},
		{
			testName:      "data: []byte(\"http:/path\")",
			data:          []byte("http:/path"),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"http:/path1/path2\")",
			data:          []byte("http:/path1/path2"),
			expectedFound: true,
			expectedEnd:   17,
		},
		// hier-part test - path-rootless test
		{
			testName:      "data: []byte(\"http:path\")",
			data:          []byte("http:path"),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"http:path1/path2\")",
			data:          []byte("http:path1/path2"),
			expectedFound: true,
			expectedEnd:   16,
		},
		// hier-part test - path-empty test
		{
			testName:      "data: []byte(\"http:\")",
			data:          []byte("http:"),
			expectedFound: true,
			expectedEnd:   5,
		},
		// [ "?" query ] test
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?\")",
			data:          []byte("http://example.com/path1/path2?"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			expectedFound: true,
			expectedEnd:   40,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key1=value1&key2=value2\")",
			data:          []byte("http://example.com/path1/path2?key1=value1&key2=value2"),
			expectedFound: true,
			expectedEnd:   54,
		},
		// [ "#" fragment ] test
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#\")",
			data:          []byte("http://example.com/path1/path2#"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#key=value\")",
			data:          []byte("http://example.com/path1/path2#key=value"),
			expectedFound: true,
			expectedEnd:   40,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2#key1=value1&key2=value2\")",
			data:          []byte("http://example.com/path1/path2#key1=value1&key2=value2"),
			expectedFound: true,
			expectedEnd:   54,
		},
	}

	execTest(tests, t, FindUri)
}

func TestFindHierPart(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com\")",
			data:          []byte("//example.com"),
			expectedFound: true,
			expectedEnd:   13,
		},
		{
			testName:      "data: []byte(\"//example.com/\")",
			data:          []byte("//example.com/"),
			expectedFound: true,
			expectedEnd:   14,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"/\")",
			data:          []byte("/"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"index.html\")",
			data:          []byte("index.html"),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"path/index.html\")",
			data:          []byte("path/index.html"),
			expectedFound: true,
			expectedEnd:   15,
		},
	}

	execTest(tests, t, FindHierPart)
}

func TestFindScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'h', 't', 't', 'p'}",
			data:          []byte{'h', 't', 't', 'p'},
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte{'h', 't', 't', 'p', ':'}",
			data:          []byte{'h', 't', 't', 'p', ':'},
			expectedFound: true,
			expectedEnd:   4,
		},
	}

	execTest(tests, t, FindScheme)
}

func TestFindAuthority(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"example.com\")",
			data:          []byte("example.com"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"user:pass@example.com\")",
			data:          []byte("user:pass@example.com"),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"user:pass@example.com:443\")",
			data:          []byte("user:pass@example.com:443"),
			expectedFound: true,
			expectedEnd:   25,
		},
	}

	execTest(tests, t, FindAuthority)
}

func TestFindHost(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"255.255.255.255\")",
			data:          []byte("255.255.255.255"),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"www.example.com\")",
			data:          []byte("www.example.com"),
			expectedFound: true,
			expectedEnd:   15,
		},
	}

	execTest(tests, t, FindHost)
}

func TestFindUserInfo(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"user\")",
			data:          []byte("user"),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"user:pass\")",
			data:          []byte("user:pass"),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"user:pass@\")",
			data:          []byte("user:pass@"),
			expectedFound: true,
			expectedEnd:   9,
		},
	}

	execTest(tests, t, FindUserInfo)
}

func TestFindIpLiteral(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]\")",
			data:          []byte("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"[v1.a]\")",
			data:          []byte("[v1.a]"),
			expectedFound: true,
			expectedEnd:   6,
		},
	}

	execTest(tests, t, FindIpLiteral)
}

func TestFindIpVFuture(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"v1.a\")",
			data:          []byte("v1.a"),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"v1F.a,:\")",
			data:          []byte("v1F.a,:"),
			expectedFound: true,
			expectedEnd:   7,
		},
	}

	execTest(tests, t, FindIpVFuture)
}

func TestFindIpV6Address(t *testing.T) {
	tests := []TestCase{
		//                            6( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   39,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   45,
		},
		//                       "::" 5( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   42,
		},
		// [               h16 ] "::" 4( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   37,
		},
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   32,
		},
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   36,
		},
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF:FFFF::FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:255.255.255.255\")",
			data:          []byte("FFFF::FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   16,
		},
		{
			testName:      "data: []byte(\"::FFFF:255.255.255.255\")",
			data:          []byte("::FFFF:255.255.255.255"),
			expectedFound: true,
			expectedEnd:   22,
		},
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   41,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF:FFFF::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::255.255.255.255\")",
			data:          []byte("FFFF:FFFF::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF:FFFF\")",
			data:          []byte("FFFF::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"FFFF::255.255.255.255\")",
			data:          []byte("FFFF::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"::FFFF:FFFF\")",
			data:          []byte("::FFFF:FFFF"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"::255.255.255.255\")",
			data:          []byte("::255.255.255.255"),
			expectedFound: true,
			expectedEnd:   17,
		},
		// [ *5( h16 ":" ) h16 ] "::"              h16
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   35,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   30,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   25,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF:FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   20,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::FFFF\")",
			data:          []byte("FFFF:FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   15,
		},
		{
			testName:      "data: []byte(\"FFFF::FFFF\")",
			data:          []byte("FFFF::FFFF"),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"::FFFF\")",
			data:          []byte("::FFFF"),
			expectedFound: true,
			expectedEnd:   6,
		},
		// [ *6( h16 ":" ) h16 ] "::"
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   36,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   31,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   26,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   21,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   16,
		},
		{
			testName:      "data: []byte(\"FFFF:FFFF::\")",
			data:          []byte("FFFF:FFFF::"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"FFFF::\")",
			data:          []byte("FFFF::"),
			expectedFound: true,
			expectedEnd:   6,
		},
		{
			testName:      "data: []byte(\"::\")",
			data:          []byte("::"),
			expectedFound: true,
			expectedEnd:   2,
		},
	}

	execTest(tests, t, FindIpV6Address)
}

func TestFindLs32(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'1', '2', 'A', 'B', ':', '3', '4', 'C', 'D'}",
			data:          []byte{'1', '2', 'A', 'B', ':', '3', '4', 'C', 'D'},
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte{'1', '.', '2', '.', '3', '.', '4'}",
			data:          []byte{'1', '.', '2', '.', '3', '.', '4'},
			expectedFound: true,
			expectedEnd:   7,
		},
	}

	execTest(tests, t, FindLs32)
}

func TestFindH16(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'1'}",
			data:          []byte{'1'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'1', '2', 'A', 'B'}",
			data:          []byte{'1', '2', 'A', 'B'},
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte{'1', '2', 'A', 'B', 'C'}",
			data:          []byte{'1', '2', 'A', 'B', 'C'},
			expectedFound: true,
			expectedEnd:   4,
		},
	}

	execTest(tests, t, FindH16)
}

func TestFindIpV4Address(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'1', '.', '2', '.', '3', '.', '4'}",
			data:          []byte{'1', '.', '2', '.', '3', '.', '4'},
			expectedFound: true,
			expectedEnd:   7,
		},
		{
			testName:      "data: []byte{'1', '0', '1', '.', '1', '0', '2', '.', '1', '0', '3', '.', '1', '0', '4'}",
			data:          []byte{'1', '0', '1', '.', '1', '0', '2', '.', '1', '0', '3', '.', '1', '0', '4'},
			expectedFound: true,
			expectedEnd:   15,
		},
	}

	execTest(tests, t, FindIpV4Address)
}

func TestFindDecOctet(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'0'}",
			data:          []byte{'0'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'9'}",
			data:          []byte{'9'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'1', '0'}",
			data:          []byte{'1', '0'},
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte{'9', '9'}",
			data:          []byte{'9', '9'},
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte{'1', '0', '0'}",
			data:          []byte{'1', '0', '0'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'1', '9', '9'}",
			data:          []byte{'1', '9', '9'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'2', '0', '0'}",
			data:          []byte{'2', '0', '0'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'2', '4', '9'}",
			data:          []byte{'2', '4', '9'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'2', '5', '0'}",
			data:          []byte{'2', '5', '0'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'2', '5', '5'}",
			data:          []byte{'2', '5', '5'},
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'2', '5', '6'}",
			data:          []byte{'2', '5', '6'},
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte{'1', '.', '2'}",
			data:          []byte{'1', '.', '2'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindDecOctet)
}

func TestFindRegName(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindRegName)
}

func TestFindPort(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'1'}",
			data:          []byte{'1'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"80\")",
			data:          []byte("80"),
			expectedFound: true,
			expectedEnd:   2,
		},
		{
			testName:      "data: []byte(\"443\")",
			data:          []byte("443"),
			expectedFound: true,
			expectedEnd:   3,
		},
	}

	execTest(tests, t, FindPort)
}

func TestFindPath(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			expectedFound: true,
			expectedEnd:   12,
		},
	}

	execTest(tests, t, FindPath)
}

func TestFindPathAbempty(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			expectedFound: true,
			expectedEnd:   0,
		},
	}

	execTest(tests, t, FindPathAbempty)
}

func TestFindPathAbsolute(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: true,
			expectedEnd:   5,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			expectedFound: true,
			expectedEnd:   12,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			expectedFound: false,
			expectedEnd:   0,
		},
	}

	execTest(tests, t, FindPathAbsolute)
}

func TestFindPathNoScheme(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			expectedFound: false,
			expectedEnd:   0,
		},
	}

	execTest(tests, t, FindPathNoScheme)
}

func TestFindPathRootless(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path\")",
			data:          []byte("path"),
			expectedFound: true,
			expectedEnd:   4,
		},
		{
			testName:      "data: []byte(\"/path1/path2\")",
			data:          []byte("/path1/path2"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"path1/path2\")",
			data:          []byte("path1/path2"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\":path1/path2\")",
			data:          []byte(":path1/path2"),
			expectedFound: true,
			expectedEnd:   12,
		},
	}

	execTest(tests, t, FindPathRootless)
}

func TestFindPathEmpty(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"/path\")",
			data:          []byte("/path"),
			expectedFound: true,
			expectedEnd:   0,
		},
	}

	execTest(tests, t, FindPathEmpty)
}

func TestFindSegment(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindSegment)
}

func TestFindSegmentNz(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte{'!'}",
			data:          []byte{'!'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{':'}",
			data:          []byte{':'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte{'@'}",
			data:          []byte{'@'},
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindSegmentNz)
}

func TestFindSegmentNzNc(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\":\")",
			data:          []byte(":"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"@\")",
			data:          []byte("@"),
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindSegmentNzNc)
}

func TestFindPchar(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"%1A\")",
			data:          []byte("%1A"),
			expectedFound: true,
			expectedEnd:   3,
		},
		{
			testName:      "data: []byte(\"!\")",
			data:          []byte("!"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\":\")",
			data:          []byte(":"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"@\")",
			data:          []byte("@"),
			expectedFound: true,
			expectedEnd:   1,
		},
	}

	execTest(tests, t, FindPchar)
}

func TestFindQuery(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"key=value\")",
			data:          []byte("key=value"),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"key1=value1&key2=value2\")",
			data:          []byte("ke1y=value1&key2=value2"),
			expectedFound: true,
			expectedEnd:   23,
		},
	}

	execTest(tests, t, FindQuery)
}

func TestFindFragment(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte{'a'}",
			data:          []byte{'a'},
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"key=value\")",
			data:          []byte("key=value"),
			expectedFound: true,
			expectedEnd:   9,
		},
		{
			testName:      "data: []byte(\"key1=value1&key2=value2\")",
			data:          []byte("ke1y=value1&key2=value2"),
			expectedFound: true,
			expectedEnd:   23,
		},
	}

	execTest(tests, t, FindFragment)
}

func TestFindUriReference(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			expectedFound: true,
			expectedEnd:   1,
		},
		// URI
		{
			testName:      "data: []byte(\"http://example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("http://example.com/index.html?key1=value1#key2=value2"),
			expectedFound: true,
			expectedEnd:   53,
		},

		// relative-ref
		{
			testName:      "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("//example.com/index.html?key1=value1#key2=value2"),
			expectedFound: true,
			expectedEnd:   48,
		},
	}

	execTest(tests, t, FindUriReference)
}

func TestFindRelativeRef(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html?key=value\")",
			data:          []byte("//example.com/index.html?key=value"),
			expectedFound: true,
			expectedEnd:   34,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html#key=value\")",
			data:          []byte("//example.com/index.html#key=value"),
			expectedFound: true,
			expectedEnd:   34,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html?key1=value1#key2=value2\")",
			data:          []byte("//example.com/index.html?key1=value1#key2=value2"),
			expectedFound: true,
			expectedEnd:   48,
		},
	}

	execTest(tests, t, FindRelativeRef)
}

func TestFindRelativePart(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: true,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"//example.com\")",
			data:          []byte("//example.com"),
			expectedFound: true,
			expectedEnd:   13,
		},
		{
			testName:      "data: []byte(\"//example.com/\")",
			data:          []byte("//example.com/"),
			expectedFound: true,
			expectedEnd:   14,
		},
		{
			testName:      "data: []byte(\"//example.com/index.html\")",
			data:          []byte("//example.com/index.html"),
			expectedFound: true,
			expectedEnd:   24,
		},
		{
			testName:      "data: []byte(\"/\")",
			data:          []byte("/"),
			expectedFound: true,
			expectedEnd:   1,
		},
		{
			testName:      "data: []byte(\"/index.html\")",
			data:          []byte("/index.html"),
			expectedFound: true,
			expectedEnd:   11,
		},
		{
			testName:      "data: []byte(\"index.html\")",
			data:          []byte("index.html"),
			expectedFound: true,
			expectedEnd:   10,
		},
		{
			testName:      "data: []byte(\"path/index.html\")",
			data:          []byte("path/index.html"),
			expectedFound: true,
			expectedEnd:   15,
		},
	}

	execTest(tests, t, FindRelativePart)
}

func TestFindAbsoluteUri(t *testing.T) {
	tests := []TestCase{
		{
			testName:      "data: []byte{}",
			data:          []byte{},
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"a\")",
			data:          []byte("a"),
			expectedFound: false,
			expectedEnd:   0,
		},
		{
			testName:      "data: []byte(\"http://example.com/path1/path2?key=value\")",
			data:          []byte("http://example.com/path1/path2?key=value"),
			expectedFound: true,
			expectedEnd:   40,
		},
	}

	execTest(tests, t, FindAbsoluteUri)
}
