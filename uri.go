package urip

import (
	"errors"

	abnfp "github.com/um7a/abnf-parser"
)

type Uri struct {
	Scheme      []byte
	DoubleSlash []byte // part of hier-part
	UserInfo    []byte // part of hier-part
	AtSign      []byte // part of hier-part
	Host        []byte // part of hier-part
	Port        []byte // part of hier-part
	Path        []byte // part of hier-part
	Question    []byte
	Query       []byte
	Sharp       []byte
	Fragment    []byte
}

func Parse(data []byte) (uri *Uri, err error) {
	// RFC3986 - 3. Syntax Components
	//
	//	URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
	//
	// RFC3986 - 3.2. Authority
	//
	//	authority = [ userinfo "@" ] host [ ":" port ]
	//
	uri = new(Uri)
	remaining := data

	// RFC3986 - 3.1. Scheme
	//
	//  scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	//
	result := abnfp.ParseLongest(remaining, FindScheme)
	if len(result.Parsed) == 0 {
		return nil, errors.New("scheme not found.")
	}
	uri.Scheme = result.Parsed
	remaining = result.Remaining

	// ":"
	colonEnds := abnfp.NewFindByte(':')(remaining)
	if len(colonEnds) == 0 {
		return nil, errors.New("colon following scheme not found.")
	}
	remaining = remaining[colonEnds[0]:]

	// RFC3986 - 3. Syntax Components
	//
	//	hier-part = "//" authority path-abempty
	//	          / path-absolute
	//	          / path-rootless
	//	          / path-empty
	//
	result = abnfp.ParseLongest(remaining, FindHierPart)
	if len(result.Parsed) >= 2 && result.Parsed[0] == '/' && result.Parsed[1] == '/' {
		// hier-part = "//" authority path-abempty

		// "//"
		uri.DoubleSlash = []byte("//")
		remaining = remaining[2:]

		// RFC3986 - 3.2. Authority
		//
		//  authority = [ userinfo "@" ] host [ ":" port ]
		//

		// [ userinfo "@" ]
		result = abnfp.ParseLongest(remaining, abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				FindUserInfo,
				abnfp.NewFindByte('@'),
			}),
		))
		if len(result.Parsed) > 0 {
			// RFC3986 - 3.2.1. User Information
			//
			//  userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
			//
			uri.UserInfo = result.Parsed[:len(result.Parsed)-1]
			uri.AtSign = []byte("@")
			remaining = result.Remaining
		}

		// RFC3986 - 3.2.2. Host
		//
		//  host = IP-literal / IPv4address / reg-name
		//
		result = abnfp.ParseLongest(remaining, FindHost)
		if len(result.Parsed) > 0 {
			uri.Host = result.Parsed
			remaining = result.Remaining
		}

		// [ ":" port ]
		result = abnfp.ParseLongest(remaining, abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte(':'),
				FindPort,
			}),
		))
		if len(result.Parsed) > 0 {
			uri.Port = result.Parsed[1:]
			remaining = result.Remaining
		}

		// RFC3986 - 3.3. Path
		//
		//  path-abempty  = *( "/" segment )
		//
		result = abnfp.ParseLongest(remaining, FindPathAbempty)
		if len(result.Parsed) > 0 {
			uri.Path = result.Parsed
			remaining = result.Remaining
		}
	} else if len(result.Parsed) >= 1 && result.Parsed[0] == '/' {
		// hier-part = path-absolute

		// RFC3986 - 3.3. Path
		//
		//  path-absolute = "/" [ segment-nz *( "/" segment ) ]
		//
		result = abnfp.ParseLongest(remaining, FindPathAbsolute)
		if len(result.Parsed) == 0 {
			return nil, errors.New("path-absolute not found.")
		}
		uri.Path = result.Parsed
		remaining = result.Remaining
	} else if len(result.Parsed) > 0 {
		// hier-part = path-rootless

		// RFC3986 - 3.3. Path
		//
		//  path-rootless = segment-nz *( "/" segment )
		//
		result = abnfp.ParseLongest(remaining, FindPathRootless)
		if len(result.Parsed) == 0 {
			return nil, errors.New("path-rootless not found.")
		}
		uri.Path = result.Parsed
		remaining = result.Remaining
	} else {
		// hier-part = path-empty

		// do nothing.
	}

	// [ "?" query ]
	result = abnfp.ParseLongest(remaining, abnfp.NewFindOptionalSequence(
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('?'),
			FindQuery,
		}),
	))
	if len(result.Parsed) > 0 {
		uri.Question = []byte("?")
		uri.Query = result.Parsed[1:]
		remaining = result.Remaining
	}

	// [ "#" fragment ]
	result = abnfp.ParseLongest(remaining, abnfp.NewFindOptionalSequence(
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('#'),
			FindFragment,
		}),
	))
	if len(result.Parsed) > 0 {
		uri.Sharp = []byte("#")
		uri.Fragment = result.Parsed[1:]
		remaining = result.Remaining
	}
	return uri, nil
}

func (uri *Uri) String() string {
	// RFC3986 - 3. Syntax Components
	//
	//  URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
	//
	// RFC3986 - 3. Syntax Components
	//
	//  hier-part = "//" authority path-abempty
	//            / path-absolute
	//            / path-rootless
	//            / path-empty
	//
	str := string(uri.Scheme)
	str += ":"
	if len(uri.DoubleSlash) > 0 {
		str += string(uri.DoubleSlash)
		str += uri.GetAuthority()
	}
	str += string(uri.Path)
	str += string(uri.Question)
	str += string(uri.Query)
	str += string(uri.Sharp)
	str += string(uri.Fragment)
	return str
}

func (uri *Uri) GetAuthority() string {
	// RFC3986 - 3.2. Authority
	//
	//  authority = [ userinfo "@" ] host [ ":" port ]
	//
	str := ""
	str += string(uri.UserInfo)
	str += string(uri.AtSign)
	str += string(uri.Host)
	if len(uri.Port) > 0 {
		str += ":"
		str += string(uri.Port)
	}
	return str
}
