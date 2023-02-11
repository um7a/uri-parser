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

	// RFC3986 - 3.1. Scheme
	//
	//  scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
	//
	parsed, remaining := abnfp.Parse(data, NewSchemeFinder())
	if len(parsed) == 0 {
		return nil, errors.New("scheme not found.")
	}
	uri.Scheme = parsed

	// ":"
	found, end := abnfp.NewByteFinder(':').Find(remaining)
	if !found {
		return nil, errors.New("colon following scheme not found.")
	}
	remaining = remaining[end:]

	// RFC3986 - 3. Syntax Components
	//
	//	hier-part = "//" authority path-abempty
	//	          / path-absolute
	//	          / path-rootless
	//	          / path-empty
	//

	var hierPartRemaining []byte
	parsed, remaining = abnfp.Parse(remaining, NewHierPartFinder())
	if len(parsed) >= 2 && parsed[0] == '/' && parsed[1] == '/' {
		// hier-part = "//" authority path-abempty

		// "//"
		uri.DoubleSlash = parsed[:2]
		hierPartRemaining = parsed[2:]

		// RFC3986 - 3.2. Authority
		//
		//  authority = [ userinfo "@" ] host [ ":" port ]
		//

		// [ userinfo "@" ]
		parsed, hierPartRemaining = abnfp.Parse(
			hierPartRemaining,
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					NewUserInfoFinder(),
					abnfp.NewByteFinder('@'),
				}),
			))
		if len(parsed) > 0 {
			uri.UserInfo = parsed[:len(parsed)-1]
			uri.AtSign = []byte("@")
		}

		// RFC3986 - 3.2.2. Host
		//
		//  host = IP-literal / IPv4address / reg-name
		//
		parsed, hierPartRemaining = abnfp.Parse(hierPartRemaining, NewHostFinder())
		if len(parsed) > 0 {
			uri.Host = parsed
		}

		// [ ":" port ]
		parsed, hierPartRemaining = abnfp.Parse(
			hierPartRemaining,
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewByteFinder(':'),
					NewPortFinder(),
				}),
			))
		if len(parsed) > 0 {
			uri.Port = parsed[1:]
		}

		// RFC3986 - 3.3. Path
		//
		//  path-abempty  = *( "/" segment )
		//
		parsed, hierPartRemaining = abnfp.Parse(hierPartRemaining, NewPathAbemptyFinder())
		if len(parsed) > 0 {
			uri.Path = parsed
		}
	} else if len(parsed) >= 1 && parsed[0] == '/' {
		// hier-part = path-absolute

		// RFC3986 - 3.3. Path
		//
		//  path-absolute = "/" [ segment-nz *( "/" segment ) ]
		//
		parsed, hierPartRemaining = abnfp.Parse(parsed, NewPathAbsoluteFinder())
		if len(parsed) == 0 {
			return nil, errors.New("path-absolute not found.")
		}
		uri.Path = parsed
	} else if len(parsed) > 0 {
		// hier-part = path-rootless

		// RFC3986 - 3.3. Path
		//
		//  path-rootless = segment-nz *( "/" segment )
		//
		parsed, hierPartRemaining = abnfp.Parse(parsed, NewPathRootlessFinder())
		if len(parsed) == 0 {
			return nil, errors.New("path-rootless not found.")
		}
		uri.Path = parsed
	} else {
		// hier-part = path-empty

		// do nothing.
	}

	// [ "?" query ]
	parsed, remaining = abnfp.Parse(remaining, abnfp.NewOptionalSequenceFinder(
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('?'),
			NewQueryFinder(),
		}),
	))
	if len(parsed) > 0 {
		uri.Question = []byte("?")
		uri.Query = parsed[1:]
	}

	// [ "#" fragment ]
	parsed, remaining = abnfp.Parse(remaining, abnfp.NewOptionalSequenceFinder(
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('#'),
			NewFragmentFinder(),
		}),
	))
	if len(parsed) > 0 {
		uri.Sharp = []byte("#")
		uri.Fragment = parsed[1:]
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
	var str string
	str += string(uri.UserInfo)
	str += string(uri.AtSign)
	str += string(uri.Host)
	if len(uri.Port) > 0 {
		str += ":"
		str += string(uri.Port)
	}
	return str
}
