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
	// RFC3986 - 3. Syntax Components
	//
	//	hier-part = "//" authority path-abempty
	//	          / path-absolute
	//	          / path-rootless
	//	          / path-empty
	//
	// RFC3986 - 3.2. Authority
	//
	//	authority = [ userinfo "@" ] host [ ":" port ]
	//
	uri = new(Uri)
	found := false
	remaining := data

	// scheme
	found, uri.Scheme, remaining = abnfp.Parse(remaining, FindScheme)
	if !found {
		return nil, errors.New("scheme not found.")
	}

	// ":"
	findColon := abnfp.CreateFind([]byte{':'})
	found, _, remaining = abnfp.Parse(remaining, findColon)
	if !found {
		return nil, errors.New("colon following scheme not found.")
	}

	// hier-part
	found, _ = FindHierPart(remaining)
	if !found {
		return nil, errors.New("hier-part not found.")
	}

	// "//"
	found, _ = abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte("//")),
		FindAuthority,
		FindPathAbempty,
	})(remaining)
	if found {
		// It seems that hier-part = ( "//" authority path-abempty ).
		found, uri.DoubleSlash, remaining = abnfp.Parse(remaining, abnfp.CreateFind([]byte("//")))
		if !found {
			return nil, errors.New("hier-part has \"//\", but failed to parse \"//\".")
		}
		// [ userinfo "@" ]
		found, _ = abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			FindUserInfo,
			abnfp.CreateFind([]byte{'@'}),
		})(remaining)
		if found {
			found, uri.UserInfo, remaining = abnfp.Parse(remaining, FindUserInfo)
			if !found {
				return nil, errors.New("[ userinfo \"@\" ] found. But failed to parse userinfo.")
			}
			found, uri.AtSign, remaining = abnfp.Parse(remaining, abnfp.CreateFind([]byte{'@'}))
			if !found {
				return nil, errors.New("[ userinfo \"@\" ] found. But failed to parse \"@\".")
			}
		}
		// host
		found, uri.Host, remaining = abnfp.Parse(remaining, FindHost)
		if !found {
			return nil, errors.New("hier-part has \"//\", but host not found.")
		}
		// [ ":" port ]
		found, _ := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{':'}),
			FindPort,
		})(remaining)
		if found {
			found, _, remaining = abnfp.Parse(remaining, abnfp.CreateFind([]byte{':'}))
			if !found {
				return nil, errors.New("[ \":\" port ] found. But failed to parse \":\".")
			}
			found, uri.Port, remaining = abnfp.Parse(remaining, FindPort)
			if !found {
				return nil, errors.New("[ \":\" port ] found. But failed to parse port.")
			}
		}
		// path-abempty
		found, uri.Path, remaining = abnfp.Parse(remaining, FindPathAbempty)
		if !found {
			return nil, errors.New("hier-part has \"//\", but failed to parse path-abempty.")
		}
	} else {
		// it seems that
		//  hier-part = path-absolute
		//            / path-rootless
		//            / path-empty
		findPath := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindPathAbsolute,
			FindPathRootless,
			FindPathEmpty,
		})
		found, uri.Path, remaining = abnfp.Parse(remaining, findPath)
		if !found {
			return nil, errors.New("Failed to parse hier-part. Unknown syntax.")
		}
	}
	// [ "?" query ]
	found, _ = abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'?'}),
		FindQuery,
	})(remaining)
	if found {
		found, uri.Question, remaining = abnfp.Parse(remaining, abnfp.CreateFind([]byte{'?'}))
		if !found {
			return nil, errors.New("[ \"?\" query ] found. But failed to parse \"?\"")
		}
		found, uri.Query, remaining = abnfp.Parse(remaining, FindQuery)
		if !found {
			return nil, errors.New("[ \"?\" query ] found. But failed to parse query.")
		}
	}
	// [ "#" fragment ]
	found, _ = abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'#'}),
		FindFragment,
	})(remaining)
	if found {
		found, uri.Sharp, remaining = abnfp.Parse(remaining, abnfp.CreateFind([]byte{'#'}))
		if !found {
			return nil, errors.New("[ \"#\" fragment ] found. But failed to parse \"#\"")
		}
		found, uri.Fragment, remaining = abnfp.Parse(remaining, FindFragment)
		if !found {
			return nil, errors.New("[ \"#\" fragment ] found. But failed to parse fragment.")
		}
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
