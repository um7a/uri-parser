package urip

import (
	abnfp "github.com/um7a/abnf-parser"
)

// RFC3986 - 2.1. Percent-Encoding
//
//  pct-encoded   = "%" HEXDIG HEXDIG
//

func FindPctEncoded(data []byte) (found bool, end int) {
	findPctEncoded := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		// "%"
		abnfp.CreateFind([]byte{'%'}),
		// HEXDIG
		abnfp.FindHexDig,
		// HEXDIG
		abnfp.FindHexDig,
	})
	return findPctEncoded(data[end:])
}

// RFC3986 - 2.2. Reserved Characters
//
//  reserved    = gen-delims / sub-delims
//

func FindReserved(data []byte) (found bool, end int) {
	findReserved := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		FindGenDelims,
		FindSubDelims,
	})
	return findReserved(data)
}

// RFC3986 - 2.2. Reserved Characters
//
//  gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
//

func FindGenDelims(data []byte) (found bool, end int) {
	findGenDelims := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{':'}),
		abnfp.CreateFind([]byte{'/'}),
		abnfp.CreateFind([]byte{'?'}),
		abnfp.CreateFind([]byte{'#'}),
		abnfp.CreateFind([]byte{'['}),
		abnfp.CreateFind([]byte{']'}),
		abnfp.CreateFind([]byte{'@'}),
	})
	return findGenDelims(data)
}

// RFC3986 - 2.2. Reserved Characters
//
//  sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
//

func FindSubDelims(data []byte) (found bool, end int) {
	findSubDelims := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'!'}),
		abnfp.CreateFind([]byte{'$'}),
		abnfp.CreateFind([]byte{'&'}),
		abnfp.CreateFind([]byte{'\''}),
		abnfp.CreateFind([]byte{'('}),
		abnfp.CreateFind([]byte{')'}),
		abnfp.CreateFind([]byte{'*'}),
		abnfp.CreateFind([]byte{'+'}),
		abnfp.CreateFind([]byte{','}),
		abnfp.CreateFind([]byte{';'}),
		abnfp.CreateFind([]byte{'='}),
	})
	return findSubDelims(data)
}

// RFC3986 - 2.3. Unreserved Characters
//
//  unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
//

func FindUnreserved(data []byte) (found bool, end int) {
	findUnreserved := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		abnfp.FindAlpha,
		abnfp.FindDigit,
		abnfp.CreateFind([]byte{'-'}),
		abnfp.CreateFind([]byte{'.'}),
		abnfp.CreateFind([]byte{'_'}),
		abnfp.CreateFind([]byte{'~'}),
	})
	return findUnreserved(data)
}

// RFC3986 - 3. Syntax Components
//
//  URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//

func FindUri(data []byte) (found bool, end int) {
	findUrl := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		FindScheme,
		abnfp.CreateFind([]byte{':'}),
		FindHierPart,
		abnfp.CreateFindOptionalSequence(
			abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				abnfp.CreateFind([]byte{'?'}),
				FindQuery,
			}),
		),
		abnfp.CreateFindOptionalSequence(
			abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				abnfp.CreateFind([]byte{'#'}),
				FindQuery,
			}),
		),
	})
	return findUrl(data)
}

// RFC3986 - 3. Syntax Components
//
//  hier-part = "//" authority path-abempty
//            / path-absolute
//            / path-rootless
//            / path-empty
//

func FindHierPart(data []byte) (found bool, end int) {
	findHierPart := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte("//")),
			FindAuthority,
			FindPathAbempty,
		}),
		FindPathAbsolute,
		FindPathRootless,
		FindPathEmpty,
	})
	return findHierPart(data)
}

// RFC3986 - 3.1. Scheme
//
//  scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//

func FindScheme(data []byte) (found bool, end int) {
	findScheme := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.FindAlpha,
		abnfp.CreateFindVariableRepetition(
			abnfp.CreateFindAlternatives([]abnfp.FindFunc{
				abnfp.FindAlpha,
				abnfp.FindDigit,
				abnfp.CreateFind([]byte{'+'}),
				abnfp.CreateFind([]byte{'-'}),
				abnfp.CreateFind([]byte{'.'}),
			})),
	})
	return findScheme(data)
}

// RFC3986 - 3.2. Authority
//
//  authority = [ userinfo "@" ] host [ ":" port ]
//

func FindAuthority(data []byte) (found bool, end int) {
	findAuthority := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFindOptionalSequence(
			abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindUserInfo,
				abnfp.CreateFind([]byte{'@'}),
			}),
		),
		FindHost,
		abnfp.CreateFindOptionalSequence(
			abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				abnfp.CreateFind([]byte{':'}),
				FindPort,
			}),
		),
	})
	return findAuthority(data)
}

// RFC3986 - 3.2.1. User Information
//
//  userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
//

func FindUserInfo(data []byte) (found bool, end int) {
	findUserInfo := abnfp.CreateFindVariableRepetition(
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindUnreserved,
			FindPctEncoded,
			FindSubDelims,
			abnfp.CreateFind([]byte{':'}),
		}),
	)
	return findUserInfo(data)
}

// RFC3986 - 3.2.2. Host
//
//  host = IP-literal / IPv4address / reg-name
//

func FindHost(data []byte) (found bool, end int) {
	findHost := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		FindIpLiteral,
		FindIpV4Address,
		FindRegName,
	})
	return findHost(data)
}

// RFC3986 - 3.2.2. Host
//
//  IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
//

func FindIpLiteral(data []byte) (found bool, end int) {
	findIpLiteral := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'['}),
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindIpV6Address,
			FindIpVFuture,
		}),
		abnfp.CreateFind([]byte{']'}),
	})
	return findIpLiteral(data)
}

// RFC3986 - 3.2.2. Host
//
//  IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
//

func FindIpVFuture(data []byte) (found bool, end int) {
	findIpVFuture := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'v'}),
		abnfp.CreateFindVariableRepetitionMin(1, abnfp.FindHexDig),
		abnfp.CreateFind([]byte{'.'}),
		abnfp.CreateFindVariableRepetitionMin(1, abnfp.CreateFindAlternatives(
			[]abnfp.FindFunc{
				FindUnreserved,
				FindSubDelims,
				abnfp.CreateFind([]byte{':'}),
			},
		)),
	})
	return findIpVFuture(data)
}

// RFC3986 - 3.2.2. Host
//
//  IPv6address =                            6( h16 ":" ) ls32
//              /                       "::" 5( h16 ":" ) ls32
//              / [               h16 ] "::" 4( h16 ":" ) ls32
//              / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//              / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//              / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
//              / [ *4( h16 ":" ) h16 ] "::"              ls32
//              / [ *5( h16 ":" ) h16 ] "::"              h16
//              / [ *6( h16 ":" ) h16 ] "::"
//

func FindIpV6Address(data []byte) (found bool, end int) {
	findIpV6Address := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		//                            6( h16 ":" ) ls32
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindSpecificRepetition(6, abnfp.CreateFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFind([]byte{':'}),
				},
			)),
			FindLs32,
		}),
		//                       "::" 5( h16 ":" ) ls32
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{':', ':'}),
			abnfp.CreateFindSpecificRepetition(5, abnfp.CreateFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFind([]byte{':'}),
				},
			)),
			FindLs32,
		}),
		// [               h16 ] "::" 4( h16 ":" ) ls32
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(FindH16),
			abnfp.CreateFind([]byte{':', ':'}),
			abnfp.CreateFindSpecificRepetition(4, abnfp.CreateFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFind([]byte{':'}),
				},
			)),
			FindLs32,
		}),
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		//
		// FIXME
		// When parse []byte("FFFF::FFFF:FFFF:FFFF:FFFF:FFFF"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *1( ":" h16 ) ] "::" 3( h16 ":" ) ls32
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(
				abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFindVariableRepetitionMax(1, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
						abnfp.CreateFind([]byte{':'}),
						FindH16,
					})),
				}),
			),
			abnfp.CreateFind([]byte{':', ':'}),
			abnfp.CreateFindSpecificRepetition(3, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindH16,
				abnfp.CreateFind([]byte{':'}),
			})),
			FindLs32,
		}),
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		// FIXME
		// When parse []byte("FFFF:FFFF::FFFF:FFFF:FFFF:FFFF"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *2( ":" h16 ) ] "::" 2( h16 ":" ) ls32
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(
				abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFindVariableRepetitionMax(2, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
						abnfp.CreateFind([]byte{':'}),
						FindH16,
					})),
				}),
			),
			abnfp.CreateFind([]byte{':', ':'}),
			abnfp.CreateFindSpecificRepetition(2, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindH16,
				abnfp.CreateFind([]byte{':'}),
			})),
			FindLs32,
		}),
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		// FIXME
		// When parse []byte("FFFF:FFFF:FFFF::FFFF:FFFF:FFFF"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *3( ":" h16 ) ] "::"    h16 ":"   ls32
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(
				abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					FindH16,
					abnfp.CreateFindVariableRepetitionMax(3, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
						abnfp.CreateFind([]byte{':'}),
						FindH16,
					})),
				}),
			),
			abnfp.CreateFind([]byte{':', ':'}),
			FindH16,
			abnfp.CreateFind([]byte{':'}),
			FindLs32,
		}),
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		// FIXME
		// When parse []byte("FFFF:FFFF:FFFF:FFFF::FFFF:FFFF"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *4( ":" h16 ) ] "::"              ls32
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindH16,
				abnfp.CreateFindVariableRepetitionMax(4, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					abnfp.CreateFind([]byte{':'}),
					FindH16,
				})),
			})),
			abnfp.CreateFind([]byte{':', ':'}),
			FindLs32,
		}),
		// [ *5( h16 ":" ) h16 ] "::"              h16
		// FIXME
		// When parse []byte("FFFF:FFFF:FFFF:FFFF:FFFF::FFFF"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *5( ":" h16 ) ] "::"             h16
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindH16,
				abnfp.CreateFindVariableRepetitionMax(5, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					abnfp.CreateFind([]byte{':'}),
					FindH16,
				})),
			})),
			abnfp.CreateFind([]byte{':', ':'}),
			FindH16,
		}),
		// [ *6( h16 ":" ) h16 ] "::"
		// FIXME
		// When parse []byte("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::"),
		// the 'FFFF::' is h16 ":" ":". This is parsed as ( h16 ":" ) and ":".
		// This makes the parsing fail.
		// To avoid this issue, I should fix abnf-parser.
		// But as a hot fix, I modify the rule as follows.
		//
		//  [ h16 *6( ":" h16 ) ] "::"
		//
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindOptionalSequence(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				FindH16,
				abnfp.CreateFindVariableRepetitionMax(6, abnfp.CreateFindConcatenation([]abnfp.FindFunc{
					abnfp.CreateFind([]byte{':'}),
					FindH16,
				})),
			})),
			abnfp.CreateFind([]byte{':', ':'}),
		}),
	})
	return findIpV6Address(data)
}

// RFC3986 - 3.2.2. Host
//
//  ls32        = ( h16 ":" h16 ) / IPv4address
//  ; least-significant 32 bits of address
//

func FindLs32(data []byte) (found bool, end int) {
	findH32 := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			FindH16,
			abnfp.CreateFind([]byte{':'}),
			FindH16,
		}),
		FindIpV4Address,
	})
	return findH32(data)
}

// RFC3986 - 3.2.2. Host
//
//  h16         = 1*4HEXDIG
//  ; 16 bits of address represented in hexadecimal
//

func FindH16(data []byte) (found bool, end int) {
	findH16 := abnfp.CreateFindVariableRepetitionMinMax(1, 4, abnfp.FindHexDig)
	return findH16(data)
}

// RFC3986 - 3.2.2. Host
//
//  IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
//

func FindIpV4Address(data []byte) (found bool, end int) {
	findIpV4Address := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		FindDecOctet,
		abnfp.CreateFind([]byte{'.'}),
		FindDecOctet,
		abnfp.CreateFind([]byte{'.'}),
		FindDecOctet,
		abnfp.CreateFind([]byte{'.'}),
		FindDecOctet,
	})
	return findIpV4Address(data)
}

// RFC3986 - 3.2.2. Host
//
//  dec-octet = DIGIT                 ; 0-9
//            / %x31-39 DIGIT         ; 10-99
//            / "1" 2DIGIT            ; 100-199
//            / "2" %x30-34 DIGIT     ; 200-249
//            / "25" %x30-35          ; 250-255
//

func FindDecOctet(data []byte) (found bool, end int) {
	findDecOctet := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		// "25" %x30-35          ; 250-255
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'2', '5'}),
			abnfp.CreateFindValueRangeAlternatives(0x30, 0x35),
		}),
		// "2" %x30-34 DIGIT     ; 200-249
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'2'}),
			abnfp.CreateFindValueRangeAlternatives(0x30, 0x34),
			abnfp.FindDigit,
		}),
		// "1" 2DIGIT            ; 100-199
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'1'}),
			abnfp.CreateFindSpecificRepetition(2, abnfp.FindDigit),
		}),
		// %x31-39 DIGIT         ; 10-99
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFindValueRangeAlternatives(0x31, 0x39),
			abnfp.FindDigit,
		}),
		// DIGIT                 ; 0-9
		abnfp.FindDigit,
	})
	return findDecOctet(data)
}

// RFC3986 - 3.2.2. Host
//
//  reg-name = *( unreserved / pct-encoded / sub-delims )
//

func FindRegName(data []byte) (found bool, end int) {
	findRegName := abnfp.CreateFindVariableRepetition(
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindUnreserved,
			FindPctEncoded,
			FindSubDelims,
		}),
	)
	return findRegName(data)
}

// RFC3986 - 3.2.3. Port
//
//  port = *DIGIT
//

func FindPort(data []byte) (found bool, end int) {
	findPort := abnfp.CreateFindVariableRepetition(abnfp.FindDigit)
	return findPort(data)
}

// RFC3986 - 3.3. Path
//
//  path = path-abempty    ; begins with "/" or is empty
//       / path-absolute   ; begins with "/" but not "//"
//       / path-noscheme   ; begins with a non-colon segment
//       / path-rootless   ; begins with a segment
//       / path-empty      ; zero characters
//

func FindPath(data []byte) (found bool, end int) {
	// NOTE
	// path-absolute and path-empty match 0 byte data.
	// So move to the last of the slice.
	findPath := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		FindPathAbsolute,
		FindPathNoScheme,
		FindPathRootless,
		FindPathAbempty,
		FindPathEmpty,
	})
	return findPath(data)
}

// RFC3986 - 3.3. Path
//
//  path-abempty  = *( "/" segment )
//

func FindPathAbempty(data []byte) (found bool, end int) {
	findPathAbempty := abnfp.CreateFindVariableRepetition(
		abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'/'}),
			FindSegment,
		}),
	)
	return findPathAbempty(data)
}

// RFC3986 - 3.3. Path
//
//  path-absolute = "/" [ segment-nz *( "/" segment ) ]
//

func FindPathAbsolute(data []byte) (found bool, end int) {
	findPathAbsolute := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		abnfp.CreateFind([]byte{'/'}),
		abnfp.CreateFindOptionalSequence(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			FindSegmentNz,
			abnfp.CreateFindVariableRepetition(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
				abnfp.CreateFind([]byte{'/'}),
				FindSegment,
			})),
		})),
	})
	return findPathAbsolute(data)
}

// RFC3986 - 3.3. Path
//
//  path-noscheme = segment-nz-nc *( "/" segment )
//

func FindPathNoScheme(data []byte) (found bool, end int) {
	findPathNoScheme := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		FindSegmentNzNc,
		abnfp.CreateFindVariableRepetition(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'/'}),
			FindSegment,
		})),
	})
	return findPathNoScheme(data)
}

// RFC3986 - 3.3. Path
//
//  path-rootless = segment-nz *( "/" segment )
//

func FindPathRootless(data []byte) (found bool, end int) {
	findPathRootless := abnfp.CreateFindConcatenation([]abnfp.FindFunc{
		FindSegmentNz,
		abnfp.CreateFindVariableRepetition(abnfp.CreateFindConcatenation([]abnfp.FindFunc{
			abnfp.CreateFind([]byte{'/'}),
			FindSegment,
		})),
	})
	return findPathRootless(data)
}

// RFC3986 - 3.3. Path
//
//  path-empty    = 0<pchar>
//

func FindPathEmpty(data []byte) (found bool, end int) {
	return true, 0
}

// RFC3986 - 3.3. Path
//
//  segment       = *pchar
//

func FindSegment(data []byte) (found bool, end int) {
	findSegment := abnfp.CreateFindVariableRepetition(FindPchar)
	return findSegment(data)
}

// RFC3986 - 3.3. Path
//
//  segment-nz    = 1*pchar
//

func FindSegmentNz(data []byte) (found bool, end int) {
	findSegmentNz := abnfp.CreateFindVariableRepetitionMin(1, FindPchar)
	return findSegmentNz(data)
}

// RFC3986 - 3.3. Path
//
//  segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//  							; non-zero-length segment without any colon ":"
//

func FindSegmentNzNc(data []byte) (found bool, end int) {
	findSegmentNzNc := abnfp.CreateFindVariableRepetitionMin(1,
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindUnreserved,
			FindPctEncoded,
			FindSubDelims,
			abnfp.CreateFind([]byte{'@'}),
		}),
	)
	return findSegmentNzNc(data)
}

// RFC3986 - 3.3. Path
//
//  pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//

func FindPchar(data []byte) (found bool, end int) {
	findPchar := abnfp.CreateFindAlternatives([]abnfp.FindFunc{
		FindUnreserved,
		FindPctEncoded,
		FindSubDelims,
		abnfp.CreateFind([]byte{':'}),
		abnfp.CreateFind([]byte{'@'}),
	})
	return findPchar(data)
}

// RFC3986 - 3.4. Query
//
//  query = *( pchar / "/" / "?" )
//

func FindQuery(data []byte) (found bool, end int) {
	findQuery := abnfp.CreateFindVariableRepetition(
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindPchar,
			abnfp.CreateFind([]byte{'/'}),
			abnfp.CreateFind([]byte{'?'}),
		}),
	)
	return findQuery(data)
}

// RFC3986 - 3.5. Fragment
//
//  fragment = *( pchar / "/" / "?" )
//

func FindFragment(data []byte) (found bool, end int) {
	findFragment := abnfp.CreateFindVariableRepetition(
		abnfp.CreateFindAlternatives([]abnfp.FindFunc{
			FindPchar,
			abnfp.CreateFind([]byte{'/'}),
			abnfp.CreateFind([]byte{'?'}),
		}),
	)
	return findFragment(data)
}
