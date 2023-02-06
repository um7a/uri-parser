package urip

import (
	abnfp "github.com/um7a/abnf-parser"
)

// RFC3986 - 2.1. Percent-Encoding
//
//  pct-encoded   = "%" HEXDIG HEXDIG
//

func FindPctEncoded(data []byte) []int {
	findPctEncoded := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindByte('%'),
		abnfp.FindHexDig,
		abnfp.FindHexDig,
	})
	return findPctEncoded(data)
}

// RFC3986 - 2.2. Reserved Characters
//
//  reserved    = gen-delims / sub-delims
//

func FindReserved(data []byte) []int {
	findReserved := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindGenDelims,
		FindSubDelims,
	})
	return findReserved(data)
}

// RFC3986 - 2.2. Reserved Characters
//
//  gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
//

func FindGenDelims(data []byte) []int {
	findGenDelims := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.NewFindByte(':'),
		abnfp.NewFindByte('/'),
		abnfp.NewFindByte('?'),
		abnfp.NewFindByte('#'),
		abnfp.NewFindByte('['),
		abnfp.NewFindByte(']'),
		abnfp.NewFindByte('@'),
	})
	return findGenDelims(data)
}

// RFC3986 - 2.2. Reserved Characters
//
//  sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
//

func FindSubDelims(data []byte) []int {
	findSubDelims := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.NewFindByte('!'),
		abnfp.NewFindByte('$'),
		abnfp.NewFindByte('&'),
		abnfp.NewFindByte('\''),
		abnfp.NewFindByte('('),
		abnfp.NewFindByte(')'),
		abnfp.NewFindByte('*'),
		abnfp.NewFindByte('+'),
		abnfp.NewFindByte(','),
		abnfp.NewFindByte(';'),
		abnfp.NewFindByte('='),
	})
	return findSubDelims(data)
}

// RFC3986 - 2.3. Unreserved Characters
//
//  unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
//

func FindUnreserved(data []byte) []int {
	findUnreserved := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.FindAlpha,
		abnfp.FindDigit,
		abnfp.NewFindByte('-'),
		abnfp.NewFindByte('.'),
		abnfp.NewFindByte('_'),
		abnfp.NewFindByte('~'),
	})
	return findUnreserved(data)
}

// RFC3986 - 3. Syntax Components
//
//  URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//

func FindUri(data []byte) []int {
	findUrl := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindScheme,
		abnfp.NewFindByte(':'),
		FindHierPart,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('?'),
				FindQuery,
			}),
		),
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('#'),
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

func FindHierPart(data []byte) []int {
	findHierPart := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindBytes([]byte("//")),
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

func FindScheme(data []byte) []int {
	findScheme := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.FindAlpha,
		abnfp.NewFindVariableRepetition(
			abnfp.NewFindAlternatives([]abnfp.FindFunc{
				abnfp.FindAlpha,
				abnfp.FindDigit,
				abnfp.NewFindByte('+'),
				abnfp.NewFindByte('-'),
				abnfp.NewFindByte('.'),
			})),
	})
	return findScheme(data)
}

// RFC3986 - 3.2. Authority
//
//  authority = [ userinfo "@" ] host [ ":" port ]
//

func FindAuthority(data []byte) []int {
	findAuthority := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				FindUserInfo,
				abnfp.NewFindByte('@'),
			}),
		),
		FindHost,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte(':'),
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

func FindUserInfo(data []byte) []int {
	findUserInfo := abnfp.NewFindVariableRepetition(
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			FindUnreserved,
			FindPctEncoded,
			FindSubDelims,
			abnfp.NewFindByte(':'),
		}),
	)
	return findUserInfo(data)
}

// RFC3986 - 3.2.2. Host
//
//  host = IP-literal / IPv4address / reg-name
//

func FindHost(data []byte) []int {
	findHost := abnfp.NewFindAlternatives([]abnfp.FindFunc{
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

func FindIpLiteral(data []byte) []int {
	findIpLiteral := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindByte('['),
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			FindIpV6Address,
			FindIpVFuture,
		}),
		abnfp.NewFindByte(']'),
	})
	return findIpLiteral(data)
}

// RFC3986 - 3.2.2. Host
//
//  IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
//

func FindIpVFuture(data []byte) []int {
	findIpVFuture := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindByte('v'),
		abnfp.NewFindVariableRepetitionMin(1, abnfp.FindHexDig),
		abnfp.NewFindByte('.'),
		abnfp.NewFindVariableRepetitionMin(1, abnfp.NewFindAlternatives(
			[]abnfp.FindFunc{
				FindUnreserved,
				FindSubDelims,
				abnfp.NewFindByte(':'),
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

func FindIpV6Address(data []byte) []int {
	findIpV6Address := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		//                            6( h16 ":" ) ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindSpecificRepetition(6, abnfp.NewFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.NewFindByte(':'),
				},
			)),
			FindLs32,
		}),
		//                       "::" 5( h16 ":" ) ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindBytes([]byte("::")),
			abnfp.NewFindSpecificRepetition(5, abnfp.NewFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.NewFindByte(':'),
				},
			)),
			FindLs32,
		}),
		// [               h16 ] "::" 4( h16 ":" ) ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(FindH16),
			abnfp.NewFindBytes([]byte("::")),
			abnfp.NewFindSpecificRepetition(4, abnfp.NewFindConcatenation(
				[]abnfp.FindFunc{
					FindH16,
					abnfp.NewFindByte(':'),
				},
			)),
			FindLs32,
		}),
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(1,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
			abnfp.NewFindSpecificRepetition(3,
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					FindH16,
					abnfp.NewFindByte(':'),
				}),
			),
			FindLs32,
		}),
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(2,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
			abnfp.NewFindSpecificRepetition(2,
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					FindH16,
					abnfp.NewFindByte(':'),
				}),
			),
			FindLs32,
		}),
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(3,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
			FindH16,
			abnfp.NewFindByte(':'),
			FindLs32,
		}),
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(4,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
			FindLs32,
		}),
		// [ *5( h16 ":" ) h16 ] "::"              h16
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(5,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
			FindH16,
		}),
		// [ *6( h16 ":" ) h16 ] "::"
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindOptionalSequence(
				abnfp.NewFindConcatenation([]abnfp.FindFunc{
					abnfp.NewFindVariableRepetitionMax(6,
						abnfp.NewFindConcatenation([]abnfp.FindFunc{
							FindH16,
							abnfp.NewFindByte(':'),
						}),
					),
					FindH16,
				}),
			),
			abnfp.NewFindBytes([]byte("::")),
		}),
	})
	return findIpV6Address(data)
}

// RFC3986 - 3.2.2. Host
//
//  ls32        = ( h16 ":" h16 ) / IPv4address
//  ; least-significant 32 bits of address
//

func FindLs32(data []byte) []int {
	findH32 := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			FindH16,
			abnfp.NewFindByte(':'),
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

func FindH16(data []byte) []int {
	findH16 := abnfp.NewFindVariableRepetitionMinMax(1, 4, abnfp.FindHexDig)
	return findH16(data)
}

// RFC3986 - 3.2.2. Host
//
//  IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
//

func FindIpV4Address(data []byte) []int {
	findIpV4Address := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindDecOctet,
		abnfp.NewFindByte('.'),
		FindDecOctet,
		abnfp.NewFindByte('.'),
		FindDecOctet,
		abnfp.NewFindByte('.'),
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

func FindDecOctet(data []byte) []int {
	findDecOctet := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		// "25" %x30-35          ; 250-255
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindBytes([]byte("25")),
			abnfp.NewFindValueRangeAlternatives(0x30, 0x35),
		}),
		// "2" %x30-34 DIGIT     ; 200-249
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('2'),
			abnfp.NewFindValueRangeAlternatives(0x30, 0x34),
			abnfp.FindDigit,
		}),
		// "1" 2DIGIT            ; 100-199
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('1'),
			abnfp.NewFindSpecificRepetition(2, abnfp.FindDigit),
		}),
		// %x31-39 DIGIT         ; 10-99
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindValueRangeAlternatives(0x31, 0x39),
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

func FindRegName(data []byte) []int {
	findRegName := abnfp.NewFindVariableRepetition(
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
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

func FindPort(data []byte) []int {
	findPort := abnfp.NewFindVariableRepetition(abnfp.FindDigit)
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

func FindPath(data []byte) []int {
	// NOTE
	// path-absolute and path-empty match 0 byte data.
	// So move to the last of the slice.
	findPath := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindPathAbempty,
		FindPathAbsolute,
		FindPathNoScheme,
		FindPathRootless,
		FindPathEmpty,
	})
	return findPath(data)
}

// RFC3986 - 3.3. Path
//
//  path-abempty  = *( "/" segment )
//

func FindPathAbempty(data []byte) []int {
	findPathAbempty := abnfp.NewFindVariableRepetition(
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('/'),
			FindSegment,
		}),
	)
	return findPathAbempty(data)
}

// RFC3986 - 3.3. Path
//
//  path-absolute = "/" [ segment-nz *( "/" segment ) ]
//

func FindPathAbsolute(data []byte) []int {
	findPathAbsolute := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindByte('/'),
		abnfp.NewFindOptionalSequence(abnfp.NewFindConcatenation([]abnfp.FindFunc{
			FindSegmentNz,
			abnfp.NewFindVariableRepetition(abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('/'),
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

func FindPathNoScheme(data []byte) []int {
	findPathNoScheme := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindSegmentNzNc,
		abnfp.NewFindVariableRepetition(abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('/'),
			FindSegment,
		})),
	})
	return findPathNoScheme(data)
}

// RFC3986 - 3.3. Path
//
//  path-rootless = segment-nz *( "/" segment )
//

func FindPathRootless(data []byte) []int {
	findPathRootless := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindSegmentNz,
		abnfp.NewFindVariableRepetition(abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('/'),
			FindSegment,
		})),
	})
	return findPathRootless(data)
}

// RFC3986 - 3.3. Path
//
//  path-empty    = 0<pchar>
//

func FindPathEmpty(data []byte) []int {
	return []int{0}
}

// RFC3986 - 3.3. Path
//
//  segment       = *pchar
//

func FindSegment(data []byte) []int {
	findSegment := abnfp.NewFindVariableRepetition(FindPchar)
	return findSegment(data)
}

// RFC3986 - 3.3. Path
//
//  segment-nz    = 1*pchar
//

func FindSegmentNz(data []byte) []int {
	findSegmentNz := abnfp.NewFindVariableRepetitionMin(1, FindPchar)
	return findSegmentNz(data)
}

// RFC3986 - 3.3. Path
//
//  segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//  							; non-zero-length segment without any colon ":"
//

func FindSegmentNzNc(data []byte) []int {
	findSegmentNzNc := abnfp.NewFindVariableRepetitionMin(1,
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			FindUnreserved,
			FindPctEncoded,
			FindSubDelims,
			abnfp.NewFindByte('@'),
		}),
	)
	return findSegmentNzNc(data)
}

// RFC3986 - 3.3. Path
//
//  pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//

func FindPchar(data []byte) []int {
	findPchar := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindUnreserved,
		FindPctEncoded,
		FindSubDelims,
		abnfp.NewFindByte(':'),
		abnfp.NewFindByte('@'),
	})
	return findPchar(data)
}

// RFC3986 - 3.4. Query
//
//  query = *( pchar / "/" / "?" )
//

func FindQuery(data []byte) []int {
	findQuery := abnfp.NewFindVariableRepetition(
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			FindPchar,
			abnfp.NewFindByte('/'),
			abnfp.NewFindByte('?'),
		}),
	)
	return findQuery(data)
}

// RFC3986 - 3.5. Fragment
//
//  fragment = *( pchar / "/" / "?" )
//

func FindFragment(data []byte) []int {
	findFragment := abnfp.NewFindVariableRepetition(
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			FindPchar,
			abnfp.NewFindByte('/'),
			abnfp.NewFindByte('?'),
		}),
	)
	return findFragment(data)
}

// RFC3986 - 4.1. URI Reference
// URI-reference is used to denote the most common usage of a resource identifier.
//
//  URI-reference = URI / relative-ref
//

func FindUriReference(data []byte) []int {
	findUriReference := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindUri,
		FindRelativeRef,
	})
	return findUriReference(data)
}

// RFC3986 - 4.2. Relative Reference
//
//  relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
//

func FindRelativeRef(data []byte) []int {
	findRelativeRef := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindRelativePart,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('?'),
				FindQuery,
			}),
		),
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('#'),
				FindFragment,
			}),
		),
	})
	return findRelativeRef(data)
}

// RFC3986 - 4.2. Relative Reference
//
//  relative-part = "//" authority path-abempty
//                / path-absolute
//                / path-noscheme
//                / path-empty
//

func FindRelativePart(data []byte) []int {
	// NOTE
	// I think relative-part is the same with hier-part.
	//
	// RFC3986 - 3. Syntax Components
	//
	//  hier-part = "//" authority path-abempty
	//            / path-absolute
	//            / path-rootless
	//            / path-empty
	//
	return FindHierPart(data)
}

// RFC3986 - 4.3. Absolute URI
//
//  absolute-URI  = scheme ":" hier-part [ "?" query ]
//

func FindAbsoluteUri(data []byte) []int {
	findAbsoluteUri := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindScheme,
		abnfp.NewFindByte(':'),
		FindHierPart,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindByte('?'),
				FindQuery,
			}),
		),
	})
	return findAbsoluteUri(data)
}
