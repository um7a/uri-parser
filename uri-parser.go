package urip

import (
	abnfp "github.com/um7a/abnf-parser"
)

// RFC3986 - 2.1. Percent-Encoding
//
//  pct-encoded   = "%" HEXDIG HEXDIG
//

func NewPctEncodedFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewByteFinder('%'),
		abnfp.NewHexDigFinder(),
		abnfp.NewHexDigFinder(),
	})
}

// RFC3986 - 2.2. Reserved Characters
//
//  reserved    = gen-delims / sub-delims
//

func NewReservedFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewGenDelimsFinder(),
		NewSubDelimsFinder(),
	})
}

// RFC3986 - 2.2. Reserved Characters
//
//  gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
//

func NewGenDelimsFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewByteFinder(':'),
		abnfp.NewByteFinder('/'),
		abnfp.NewByteFinder('?'),
		abnfp.NewByteFinder('#'),
		abnfp.NewByteFinder('['),
		abnfp.NewByteFinder(']'),
		abnfp.NewByteFinder('@'),
	})
}

// RFC3986 - 2.2. Reserved Characters
//
//  sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
//

func NewSubDelimsFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewByteFinder('!'),
		abnfp.NewByteFinder('$'),
		abnfp.NewByteFinder('&'),
		abnfp.NewByteFinder('\''),
		abnfp.NewByteFinder('('),
		abnfp.NewByteFinder(')'),
		abnfp.NewByteFinder('*'),
		abnfp.NewByteFinder('+'),
		abnfp.NewByteFinder(','),
		abnfp.NewByteFinder(';'),
		abnfp.NewByteFinder('='),
	})
}

// RFC3986 - 2.3. Unreserved Characters
//
//  unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
//

func NewUnreservedFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewAlphaFinder(),
		abnfp.NewDigitFinder(),
		abnfp.NewByteFinder('-'),
		abnfp.NewByteFinder('.'),
		abnfp.NewByteFinder('_'),
		abnfp.NewByteFinder('~'),
	})
}

// RFC3986 - 3. Syntax Components
//
//  URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//

func NewUriFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewSchemeFinder(),
		abnfp.NewByteFinder(':'),
		NewHierPartFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('?'),
				NewQueryFinder(),
			}),
		),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('#'),
				NewQueryFinder(),
			}),
		),
	})
}

// RFC3986 - 3. Syntax Components
//
//  hier-part = "//" authority path-abempty
//            / path-absolute
//            / path-rootless
//            / path-empty
//

func NewHierPartFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewBytesFinder([]byte("//")),
			NewAuthorityFinder(),
			NewPathAbemptyFinder(),
		}),
		NewPathAbsoluteFinder(),
		NewPathRootlessFinder(),
		NewPathEmptyFinder(),
	})
}

// RFC3986 - 3.1. Scheme
//
//  scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//

func NewSchemeFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewAlphaFinder(),
		abnfp.NewVariableRepetitionFinder(
			abnfp.NewAlternativesFinder([]abnfp.Finder{
				abnfp.NewAlphaFinder(),
				abnfp.NewDigitFinder(),
				abnfp.NewByteFinder('+'),
				abnfp.NewByteFinder('-'),
				abnfp.NewByteFinder('.'),
			})),
	})
}

// RFC3986 - 3.2. Authority
//
//  authority = [ userinfo "@" ] host [ ":" port ]
//

func NewAuthorityFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				NewUserInfoFinder(),
				abnfp.NewByteFinder('@'),
			}),
		),
		NewHostFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder(':'),
				NewPortFinder(),
			}),
		),
	})
}

// RFC3986 - 3.2.1. User Information
//
//  userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
//

func NewUserInfoFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewUnreservedFinder(),
			NewPctEncodedFinder(),
			NewSubDelimsFinder(),
			abnfp.NewByteFinder(':'),
		}),
	)
}

// RFC3986 - 3.2.2. Host
//
//  host = IP-literal / IPv4address / reg-name
//

func NewHostFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewIpLiteralFinder(),
		NewIpV4AddressFinder(),
		NewRegNameFinder(),
	})
}

// RFC3986 - 3.2.2. Host
//
//  IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
//

func NewIpLiteralFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewByteFinder('['),
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewIpV6AddressFinder(),
			NewIpVFutureFinder(),
		}),
		abnfp.NewByteFinder(']'),
	})
}

// RFC3986 - 3.2.2. Host
//
//  IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
//

func NewIpVFutureFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewByteFinder('v'),
		abnfp.NewVariableRepetitionMinFinder(1, abnfp.NewHexDigFinder()),
		abnfp.NewByteFinder('.'),
		abnfp.NewVariableRepetitionMinFinder(1, abnfp.NewAlternativesFinder(
			[]abnfp.Finder{
				NewUnreservedFinder(),
				NewSubDelimsFinder(),
				abnfp.NewByteFinder(':'),
			},
		)),
	})
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

func NewIpV6AddressFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		//                            6( h16 ":" ) ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewSpecificRepetitionFinder(6, abnfp.NewConcatenationFinder(
				[]abnfp.Finder{
					NewH16Finder(),
					abnfp.NewByteFinder(':'),
				},
			)),
			NewLs32Finder(),
		}),
		//                       "::" 5( h16 ":" ) ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewBytesFinder([]byte("::")),
			abnfp.NewSpecificRepetitionFinder(5, abnfp.NewConcatenationFinder(
				[]abnfp.Finder{
					NewH16Finder(),
					abnfp.NewByteFinder(':'),
				},
			)),
			NewLs32Finder(),
		}),
		// [               h16 ] "::" 4( h16 ":" ) ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(NewH16Finder()),
			abnfp.NewBytesFinder([]byte("::")),
			abnfp.NewSpecificRepetitionFinder(4, abnfp.NewConcatenationFinder(
				[]abnfp.Finder{
					NewH16Finder(),
					abnfp.NewByteFinder(':'),
				},
			)),
			NewLs32Finder(),
		}),
		// [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(1,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
			abnfp.NewSpecificRepetitionFinder(3,
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					NewH16Finder(),
					abnfp.NewByteFinder(':'),
				}),
			),
			NewLs32Finder(),
		}),
		// [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(2,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
			abnfp.NewSpecificRepetitionFinder(2,
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					NewH16Finder(),
					abnfp.NewByteFinder(':'),
				}),
			),
			NewLs32Finder(),
		}),
		// [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(3,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
			NewH16Finder(),
			abnfp.NewByteFinder(':'),
			NewLs32Finder(),
		}),
		// [ *4( h16 ":" ) h16 ] "::"              ls32
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(4,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
			NewLs32Finder(),
		}),
		// [ *5( h16 ":" ) h16 ] "::"              h16
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(5,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
			NewH16Finder(),
		}),
		// [ *6( h16 ":" ) h16 ] "::"
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewOptionalSequenceFinder(
				abnfp.NewConcatenationFinder([]abnfp.Finder{
					abnfp.NewVariableRepetitionMaxFinder(6,
						abnfp.NewConcatenationFinder([]abnfp.Finder{
							NewH16Finder(),
							abnfp.NewByteFinder(':'),
						}),
					),
					NewH16Finder(),
				}),
			),
			abnfp.NewBytesFinder([]byte("::")),
		}),
	})
}

// RFC3986 - 3.2.2. Host
//
//  ls32        = ( h16 ":" h16 ) / IPv4address
//  ; least-significant 32 bits of address
//

func NewLs32Finder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			NewH16Finder(),
			abnfp.NewByteFinder(':'),
			NewH16Finder(),
		}),
		NewIpV4AddressFinder(),
	})
}

// RFC3986 - 3.2.2. Host
//
//  h16         = 1*4HEXDIG
//  ; 16 bits of address represented in hexadecimal
//

func NewH16Finder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinMaxFinder(1, 4, abnfp.NewHexDigFinder())
}

// RFC3986 - 3.2.2. Host
//
//  IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
//

func NewIpV4AddressFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewDecOctetFinder(),
		abnfp.NewByteFinder('.'),
		NewDecOctetFinder(),
		abnfp.NewByteFinder('.'),
		NewDecOctetFinder(),
		abnfp.NewByteFinder('.'),
		NewDecOctetFinder(),
	})
}

// RFC3986 - 3.2.2. Host
//
//  dec-octet = DIGIT                 ; 0-9
//            / %x31-39 DIGIT         ; 10-99
//            / "1" 2DIGIT            ; 100-199
//            / "2" %x30-34 DIGIT     ; 200-249
//            / "25" %x30-35          ; 250-255
//

func NewDecOctetFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		// "25" %x30-35          ; 250-255
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewBytesFinder([]byte("25")),
			abnfp.NewValueRangeAlternativesFinder(0x30, 0x35),
		}),
		// "2" %x30-34 DIGIT     ; 200-249
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('2'),
			abnfp.NewValueRangeAlternativesFinder(0x30, 0x34),
			abnfp.NewDigitFinder(),
		}),
		// "1" 2DIGIT            ; 100-199
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('1'),
			abnfp.NewSpecificRepetitionFinder(2, abnfp.NewDigitFinder()),
		}),
		// %x31-39 DIGIT         ; 10-99
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewValueRangeAlternativesFinder(0x31, 0x39),
			abnfp.NewDigitFinder(),
		}),
		// DIGIT                 ; 0-9
		abnfp.NewDigitFinder(),
	})
}

// RFC3986 - 3.2.2. Host
//
//  reg-name = *( unreserved / pct-encoded / sub-delims )
//

func NewRegNameFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewUnreservedFinder(),
			NewPctEncodedFinder(),
			NewSubDelimsFinder(),
		}),
	)
}

// RFC3986 - 3.2.3. Port
//
//  port = *DIGIT
//

func NewPortFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(abnfp.NewDigitFinder())
}

// RFC3986 - 3.3. Path
//
//  path = path-abempty    ; begins with "/" or is empty
//       / path-absolute   ; begins with "/" but not "//"
//       / path-noscheme   ; begins with a non-colon segment
//       / path-rootless   ; begins with a segment
//       / path-empty      ; zero characters
//

func NewPathFinder() abnfp.Finder {
	// NOTE
	// path-abempty and path-empty match 0 byte data.
	// So move to the last of the slice.
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewPathAbsoluteFinder(), // path-absolute = "/" [ segment-nz *( "/" segment ) ]
		NewPathNoSchemeFinder(), // path-noscheme = segment-nz-nc *( "/" segment )
		NewPathRootlessFinder(), // path-rootless = segment-nz *( "/" segment )
		NewPathAbemptyFinder(),  // path-abempty  = *( "/" segment )
		NewPathEmptyFinder(),    // path-empty    = 0<pchar>
	})
}

// RFC3986 - 3.3. Path
//
//  path-abempty  = *( "/" segment )
//

func NewPathAbemptyFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('/'),
			NewSegmentFinder(),
		}),
	)
}

// RFC3986 - 3.3. Path
//
//  path-absolute = "/" [ segment-nz *( "/" segment ) ]
//

func NewPathAbsoluteFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewByteFinder('/'),
		abnfp.NewOptionalSequenceFinder(abnfp.NewConcatenationFinder([]abnfp.Finder{
			NewSegmentNzFinder(),
			abnfp.NewVariableRepetitionFinder(abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('/'),
				NewSegmentFinder(),
			})),
		})),
	})
}

// RFC3986 - 3.3. Path
//
//  path-noscheme = segment-nz-nc *( "/" segment )
//

func NewPathNoSchemeFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewSegmentNzNcFinder(),
		abnfp.NewVariableRepetitionFinder(abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('/'),
			NewSegmentFinder(),
		})),
	})
}

// RFC3986 - 3.3. Path
//
//  path-rootless = segment-nz *( "/" segment )
//

func NewPathRootlessFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewSegmentNzFinder(),
		abnfp.NewVariableRepetitionFinder(abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('/'),
			NewSegmentFinder(),
		})),
	})
}

// RFC3986 - 3.3. Path
//
//  path-empty    = 0<pchar>
//

func NewPathEmptyFinder() abnfp.Finder {
	return abnfp.NewSpecificRepetitionFinder(0, NewPcharFinder())
}

// RFC3986 - 3.3. Path
//
//  segment       = *pchar
//

func NewSegmentFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(NewPcharFinder())
}

// RFC3986 - 3.3. Path
//
//  segment-nz    = 1*pchar
//

func NewSegmentNzFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(1, NewPcharFinder())
}

// RFC3986 - 3.3. Path
//
//  segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//  							; non-zero-length segment without any colon ":"
//

func NewSegmentNzNcFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(1,
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewUnreservedFinder(),
			NewPctEncodedFinder(),
			NewSubDelimsFinder(),
			abnfp.NewByteFinder('@'),
		}),
	)
}

// RFC3986 - 3.3. Path
//
//  pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//

func NewPcharFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewUnreservedFinder(),
		NewPctEncodedFinder(),
		NewSubDelimsFinder(),
		abnfp.NewByteFinder(':'),
		abnfp.NewByteFinder('@'),
	})
}

// RFC3986 - 3.4. Query
//
//  query = *( pchar / "/" / "?" )
//

func NewQueryFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewPcharFinder(),
			abnfp.NewByteFinder('/'),
			abnfp.NewByteFinder('?'),
		}),
	)
}

// RFC3986 - 3.5. Fragment
//
//  fragment = *( pchar / "/" / "?" )
//

func NewFragmentFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			NewPcharFinder(),
			abnfp.NewByteFinder('/'),
			abnfp.NewByteFinder('?'),
		}),
	)
}

// RFC3986 - 4.1. URI Reference
// URI-reference is used to denote the most common usage of a resource identifier.
//
//  URI-reference = URI / relative-ref
//

func NewUriReferenceFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewUriFinder(),
		NewRelativeRefFinder(),
	})
}

// RFC3986 - 4.2. Relative Reference
//
//  relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
//

func NewRelativeRefFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewRelativePartFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('?'),
				NewQueryFinder(),
			}),
		),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('#'),
				NewFragmentFinder(),
			}),
		),
	})
}

// RFC3986 - 4.2. Relative Reference
//
//  relative-part = "//" authority path-abempty
//                / path-absolute
//                / path-noscheme
//                / path-empty
//

func NewRelativePartFinder() abnfp.Finder {
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
	return NewHierPartFinder()
}

// RFC3986 - 4.3. Absolute URI
//
//  absolute-URI  = scheme ":" hier-part [ "?" query ]
//

func NewAbsoluteUriFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewSchemeFinder(),
		abnfp.NewByteFinder(':'),
		NewHierPartFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('?'),
				NewQueryFinder(),
			}),
		),
	})
}
