use "collections"

type X509ExtendedKeyUsageFlags is Flags[(XKUSSLServer|XKUSSLClient|XKUSMIME|XKUCodeSign|XKUSGC|XKUOCSPSign|XKUTimestamp|XKUDVCS|XKUANYEKU), U32]

primitive XKUSSLServer is Flag[U32] fun value(): U32 => 0x1
primitive XKUSSLClient is Flag[U32] fun value(): U32 => 0x2
primitive XKUSMIME     is Flag[U32] fun value(): U32 => 0x4
primitive XKUCodeSign  is Flag[U32] fun value(): U32 => 0x8
primitive XKUSGC       is Flag[U32] fun value(): U32 => 0x10
primitive XKUOCSPSign  is Flag[U32] fun value(): U32 => 0x20
primitive XKUTimestamp is Flag[U32] fun value(): U32 => 0x40
primitive XKUDVCS      is Flag[U32] fun value(): U32 => 0x80
primitive XKUANYEKU    is Flag[U32] fun value(): U32 => 0x100
