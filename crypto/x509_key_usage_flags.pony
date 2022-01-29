use "collections"

type X509KeyUsageFlags is Flags[(DigitalSignature|NonRepudiation|KeyEncipherment|DataEncipherment|KeyAgreement|KeyCertSign|CRLSign|EncipherOnly|DecipherOnly), U32]

primitive DigitalSignature is Flag[U32] fun value(): U32 => 0x0080
primitive NonRepudiation   is Flag[U32] fun value(): U32 => 0x0040
primitive KeyEncipherment  is Flag[U32] fun value(): U32 => 0x0020
primitive DataEncipherment is Flag[U32] fun value(): U32 => 0x0010
primitive KeyAgreement     is Flag[U32] fun value(): U32 => 0x0008
primitive KeyCertSign      is Flag[U32] fun value(): U32 => 0x0004
primitive CRLSign          is Flag[U32] fun value(): U32 => 0x0002
primitive EncipherOnly     is Flag[U32] fun value(): U32 => 0x0001
primitive DecipherOnly     is Flag[U32] fun value(): U32 => 0x8000



