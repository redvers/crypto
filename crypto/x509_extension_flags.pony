use "collections"

type X509ExtensionFlags is Flags[(ExtBCons|ExtKUsage|ExtXKUsage|ExtNSCert|ExtCA|ExtSI|ExtV1|ExtInvalid|ExtSet|ExtCritical|ExtProxy|ExtInvalidPolicy|ExtFreshest|ExtSS|ExtNoFingerprint), U32]

primitive ExtBCons         is Flag[U32] fun value(): U32 => 0x1
primitive ExtKUsage        is Flag[U32] fun value(): U32 => 0x2
primitive ExtXKUsage       is Flag[U32] fun value(): U32 => 0x4
primitive ExtNSCert        is Flag[U32] fun value(): U32 => 0x8
primitive ExtCA            is Flag[U32] fun value(): U32 => 0x10
primitive ExtSI            is Flag[U32] fun value(): U32 => 0x20
primitive ExtV1            is Flag[U32] fun value(): U32 => 0x40
primitive ExtInvalid       is Flag[U32] fun value(): U32 => 0x80
primitive ExtSet           is Flag[U32] fun value(): U32 => 0x100
primitive ExtCritical      is Flag[U32] fun value(): U32 => 0x200
primitive ExtProxy         is Flag[U32] fun value(): U32 => 0x400
primitive ExtInvalidPolicy is Flag[U32] fun value(): U32 => 0x800
primitive ExtFreshest      is Flag[U32] fun value(): U32 => 0x1000
primitive ExtSS            is Flag[U32] fun value(): U32 => 0x2000
primitive ExtNoFingerprint is Flag[U32] fun value(): U32 => 0x100000
