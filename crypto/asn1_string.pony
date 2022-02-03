use @ASN1_TIME_to_tm[I32](asn1str: Pointer[ASN1String] tag, tm: Tm)
use @ASN1_STRING_get0_data[Pointer[U8] ref](asn1s: Pointer[ASN1String] tag)
use @ASN1_STRING_length[I32](asn1s: Pointer[ASN1String] tag)
use @ASN1_STRING_type[I32](asn1s: Pointer[ASN1String] tag)

primitive ASN1String
  fun array(asn1str: Pointer[ASN1String] tag): Array[U8] val ? =>
    if (asn1str.is_null()) then error end
    recover val
      let len: I32 = @ASN1_STRING_length(asn1str)
      let osslptr: Pointer[U8] ref = @ASN1_STRING_get0_data(asn1str)

      (Array[U8].from_cpointer(osslptr, len.usize())).clone()
    end

  fun time_to_posix(asn1str: Pointer[ASN1String] tag): I64 =>
    let tm: Tm = Tm
    @ASN1_TIME_to_tm(asn1str, tm)
    tm.mktime()

