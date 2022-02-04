use "format"
use "stack_x509_extension"
//use @X509_check_ca[I32](x: X509 tag)
//use @X509_check_email[I32](x: X509 tag, chk: Pointer[U8] tag, chklen: U64, flags: U32)
//use @X509_check_host[I32](x: X509 tag, chk: Pointer[U8] tag, chklen: U64, flags: U32, peername: Pointer[Pointer[U8]] tag)
//use @X509_check_ip[I32](x: X509 tag, chk: Pointer[U8] tag, chklen: U64, flags: U32)
//use @X509_check_ip_asc[I32](x: X509 tag, ipasc: Pointer[U8] tag, flags: U32)
//use @X509_CRL_get0_extensions[StackX509Extension](crl: X509CRL tag)
//use @X509_digest[I32](data: X509 tag, otype: EVPMD tag, md: Pointer[U8] tag, len: Pointer[U32] tag)
use @X509_get0_authority_key_id[Pointer[ASN1String] tag](x: Pointer[X509] tag)
//use @X509_get0_extensions[StackX509Extension](x: X509 tag)
use @X509_get0_notAfter[Pointer[ASN1String] tag](x: Pointer[X509] tag)
use @X509_get0_notBefore[Pointer[ASN1String] tag](x: Pointer[X509] tag)
use @X509_get0_serialNumber[Pointer[ASN1String] tag](x: Pointer[X509] tag)
use @X509_get0_subject_key_id[Pointer[ASN1String] tag](x: Pointer[X509] tag)
use @X509_get_issuer_name[Pointer[_X509Name] tag](a: Pointer[X509] tag)
use @X509_get_subject_name[Pointer[_X509Name] tag](a: Pointer[X509] tag)
//use @X509_issuer_name_hash[U64](a: X509 tag)
//use @X509_NAME_oneline[Pointer[U8]](a: X509Name tag, buf: Pointer[U8] tag, size: I32)
//use @X509_subject_name_hash[U64](x: X509 tag)

use @X509_print[I32](bp: Pointer[_BIO] tag, x: Pointer[X509] tag)
use @X509_OBJECT_get0_X509[Pointer[X509] tag](a: Pointer[X509Object] tag)

class X509
  """
  A Classical Cert™
  """
  var _cert: Pointer[X509] tag

  new from_x509object(obj: Pointer[X509Object] tag) =>
    _cert = @X509_OBJECT_get0_X509(obj)

  fun issuer_name(): String val ? =>
    _X509Name.string(@X509_get_issuer_name(_cert))?

  fun subject_name(): String val ? =>
    _X509Name.string(@X509_get_subject_name(_cert))?

	fun not_before_posix(): I64 =>
		let notb4: Pointer[ASN1String] tag = @X509_get0_notBefore(_cert)
		ASN1String.time_to_posix(notb4)

	fun not_after_posix(): I64 =>
		let notb4: Pointer[ASN1String] tag = @X509_get0_notAfter(_cert)
		ASN1String.time_to_posix(notb4)

  fun get_extensions(): StackX509Extension =>
    StackX509Extension.create_from_x509(_cert)



  fun print(): String val ? =>
    let bio: _BIO = _BIO
    if (@X509_print(bio.apply(), _cert) != 1) then error end
    bio.string()

  fun authority_key_id(): String val ? =>
    _format_colon_hex(key_id_raw()?)?
  fun authority_key_id_raw(): Array[U8] val ? =>
    let asn1s: Pointer[ASN1String] tag = @X509_get0_authority_key_id(_cert)
    ASN1String.array(asn1s)?

  fun key_id(): String val ? =>
    _format_colon_hex(key_id_raw()?)?
  fun key_id_raw(): Array[U8] val ? =>
    let asn1s: Pointer[ASN1String] tag = @X509_get0_subject_key_id(_cert)
    ASN1String.array(asn1s)?

  fun serial(): String val ? =>
    _format_hex(serial_raw()?)?
  fun serial_raw(): Array[U8] val ? =>
    let asn1s: Pointer[ASN1String] tag = @X509_get0_serialNumber(_cert)
    ASN1String.array(asn1s)?

  fun _format_colon_hex(raw: Array[U8] val): String ? =>
    var string: String trn = recover trn String end
    var cnt: USize = 0
    while (cnt < raw.size()) do
      if (cnt > 0) then
        string.append(":")
      end
      string.append(Format.int[U8](raw(cnt)? where width = 2, fmt = FormatHexBare, prec = 2))
      cnt = cnt + 1
    end
    consume string

  fun _format_hex(raw: Array[U8] val): String ? =>
    var string: String trn = recover trn String end
    var cnt: USize = 0
    while (cnt < raw.size()) do
      string.append(Format.int[U8](raw(cnt)? where width = 2, fmt = FormatHexBare, prec = 2))
      cnt = cnt + 1
    end
    consume string


