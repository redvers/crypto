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
use @PEM_read_bio_X509[Pointer[X509] tag](bio: Pointer[_BIO] tag, x509: Pointer[X509] tag, cb: Pointer[None], u: Pointer[None])

use @X509_print[I32](bp: Pointer[_BIO] tag, x: Pointer[X509] tag)
use @X509_OBJECT_get0_X509[Pointer[X509] tag](a: Pointer[X509Object] tag)

class X509
  """
  An X509 Classical Certificate with all that entails™
  """
  var _cert: Pointer[X509] tag

  new from_x509object(obj: Pointer[X509Object] tag) =>
    """
    A constructor which creates the object from an X509Object pointer.
    This is used when retrieving a certificate from a Certificate Store
    (X509Store)
    """
    _cert = @X509_OBJECT_get0_X509(obj)

  new from_pem(data: (Array[U8] val | String val)) ? =>
    """
    A constructor that takes a certificate as PEM data.
    """
    let bio: _BIO = _BIO
    if (not bio.write(data)) then error end
    _cert = @PEM_read_bio_X509(bio.apply(), Pointer[X509], Pointer[None], Pointer[None])
    if (_cert.is_null()) then error end


  fun issuer_name(): String val ? =>
    """
    Returns the issuer's CN.
    """
    _X509Name.string(@X509_get_issuer_name(_cert))?

  fun subject_name(): String val ? =>
    """
    Returns the certificate's CN.
    """
    _X509Name.string(@X509_get_subject_name(_cert))?

	fun not_before_posix(): I64 =>
    """
    Returns the notBefore time for the certificate in UNIX epoch form.
    """
		let notb4: Pointer[ASN1String] tag = @X509_get0_notBefore(_cert)
		ASN1String.time_to_posix(notb4)

	fun not_after_posix(): I64 =>
    """
    Returns the notAfter time for the certificate in UNIX epoch form.
    """
		let notb4: Pointer[ASN1String] tag = @X509_get0_notAfter(_cert)
		ASN1String.time_to_posix(notb4)

  fun get_extensions(): StackX509Extension =>
    """
    Returns an object that represents a collection of Extensions.
    """
    StackX509Extension.create_from_x509(_cert)



  fun print(): String val ? =>
    """
    Returns a textual representation of the certificate in a form which
    is identical to openssl x509 -text.
    """
    let bio: _BIO = _BIO
    if (@X509_print(bio.apply(), _cert) != 1) then error end
    bio.string()

  fun authority_key_id(): String val ? =>
    """
    Returns the Key ID of the Issuing CA Certificate as a string.
    """
    _format_colon_hex(authority_key_id_raw()?)?

  fun authority_key_id_raw(): Array[U8] val ? =>
    """
    Returns the Key ID of the Issuing CA Certificate in its binary form.
    """
    let asn1s: Pointer[ASN1String] tag = @X509_get0_authority_key_id(_cert)
    ASN1String.array(asn1s)?

  fun key_id(): String val ? =>
    """
    Returns the Key ID of the Certificate as a String.
    """
    _format_colon_hex(key_id_raw()?)?

  fun key_id_raw(): Array[U8] val ? =>
    """
    Returns the Key ID of the Certificate in its binary form.
    """
    let asn1s: Pointer[ASN1String] tag = @X509_get0_subject_key_id(_cert)
    ASN1String.array(asn1s)?

  fun serial(): String val ? =>
    """
    Returns the Serial Number of the Certificate in its binary form.
    """
    _format_hex(serial_raw()?)?

  fun serial_raw(): Array[U8] val ? =>
    """
    Returns the Serial Number in its binary form.
    """
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


