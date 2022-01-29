use "path:/usr/local/opt/libressl/lib" if osx
use "lib:crypto"
use "debug"
use "format"
use "collections"

use @printf[I32](fmt: Pointer[U8] tag, ...)
use @BIO_s_mem[Pointer[U8]]()
use @BIO_new[Pointer[_BIO] tag](typ: Pointer[U8])
use @BIO_write[I32](bio: Pointer[_BIO] tag, buf: Pointer[U8] tag, len: I32)
use @BIO_free_all[None](bio: Pointer[_BIO] tag)
use @PEM_read_bio_X509[Pointer[_X509Certificate] tag](bp: Pointer[_BIO] tag, fp: Pointer[None], cb: Pointer[None], u: Pointer[None])
use @X509_free[None](a: Pointer[_X509Certificate] tag)
use @sk_GENERAL_NAME_num[I32](stack: Pointer[_GeneralNameStack] tag)
use @OPENSSL_sk_num[I32](stack: Pointer[_GeneralNameStack] tag)
use @OPENSSL_sk_pop[Pointer[_GeneralName] tag](stack: Pointer[_GeneralNameStack] tag)
//use @X509_get0_extensions[Pointer[_ExtensionsStack] tag](cert: Pointer[_X509Certificate] tag)
//use @X509_EXTENSION_get_object[Pointer[_ASN1Object] tag](ex: Pointer[_X509Extension] tag)
//use @X509_EXTENSION_get_critical[I32](ex: Pointer[_X509Extension] tag)
//use @X509_EXTENSION_get_data[Pointer[_ASN1String] ref](ex: Pointer[_X509Extension] tag)
//use @OBJ_obj2nid[I32](obj: Pointer[_ASN1Object] tag)
//use @OBJ_nid2ln[Pointer[U8] ref](nid: I32)
//use @OBJ_nid2sn[Pointer[U8] ref](nid: I32)
//use @OBJ_obj2txt[I32](buf: Pointer[U8] tag, buf_len: I32, a: Pointer[_ASN1Object] tag, no_name: I32)

//use @ASN1_INTEGER_get_int64[I32](int64ptr: Pointer[I64] tag, asn1int: Pointer[_ASN1Integer] tag)

use @ASN1_STRING_length[I32](asn1str: Pointer[_ASN1String] tag)
use @ASN1_STRING_get0_data[Pointer[U8] ref](asn1str: Pointer[_ASN1String] tag)

use @X509_get_extension_flags[U32](cert: Pointer[_X509Certificate] tag)
use @X509_get_key_usage[U32](cert: Pointer[_X509Certificate] tag)
use @X509_get_extended_key_usage[U32](cert: Pointer[_X509Certificate] tag)

use @X509_get_pathlen[I64](cert: Pointer[_X509Certificate] tag)
use @X509_get_proxy_pathlen[I64](cert: Pointer[_X509Certificate] tag)
use @X509_get0_subject_key_id[Pointer[_ASN1String] ref](cert: Pointer[_X509Certificate] tag)
use @X509_get0_authority_key_id[Pointer[_ASN1String] ref](cert: Pointer[_X509Certificate] tag)
//use @X509_get0_authority_issuer[Pointer[_GeneralNameStack] ref](cert: Pointer[_X509Certificate] tag)
use @X509_get0_serialNumber[Pointer[_ASN1Integer] ref](cert: Pointer[_X509Certificate] tag)
use @GENERAL_NAME_get0_value[None](name: Pointer[_GeneralName] tag, vtype: Pointer[I32])

use @ASN1_INTEGER_to_BN[Pointer[_BigNum] tag](asn1int: Pointer[_ASN1Integer] tag, bn: Pointer[_BigNum] tag)
use @BN_bn2dec[Pointer[U8] ref](bn: Pointer[_BigNum] tag)
use @BN_bn2hex[Pointer[U8] ref](bn: Pointer[_BigNum] tag)

use @free[None](cptr: Pointer[None])

primitive _BIO
primitive _X509Certificate
primitive _ExtensionsStack
primitive _X509Extension
primitive _ASN1Object
primitive _ASN1String
primitive _ASN1Integer
primitive _GeneralName
primitive _GeneralNameStack
primitive _BigNum

class X509Certificate
  let _cert: Pointer[_X509Certificate] tag
  var ext_flags: X509ExtensionFlags val
  var ku_flags:  X509KeyUsageFlags val
  var xku_flags: X509ExtendedKeyUsageFlags val

  new create(pem: String) ? =>
    let pembio: Pointer[_BIO] tag = @BIO_new(@BIO_s_mem())
    let readdata: I32 = @BIO_write(pembio, pem.cstring(), pem.size().i32())
    if (readdata != pem.size().i32()) then error end

    _cert = @PEM_read_bio_X509(pembio, Pointer[None], Pointer[None], Pointer[None])
    if (_cert.is_null()) then error end

    ext_flags = X509ExtensionFlags(@X509_get_extension_flags(_cert))
    ku_flags = X509KeyUsageFlags(@X509_get_key_usage(_cert))
    xku_flags = X509ExtendedKeyUsageFlags(@X509_get_extended_key_usage(_cert))

  fun ex_is_obsolete_v1():           Bool => ext_flags(ExtV1)
  fun ex_is_certificate_authority(): Bool => ext_flags(ExtCA)
  fun ex_is_proxy():                 Bool => ext_flags(ExtProxy)
  fun ex_is_self_issued():           Bool => ext_flags(ExtSI)
  fun ex_is_invalid():               Bool => ext_flags(ExtInvalid)
  fun ex_is_precomputed():           Bool => ext_flags(ExtSet)
  fun ex_is_critical():              Bool => ext_flags(ExtCritical)
  fun ex_has_basic_constraints():    Bool => ext_flags(ExtBCons)
  fun ex_has_subject_issuer_match(): Bool => ext_flags(ExtSS)
  fun ex_has_no_fingerprint():       Bool => ext_flags(ExtNoFingerprint)
  fun ex_has_extended_key_usage():   Bool => ext_flags(ExtXKUsage)
  fun ex_is_netscape_cert():         Bool => ext_flags(ExtNSCert)

  fun ku_digital_signature(): Bool => ku_flags(DigitalSignature)
  fun ku_non_repudiation(): Bool => ku_flags(NonRepudiation)
  fun ku_key_encipherment(): Bool => ku_flags(KeyEncipherment)
  fun ku_data_encipherment(): Bool => ku_flags(DataEncipherment)
  fun ku_key_agreement(): Bool => ku_flags(KeyAgreement)
  fun ku_cert_signing(): Bool => ku_flags(KeyCertSign)
  fun ku_crl_sign(): Bool => ku_flags(CRLSign)
  fun ku_encipher_only(): Bool => ku_flags(EncipherOnly)
  fun ku_decipher_only(): Bool => ku_flags(DecipherOnly)

  fun xku_ssl_server(): Bool => xku_flags(XKUSSLServer)
  fun xku_ssl_client(): Bool => xku_flags(XKUSSLClient)
  fun xku_smime(): Bool => xku_flags(XKUSMIME)
  fun xku_code_sign(): Bool => xku_flags(XKUCodeSign)
  fun xku_sgc(): Bool => xku_flags(XKUSGC)
  fun xku_ocsp_sign(): Bool => xku_flags(XKUOCSPSign)
  fun xku_timestamp(): Bool => xku_flags(XKUTimestamp)
  fun xku_dvcs(): Bool => xku_flags(XKUDVCS)
  fun xku_any_eku(): Bool => xku_flags(XKUANYEKU)

  fun get_pathlen(): I64 => @X509_get_pathlen(_cert)
  fun get_proxy_pathlen(): I64 => @X509_get_proxy_pathlen(_cert)

  fun subject_key_id_raw(): Array[U8] val ? => _asn1string_copy_to_array(@X509_get0_subject_key_id(_cert))?
  fun subject_key_id_string(): String val ? => _format_colon_hex(subject_key_id_raw()?)?

  fun authority_key_id_raw(): Array[U8] val ? => _asn1string_copy_to_array(@X509_get0_authority_key_id(_cert))?
  fun authority_key_id_string(): String val ? => _format_colon_hex(authority_key_id_raw()?)?

  fun serial_number_hex(): String val ? =>
    recover val
      let cptr: Pointer[U8] ref = @BN_bn2hex(_serial_number()?)
      let str: String val = String.from_cstring(cptr).clone()
      @free(cptr)
      str
    end

  fun serial_number_dec(): String val ? =>
    recover val
      let cptr: Pointer[U8] ref = @BN_bn2dec(_serial_number()?)
      let str: String val = String.from_cstring(cptr).clone()
      @free(cptr)
      str
    end

  fun _serial_number(): Pointer[_BigNum] tag ? =>
    let asn1int: Pointer[_ASN1Integer] tag = @X509_get0_serialNumber(_cert)
    if (asn1int.is_null()) then error end
    let bignum: Pointer[_BigNum] tag = @ASN1_INTEGER_to_BN(asn1int, Pointer[_BigNum])
    if (asn1int.is_null()) then error end
    bignum

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

  fun _asn1string_copy_to_array(asn1str: Pointer[_ASN1String] tag): Array[U8] val ? =>
    if (asn1str.is_null()) then
      error
    else
      recover val
        let len: USize = @ASN1_STRING_length(asn1str).usize()
        let osslptr: Pointer[U8] ref = @ASN1_STRING_get0_data(asn1str)

        (Array[U8].from_cpointer(osslptr, len)).clone()
      end
    end





























































/*
  fun _general_name_stack_to_array(stack: Pointer[_GeneralNameStack] tag) ? =>
    let count: I32 = @sk_GENERAL_NAME_num(stack)

    @printf("sizeof stack: %d\n".cstring(), count)

    var cnt: I32 = count
    while (cnt > 0) do
      _pop_general_name_stack(stack)?
      cnt = cnt - 1
    end

//use @OPENSSL_sk_pop[Pointer[_GeneralName] tag](stack: Pointer[_GeneralNameStack] tag)
  fun _pop_general_name_stack(stack: Pointer[_GeneralNameStack] tag) ? =>
    if (stack.is_null()) then error end
    let gn: Pointer[_GeneralName] tag = @OPENSSL_sk_pop(stack)
    if (gn.is_null()) then error end

    var gtype: I32 = 0

//    @GENERAL_NAME_get0_value(gn, addressof gtype)


*/

/*

    _extensions()? // Make this return an empty DS instead of error at the end

  fun ref _extensions() ? =>
    let stack: Pointer[_ExtensionsStack] tag = @X509_get0_extensions(_cert)
    let count: I32 = @OPENSSL_sk_num(stack)
    if (stack.is_null()) then @printf("in null yo\n".cstring()) end
    @printf("Extension Count: %d\n".cstring(), count)
    _ext_cnt = count.usize()

    var cnt: I32 = count
    while (cnt > 0) do
      _ponify_extension(stack)?
      cnt = cnt - 1
    end

  fun _ponify_extension(stack: Pointer[_ExtensionsStack] tag) ? =>
      let x509ext: Pointer[_X509Extension] tag = @OPENSSL_sk_pop(stack)
      let critical: Bool = _get_critical(x509ext)

      let asn1obj: Pointer[_ASN1Object] tag = @X509_EXTENSION_get_object(x509ext)
      let nid: I32 = @OBJ_obj2nid(asn1obj)
      let ln: String val = _obj_nid2ln(nid)?
      let sn: String val = _obj_nid2sn(nid)?

      let oid: String val = _obj2txt(asn1obj)
      Debug.out(oid + ": " + sn + "     →      " + sn)

//      let data: Array[U8] val = _extension_get_data(x509ext)

  fun _obj2txt(asn1obj: Pointer[_ASN1Object] tag): String =>
    let strlen: I32 = @OBJ_obj2txt(Pointer[U8], 0, asn1obj, I32(1))
    let oid: Array[U8] val = recover val Array[U8].init(0, strlen.usize()) end
    let writln: I32 = @OBJ_obj2txt(oid.cpointer(), strlen+1, asn1obj, I32(1))

    let str: String = String.from_array(oid)
    str

*/
/*
  fun _extension_get_data(ex: Pointer[_X509Extension] tag): Array[U8] val =>
    let asn1str: Pointer[_ASN1String] tag = @X509_EXTENSION_get_data(ex)
    if (asn1str.is_null()) then
      recover val Array[U8] end
    else
      recover val
        let len: USize = @ASN1_STRING_length(asn1str).usize()
        let osslptr: Pointer[U8] ref = @ASN1_STRING_get0_data(asn1str)

        (Array[U8].from_cpointer(osslptr, len)).clone()
      end
    end
*/


/*
  fun _obj_nid2sn(nid: I32): String val ? =>
    if (nid == 0) then error end
    let cptr: Pointer[U8] ref = @OBJ_nid2sn(nid)
    if (cptr.is_null()) then error end
    String.from_cstring(cptr).clone()

  fun _obj_nid2ln(nid: I32): String val ? =>
    if (nid == 0) then error end
    let cptr: Pointer[U8] ref = @OBJ_nid2ln(nid)
    if (cptr.is_null()) then error end
    String.from_cstring(cptr).clone()

  fun _get_critical(ex: Pointer[_X509Extension] tag): Bool =>
    (@X509_EXTENSION_get_critical(ex) == I32(1))

*/

/*X509_EXTENSION_get_object() returns the extension type of ex as an ASN1_OBJECT pointer. The returned pointer is an internal value which must not be freed up.
 *
 * X509_EXTENSION_get_critical() returns the criticality of extension ex it returns 1 for critical and 0 for non-critical.
 *
 * X509_EXTENSION_get_data() returns the data of extension ex. The returned pointer is an internal value which must not be freed up.
 */






  fun _final() =>
    @X509_free(_cert)





/*

-text Prints out the certificate in text form. Full details are output including the public key, signature algorithms, issuer and subject names, serial number any extensions present and any trust settings.
-ext extensions

    Prints out the certificate extensions in text form. Extensions are specified with a comma separated string, e.g., "subjectAltName,subjectKeyIdentifier". See the x509v3_config(5) manual page for the extension names.
-certopt option

-pubkey Outputs the certificate's SubjectPublicKeyInfo block in PEM format.
-modulus This option prints out the value of the modulus of the public key contained in the certificate.
-serial Outputs the certificate serial number.
-subject_hash Outputs the "hash" of the certificate subject name. This is used in OpenSSL to form an index to allow certificates in a directory to be looked up by subject name.
-issuer_hash Outputs the "hash" of the certificate issuer name.
-ocspid Outputs the OCSP hash values for the subject name and public key.
-hash Synonym for "-subject_hash" for backward compatibility reasons.
-subject_hash_old Outputs the "hash" of the certificate subject name using the older algorithm as used by OpenSSL before version 1.0.0.
-issuer_hash_old Outputs the "hash" of the certificate issuer name using the older algorithm as used by OpenSSL before version 1.0.0.
-subject Outputs the subject name.
-issuer Outputs the issuer name.
-nameopt option Option which determines how the subject or issuer names are displayed. The option argument can be a single option or multiple options separated by commas. Alternatively the -nameopt switch may be used more than once to set multiple options. See the NAME OPTIONS section for more information.
-email Outputs the email address(es) if any.
-ocsp_uri Outputs the OCSP responder address(es) if any.
-startdate Prints out the start date of the certificate, that is the notBefore date.
-enddate Prints out the expiry date of the certificate, that is the notAfter date.
-dates Prints out the start and expiry dates of a certificate.
-checkend arg Checks if the certificate expires within the next arg seconds and exits nonzero if yes it will expire or zero if not.
-fingerprint Calculates and outputs the digest of the DER encoded version of the entire certificate (see digest options).


compat

    Use the old format.
RFC2253

    Displays names compatible with RFC2253 equivalent to esc_2253, esc_ctrl, esc_msb, utf8, dump_nostr, dump_unknown, dump_der, sep_comma_plus, dn_rev and sname.
oneline

    A oneline format which is more readable than RFC2253. It is equivalent to specifying the esc_2253, esc_ctrl, esc_msb, utf8, dump_nostr, dump_der, use_quote, sep_comma_plus_space, space_eq and sname options. This is the default of no name options are given explicitly.
multiline

    A multiline format. It is equivalent esc_ctrl, esc_msb, sep_multiline, space_eq, lname and align.
esc_2253

    Escape the "special" characters required by RFC2253 in a field. That is ,+"<>;. Additionally # is escaped at the beginning of a string and a space character at the beginning or end of a string.
esc_2254

    Escape the "special" characters required by RFC2254 in a field. That is the NUL character as well as and ()*.
esc_ctrl

    Escape control characters. That is those with ASCII values less than 0x20 (space) and the delete (0x7f) character. They are escaped using the RFC2253 \XX notation (where XX are two hex digits representing the character value).
esc_msb

dump_der

dump_all

    Dump all fields. This option when used with dump_der allows the DER encoding of the structure to be unambiguously determined.
dump_unknown

    Dump any field whose OID is not recognised by OpenSSL.
sep_comma_plus, sep_comma_plus_space, sep_semi_plus_space, sep_multiline

    These options determine the field separators. The first character is between RDNs and the second between multiple AVAs (multiple AVAs are very rare and their use is discouraged). The options ending in "space" additionally place a space after the separator to make it more readable. The sep_multiline uses a linefeed character for the RDN separator and a spaced + for the AVA separator. It also indents the fields by four characters. If no field separator is specified then sep_comma_plus_space is used by default.
dn_rev

    Reverse the fields of the DN. This is required by RFC2253. As a side effect this also reverses the order of multiple AVAs but this is permissible.
nofname, sname, lname, oid

    These options alter how the field name is displayed. nofname does not display the field at all. sname uses the "short name" form (CN for commonName for example). lname uses the long form. oid represents the OID in numerical form and is useful for diagnostic purpose.
align

    Align field values for a more readable output. Only usable with sep_multiline.
space_eq

    Places spaces round the = character which follows the field name.

Text Options

As well as customising the name output format, it is also possible to customise the actual fields printed using the certopt options when the text option is present. The default behaviour is to print all fields.

compatible

    Use the old format. This is equivalent to specifying no output options at all.
no_header

    Don't print header information: that is the lines saying "Certificate" and "Data".
no_version

    Don't print out the version number.
no_serial

    Don't print out the serial number.
no_signame

    Don't print out the signature algorithm used.
no_validity

    Don't print the validity, that is the notBefore and notAfter fields.
no_subject

    Don't print out the subject name.
no_issuer

    Don't print out the issuer name.
no_pubkey

    Don't print out the public key.
no_sigdump

    Don't give a hexadecimal dump of the certificate signature.
no_aux

    Don't print out certificate trust information.
no_extensions

    Don't print out any X509V3 extensions.
ext_default

    Retain default extension behaviour: attempt to print out unsupported certificate extensions.
ext_error

    Print an error message for unsupported certificate extensions.
ext_parse

    ASN1 parse unsupported extensions.
ext_dump

    Hex dump unsupported extensions.
ca_default

    The value used by the ca utility, equivalent to no_issuer, no_pubkey, no_header, and no_version.



    -purpose

    */
