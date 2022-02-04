use @OBJ_obj2nid[I32](o: Pointer[ASN1Object] tag)
use @X509_EXTENSION_get_critical[I32](ex: Pointer[X509Extension] tag)
use @X509_EXTENSION_get_object[Pointer[ASN1Object] tag](ex: Pointer[X509Extension] tag)
use @X509V3_EXT_print[I32](out: Pointer[_BIO] tag, ext: Pointer[X509Extension] tag, flag: U64, indent: I32)

class X509Extension
  """
  Class that represents an SSL Extension
  """
  let _ext: Pointer[X509Extension] tag
  let _obj: ASN1Object val
  new create_from_ptr(extptr: Pointer[X509Extension] tag) =>
    """
    Constructor takes a pointer reference from the calling object
    """
    _ext = extptr
    _obj = ASN1Object.create_from_ref(@X509_EXTENSION_get_object(extptr))

  fun is_critical(): Bool =>
    """
    Returns true if the extension is deemed critical
    """
    if (@X509_EXTENSION_get_critical(_ext) == 1) then true else false end

  fun ln(): String val =>
    """
    Returns the longName representation of the Extension.
    """
    _obj.ln()

  fun sn(): String val =>
    """
    Returns the shortName representation of the Extension.
    """
    _obj.sn()

  fun i2a(): String val =>
    """
    FIXME
    Currently returns the longName representation, will in the future return
    the OID. (Currently in #defines in openssl, not accessable to FFI)
    """
    _obj.i2a()

  fun print(): String val ? =>
    """
    Returns a human readable text formatted description of the extension and
    its contents.
    """
    let bio: _BIO = _BIO
    if (@X509V3_EXT_print(bio.apply(), _ext, 0, 0) != 1) then error end
    bio.string()
