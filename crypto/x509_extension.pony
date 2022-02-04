use @OBJ_obj2nid[I32](o: Pointer[ASN1Object] tag)
use @X509_EXTENSION_get_critical[I32](ex: Pointer[X509Extension] tag)
use @X509_EXTENSION_get_object[Pointer[ASN1Object] tag](ex: Pointer[X509Extension] tag)
use @X509V3_EXT_print[I32](out: Pointer[_BIO] tag, ext: Pointer[X509Extension] tag, flag: U64, indent: I32)

class X509Extension
  let _ext: Pointer[X509Extension] tag
  let _nid: I32
  new create_from_ptr(extptr: Pointer[X509Extension] tag) =>
    _ext = extptr
    _nid = @OBJ_obj2nid(@X509_EXTENSION_get_object(extptr))

  fun is_critical(): Bool =>
    if (@X509_EXTENSION_get_critical(_ext) == 1) then true else false end

  fun ln(): String val =>
    ASN1Object.ln(_nid)

  fun sn(): String val =>
    ASN1Object.sn(_nid)

  fun print(): String val ? =>
    let bio: _BIO = _BIO
    if (@X509V3_EXT_print(bio.apply(), _ext, 0, 0) != 1) then error end
    bio.string()
