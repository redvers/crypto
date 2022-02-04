use @i2a_ASN1_OBJECT[I32](bp: Pointer[_BIO] tag, obj: Pointer[ASN1Object] tag)
use @OBJ_nid2ln[Pointer[U8] ref](n: I32)
use @OBJ_nid2sn[Pointer[U8] ref](n: I32)

class ASN1Object
  """
  Wrapper for the Asn1objectst
  """
  let _obj: Pointer[ASN1Object] tag
  let _nid: I32

  new val create_from_ref(obj: Pointer[ASN1Object] tag) =>
  """
  Constructor that takes an existing ASN1Object pointer,
  typically for analysis so is val.
  """
    _obj = obj
    _nid = @OBJ_obj2nid(_obj)

  fun ln(): String val =>
    """
    Returns the "longName" for the specified ASN1Object.
    """
    String.from_cstring(@OBJ_nid2ln(_nid)).clone()

  fun sn(): String val =>
    """
    Returns the "shortName" for the specified ASN1Object.
    """
    String.from_cstring(@OBJ_nid2sn(_nid)).clone()

  fun i2a(): String val =>
    """
    FIXME
    Currently returns to longName, it will return a textual representation of
    the OID. (They're set in the openssl header files as constants not as
    something that can be (currently) obtained via the C API
    """
    let bio: _BIO = _BIO
    let i32: I32 = @i2a_ASN1_OBJECT(bio.apply(), _obj)
    bio.string()
