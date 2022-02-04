use @OBJ_nid2ln[Pointer[U8] ref](n: I32)
use @OBJ_nid2sn[Pointer[U8] ref](n: I32)

primitive ASN1Object
  fun ln(nid: I32): String val =>
    String.from_cstring(@OBJ_nid2ln(nid)).clone()

  fun sn(nid: I32): String val =>
    String.from_cstring(@OBJ_nid2sn(nid)).clone()

