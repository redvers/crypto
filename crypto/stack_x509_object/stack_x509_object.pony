use "lib:crypto"
use ".."

use @OPENSSL_sk_pop[Pointer[X509Object] tag](sk: Pointer[StackX509Object] tag)
use @OPENSSL_sk_num[I32](sk: Pointer[StackX509Object] tag)
//use @X509_STORE_get0_objects[Pointer[StackX509ObjectType]](v: Pointer[X509StoreType] tag)

primitive StackX509Object
  """
  Wraps functionality for the X509Object stack.
  I expect this will result in having a similar interface to
  StackX509Extension very shortly.
  """

  fun pop(stack: Pointer[StackX509Object] tag): Pointer[X509Object] tag =>
      @OPENSSL_sk_pop(stack)

  fun size(stack: Pointer[StackX509Object] tag): USize =>
      @OPENSSL_sk_num(stack).usize()

