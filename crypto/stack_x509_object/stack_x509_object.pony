use "lib:crypto"
use ".."

use @OPENSSL_sk_pop[Pointer[X509ObjectType]](sk: Pointer[StackX509ObjectType] tag)
use @OPENSSL_sk_num[I32](sk: Pointer[StackX509ObjectType] tag)
use @X509_STORE_get0_objects[Pointer[StackX509ObjectType]](v: Pointer[X509StoreType] tag)

class StackX509Object
  let _stack: Pointer[StackX509ObjectType]
  new create_from_store(store: Pointer[X509StoreType]) =>
    _stack = @X509_STORE_get0_objects(store)

//  fun pop(): _X509Object =>
//      @OPENSSL_sk_pop(_stack)
//
//  fun size(): I32 =>
//      @OPENSSL_sk_num(_stack)

primitive StackX509ObjectType
primitive X509ObjectType
