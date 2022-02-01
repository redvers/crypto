use "files"
use "lib:crypto"
use "stack_x509_object"
//use "StackX509Extension"

use @X509_STORE_new[Pointer[X509StoreType]]()
use @X509_STORE_set_default_paths[I32](ctx: Pointer[X509StoreType])
//use @X509_STORE_get0_objects[StackX509Object](v: X509Store tag)

class X509Store
  """
  This class represents a store of X509 "stuff".  Its default configuration
  is to give you access to the system X509 store.
  """
  var _store: Pointer[X509StoreType]
  var _stack: (StackX509Object|None) = None
  new create() =>
    _store = @X509_STORE_new()

  fun ref load_system_store(auth: FileAuth) ? =>
    if(@X509_STORE_set_default_paths(_store) != 1) then error end
    _stack = StackX509Object.create_from_store(_store)





primitive X509StoreType
