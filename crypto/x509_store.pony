use "files"
use "lib:crypto"
use "stack_x509_object"
//use "StackX509Extension"

use @printf[I32](fmt: Pointer[U8] tag, ...)
use @X509_STORE_new[Pointer[X509Store] tag]()
use @X509_STORE_set_default_paths[I32](ctx: Pointer[X509Store] tag)
use @X509_STORE_get0_objects[Pointer[StackX509Object] tag](v: Pointer[X509Store] tag)

class X509Store
  """
  This class represents a store of X509 "stuff".  Its default configuration
  is empty.
  """
  var _store: Pointer[X509Store] tag
  var certs: Array[X509] val = recover val Array[X509] end
  new create() =>
    _store = @X509_STORE_new()

  fun ref load_system_store(auth: FileAuth) ? =>
    """
    Use this method to populate the store with certificates from the host's
    default store.

    An X509 class instance is created for every certificate in the store
    for your edification.

    See field certs
    """
    if(@X509_STORE_set_default_paths(_store) != 1) then error end
    var stack: Pointer[StackX509Object] tag = @X509_STORE_get0_objects(_store)
    var cnt: USize = StackX509Object.size(stack)

    certs = recover val
      let c: Array[X509] = Array[X509]
      while (cnt > 0) do
        let s: Pointer[X509Object] tag = StackX509Object.pop(stack)
        c.push(X509.from_x509object(s))
        cnt = cnt - 1
      end
      c
    end

  fun count(): USize =>
    certs.size()




