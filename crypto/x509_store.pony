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
  is empty.  It exposes the contents of the Store via the certs field.

  FIXME: This can also contain CRLs but it's not implemented yet
  Instead of exposing this, should I add an iterator like for
  StackX509Extension?
  """
  var _store: Pointer[X509Store] tag
  var certs: Array[X509 val] val = recover val Array[X509 val] end
  new create() =>
    _store = @X509_STORE_new()

  new val from_system_store(auth: FileAuth) ? =>
    """
    Use this constructor to populate the store with certificates from the host's
    default store.

    An X509 class instance is created for every certificate in the store
    for your edification.

    See field certs
    """
    _store = @X509_STORE_new()
    if(@X509_STORE_set_default_paths(_store) != 1) then error end
    var stack: Pointer[StackX509Object] tag = @X509_STORE_get0_objects(_store)
    var cnt: USize = StackX509Object.size(stack)

    certs = recover val
      let c: Array[X509 val] = Array[X509 val]
      while (cnt > 0) do
        let s: Pointer[X509Object] tag = StackX509Object.pop(stack)
        c.push(X509.from_x509object(s))
        cnt = cnt - 1
      end
      c
    end

  fun count(): USize =>
    """
    Returns a count of the number of Certificates in the Store
    """
    certs.size()




