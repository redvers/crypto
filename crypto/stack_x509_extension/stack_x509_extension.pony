use "lib:crypto"
use ".."

use @OPENSSL_sk_value[Pointer[X509Extension] tag](sk: Pointer[StackX509Extension] tag, idx: I32)
use @sk_X509_EXTENSION_new_null[Pointer[StackX509Extension] tag]()
use @X509_get0_extensions[Pointer[StackX509Extension] tag](x509: Pointer[X509] tag)
use @OPENSSL_sk_pop[Pointer[X509Extension] tag](sk: Pointer[StackX509Extension] tag)
use @OPENSSL_sk_num[I32](sk: Pointer[StackX509Extension] tag)

class StackX509Extension
  let _stack: Pointer[StackX509Extension] tag
  new create() =>
    _stack = @sk_X509_EXTENSION_new_null()

  new create_from_x509(x509ptr: Pointer[X509] tag) =>
    _stack = @X509_get0_extensions(x509ptr)

  fun size(): USize =>
      @OPENSSL_sk_num(_stack).usize()

  fun values(): StackX509ExtensionIterator =>
    StackX509ExtensionIterator.create(_stack)


class StackX509ExtensionIterator is Iterator[X509Extension]
  let _stack: Pointer[StackX509Extension] tag
  var cnt: I32 = 0

  new create(stack: Pointer[StackX509Extension] tag) =>
    _stack = stack

  fun has_next(): Bool =>
    let c: I32 = @OPENSSL_sk_num(_stack)
    if (cnt < c) then true else false end

  fun ref next(): X509Extension =>
    let ext: Pointer[X509Extension] tag = @OPENSSL_sk_value(_stack, cnt)
    cnt = cnt + 1
    X509Extension.create_from_ptr(ext)



