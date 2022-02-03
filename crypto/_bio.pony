use @BIO_free[I32](a: Pointer[_BIO] tag)
use @BIO_free_all[None](a: Pointer[_BIO] tag)
use @BIO_new[Pointer[_BIO]](otype: Pointer[BIOMethod] tag)
use @BIO_read[I32](b: Pointer[_BIO] tag, data: Pointer[U8] tag, dlen: I32)
use @BIO_s_mem[Pointer[BIOMethod] tag]()
use @BIO_write[I32](b: Pointer[_BIO] tag, data: Pointer[U8] tag, dlen: I32)

class _BIO
  let _bio: Pointer[_BIO] tag = @BIO_new(@BIO_s_mem())

  new create() =>
    None

  fun apply(): Pointer[_BIO] tag =>
    _bio

  fun string(): String val =>
    let retstr: Array[U8] val = recover val
      var tarr: Array[U8] ref = Array[U8]
      let buffer: Array[U8] ref = Array[U8].init(0, 1024)
      var len: I32 = 0
      while ((len = @BIO_read(_bio, buffer.cpointer(), buffer.size().i32())); len > 0) do
        buffer.copy_to(tarr, 0, tarr.size(), len.usize())
      end
      tarr
    end
    String.from_array(retstr)

	fun _final() =>
		@BIO_free_all(_bio)







primitive BIOMethod
