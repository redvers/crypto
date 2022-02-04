use @BIO_free[I32](a: Pointer[_BIO] tag)
use @BIO_free_all[None](a: Pointer[_BIO] tag)
use @BIO_new[Pointer[_BIO]](otype: Pointer[BIOMethod] tag)
use @BIO_read[I32](b: Pointer[_BIO] tag, data: Pointer[U8] tag, dlen: I32)
use @BIO_s_mem[Pointer[BIOMethod] tag]()
use @BIO_write[I32](b: Pointer[_BIO] tag, data: Pointer[U8] tag, dlen: I32)

class _BIO
  """
  BIO is OpenSSL's generic datastructure that allows the rest of the library
  to write "contiguous" binary data without having to worry about memory
  reällocation.

  In this API it is mainly used for reading data in and out
  """
  let _bio: Pointer[_BIO] tag = @BIO_new(@BIO_s_mem())

  new create() =>
    None

  fun apply(): Pointer[_BIO] tag =>
    """
    Alas the pointer needs to be exposed to the calling module so it can
    be passed to the FFI call that needs it
    """
    _bio

  fun array(): Array[U8] val =>
    """
    Returns the contents of the BIO as an Array[U8] val
    """
    recover val
      var tarr: Array[U8] ref = Array[U8]
      let buffer: Array[U8] ref = Array[U8].init(0, 1024)
      var len: I32 = 0
      while ((len = @BIO_read(_bio, buffer.cpointer(), buffer.size().i32())); len > 0) do
        buffer.copy_to(tarr, 0, tarr.size(), len.usize())
      end
      tarr
    end

  fun write(data: (Array[U8] val | String val)): Bool =>
    """
    Writes the contents of the provided Array[U8] or String to the
    BIO
    """
    let readdata: I32 = @BIO_write(_bio, data.cpointer(), data.size().i32())
    (readdata == data.size().i32())

  fun string(): String val =>
    """
    Returns the contents of the BIO as a String val
    """
    String.from_array(array())

	fun _final() =>
		@BIO_free_all(_bio)




primitive BIOMethod
