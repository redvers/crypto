use @mktime[I64](tm: Tm)

struct Tm
  var _tm_sec: I32 = I32(0) // FundamentalType
  var _tm_min: I32 = I32(0) // FundamentalType
  var _tm_hour: I32 = I32(0) // FundamentalType
  var _tm_mday: I32 = I32(0) // FundamentalType
  var _tm_mon: I32 = I32(0) // FundamentalType
  var _tm_year: I32 = I32(0) // FundamentalType
  var _tm_wday: I32 = I32(0) // FundamentalType
  var _tm_yday: I32 = I32(0) // FundamentalType
  var _tm_isdst: I32 = I32(0) // FundamentalType
  var _tm_gmtoff: I64 = I64(0) // FundamentalType
  var _tm_zone: Pointer[U8] = Pointer[U8] // PointerType

	fun ref mktime(): I64 =>
		@mktime(this)

