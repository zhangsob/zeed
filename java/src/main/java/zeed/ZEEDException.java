package zeed;

@SuppressWarnings("serial")
public class ZEEDException extends RuntimeException {	
	private final int code;

	ZEEDException(SEED.Error err) {
		super(err.msg()) ;
		code = err.code();
	}
	
	ZEEDException(SEED.Error err, String msg) {
		super(msg) ;
		code = err.code() ;
	}

	public int getCode(){
		return code;
	}
}
