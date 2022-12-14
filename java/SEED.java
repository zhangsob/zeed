package zeed;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 * SEED ECB (CBC / CTR도 가능) PKCS7 Padding
 * <p>
 * http://seed.kisa.or.kr/를 Open Source를 기반으로 다시 작성한 것
 * <p>
 * https://github.com/zhangsob/zeed 에 공개함.
 * 
 * @author zhangsob@gmail.com
 */
public class SEED {
	/**
	 * SEED 처리중 오류코드(및 Message)
	 */
	public enum Error {
		/** 알 수 없는 오류				*/	UNKNOWN							(0, "unknown error"),
		/** 정상						*/	OK_GOOD							(1, "success"),
		/** 채움(Padding) 오류			*/	PADDING							(2, "padding error"),
		/** 암호문 길이 오류			*/	CIPHER_LENGTH					(3, "cipher length error"),
		/** 키 길이 오류				*/	KEY_LENGTH						(4, "key length error"),
		/** 지원하지 않는 인코딩		*/	CANNOT_SUPPORT_ENCODING_TABLE	(5, "cannot support encoding table"),
		/** 지원하지 않는 문자 있음		*/	INVALID_DECODING_CHARACTER		(6, "invalid decoding character"),
		/** 키는 ASCII만 지원함			*/	KEY_IS_ONLY_ASCII				(7, "key is only ascii"),
		/** Iinital Vector 길이 오류	*/	IV_LENGTH						(8, "initial vector length error"),
		/** Counter 길이 오류			*/	CTR_LENGTH						(9, "counter length error"),
		/** 지원하지 않는 Block Chain	*/	CANNOT_SUPPORT_MODE				(10,"cannot support mode"),
		/** 지원하지 않는 암호길이(Bit)	*/	CANNOT_SUPPORT_BIT				(11, "cannot support bit"),
		/** 지원하지 않는 Padding방식	*/	CANNOT_SUPPORT_PADDING			(12, "cannot support padding"),
		/** 채움(Padding) 이 없음		*/	EMPTY_PADDING					(13, "padding is not") ;
		
		private final int _code ;
		private final String _msg ;
		
		Error(int code, String msg) {
			this._code = code ;
			this._msg = msg ;
		}

		public int code() {
			return _code ;
		}
		
		public String msg() {
			return _msg ;
		}
	} ;
	
	/**
	 * Block Chain 방식
	 */
	public enum Mode {
		/** ECB (Electronic Code Block) Mode*/	ECB(0),
		/** CBC(Cipher Block Chaining) Mode	*/	CBC(1),
		/** CFB(Cipher FeedBack) Mode 		*/	CTR(2) ;
		
		private int _mode ;
		
		Mode(int mode) {
			this._mode = mode ;
		}
		
		public int mode() {
			return _mode ;
		}
	} ;

	/**
	 * 암/복호화키 길이(Bit단위)
	 */
	public enum Bit {
		/** 128bit키 길이, 128bit Block SEED 암호화 */	SEED128(128),
		/** 256bit키 길이, 128bit Block SEED 암호화 */	SEED256(256);
		
		private int _bit ;
		
		Bit(int bit) {
			this._bit = bit ;
		}
		
		public int bit() {
			return _bit ;
		}
	} ;

	/**
	 * 채움(Padding) 방식
	 */
	public enum Padding {
		/** <code>0x80, 0x80 0x00, 0x80 0x00 0x00, ... , 0x80 .. 0x00</code> 방식 채움	*/	BIT  (11),
		/** <code>0x01, 0x00 0x02, 0x00 0x00 0x03, ... , 0x00 .. 0x10</code> 방식 채움	*/	X923 (12),
		/** <code>0x01, 0x02 0x02, 0x03 0x03 0x03, ... , 0x10 .. 0x10</code> 방식 채움	*/	PKCS7(13);
		
		private int _padding ;
		
		Padding(int padding) {
			this._padding = padding ;
		}
		
		public int padding() {
			return _padding ;
		}
	}
	
	/**
	 * Encoding [ Binary(byte[]) &lt;--&gt; Text(String)하는] 방식 
	 */
	public enum EncodingTable {
		/** 대문자 HexaDecimal로 */	HEXA_LARGE				("0123456789ABCDEF"),
		/** 소문자 HexaDecimal로 */	HEXA_SMALL				("0123456789abcdef"),
		/** 0x30 Oring			 */	HEXA_0x30_ORING			("0123456789:;<=>?"),
		
		/** Base64 (RFC4648)	 */	BASE64					("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
		/** Base64 채움없음		 */	BASE64_NOT_PADDING		("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
		/** Base64 URL Safety	 */	BASE64URL				("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="),
		/** Base64 URL 채움없음	 */	BASE64URL_NOT_PADDING	("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
		
		/** ASCII85(Adobe)		 */	ASCII85_ADOBE			("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"),
		/** ASCII85(RFC1924)	 */	ASCII85_RFC1924			("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"),
		/** ASCII85(ZeroMQ)		 */	ASCII85_ZEROMQ			("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#") ;
		
		private String _table ;
		
		EncodingTable(String table) {
			this._table = table ;
		}
		
		public String table() {
			return _table ;
		}
	}
	
	/**
	 * 옵션(선택사항)
	 */
	public enum Option {
		/** 옵션 없음								*/	NONE					 (0x0000),
		/** 복호화시 Padding이 없는 경우도 정상처리	*/	DECRYPT_EMPTY_PADDING_OK (0x0001),
		/** Decoding시 WhiteSpace 무시				*/	DECODE_IGNORE_WHITESPACE (0x0002) ;
		
		private int _option ;
		
		Option(int option) {
			this._option = option ;
		}
		
		int option() {
			return _option ;
		}
		
		static boolean is(int _option, Option option) {
			return (_option & option._option) != Option.NONE._option ;
		}
	}
	
	/**
	 * 암호화/복호화
	 */
	public enum Action {
		/** 복호화 */	DECRYPT	(0),
		/** 암호화 */	ENCRYPT	(1) ;
		
		private int _action ;
		
		Action(int action) {
			this._action = action ;
		}
		
		public int action() {
			return _action ;
		}
	}
	
	private static final int _BLOCK_SIZE = 16 ;
	
	private static final int _SS0[] = {
		0x2989a1a8, 0x05858184, 0x16c6d2d4, 0x13c3d3d0, 0x14445054, 0x1d0d111c, 0x2c8ca0ac, 0x25052124,
		0x1d4d515c, 0x03434340, 0x18081018, 0x1e0e121c, 0x11415150, 0x3cccf0fc, 0x0acac2c8, 0x23436360,
		0x28082028, 0x04444044, 0x20002020, 0x1d8d919c, 0x20c0e0e0, 0x22c2e2e0, 0x08c8c0c8, 0x17071314,
		0x2585a1a4, 0x0f8f838c, 0x03030300, 0x3b4b7378, 0x3b8bb3b8, 0x13031310, 0x12c2d2d0, 0x2ecee2ec,
		0x30407070, 0x0c8c808c, 0x3f0f333c, 0x2888a0a8, 0x32023230, 0x1dcdd1dc, 0x36c6f2f4, 0x34447074,
		0x2ccce0ec, 0x15859194, 0x0b0b0308, 0x17475354, 0x1c4c505c, 0x1b4b5358, 0x3d8db1bc, 0x01010100,
		0x24042024, 0x1c0c101c, 0x33437370, 0x18889098, 0x10001010, 0x0cccc0cc, 0x32c2f2f0, 0x19c9d1d8,
		0x2c0c202c, 0x27c7e3e4, 0x32427270, 0x03838380, 0x1b8b9398, 0x11c1d1d0, 0x06868284, 0x09c9c1c8,
		0x20406060, 0x10405050, 0x2383a3a0, 0x2bcbe3e8, 0x0d0d010c, 0x3686b2b4, 0x1e8e929c, 0x0f4f434c,
		0x3787b3b4, 0x1a4a5258, 0x06c6c2c4, 0x38487078, 0x2686a2a4, 0x12021210, 0x2f8fa3ac, 0x15c5d1d4,
		0x21416160, 0x03c3c3c0, 0x3484b0b4, 0x01414140, 0x12425250, 0x3d4d717c, 0x0d8d818c, 0x08080008,
		0x1f0f131c, 0x19899198, 0x00000000, 0x19091118, 0x04040004, 0x13435350, 0x37c7f3f4, 0x21c1e1e0,
		0x3dcdf1fc, 0x36467274, 0x2f0f232c, 0x27072324, 0x3080b0b0, 0x0b8b8388, 0x0e0e020c, 0x2b8ba3a8,
		0x2282a2a0, 0x2e4e626c, 0x13839390, 0x0d4d414c, 0x29496168, 0x3c4c707c, 0x09090108, 0x0a0a0208,
		0x3f8fb3bc, 0x2fcfe3ec, 0x33c3f3f0, 0x05c5c1c4, 0x07878384, 0x14041014, 0x3ecef2fc, 0x24446064,
		0x1eced2dc, 0x2e0e222c, 0x0b4b4348, 0x1a0a1218, 0x06060204, 0x21012120, 0x2b4b6368, 0x26466264,
		0x02020200, 0x35c5f1f4, 0x12829290, 0x0a8a8288, 0x0c0c000c, 0x3383b3b0, 0x3e4e727c, 0x10c0d0d0,
		0x3a4a7278, 0x07474344, 0x16869294, 0x25c5e1e4, 0x26062224, 0x00808080, 0x2d8da1ac, 0x1fcfd3dc,
		0x2181a1a0, 0x30003030, 0x37073334, 0x2e8ea2ac, 0x36063234, 0x15051114, 0x22022220, 0x38083038,
		0x34c4f0f4, 0x2787a3a4, 0x05454144, 0x0c4c404c, 0x01818180, 0x29c9e1e8, 0x04848084, 0x17879394,
		0x35053134, 0x0bcbc3c8, 0x0ecec2cc, 0x3c0c303c, 0x31417170, 0x11011110, 0x07c7c3c4, 0x09898188,
		0x35457174, 0x3bcbf3f8, 0x1acad2d8, 0x38c8f0f8, 0x14849094, 0x19495158, 0x02828280, 0x04c4c0c4,
		0x3fcff3fc, 0x09494148, 0x39093138, 0x27476364, 0x00c0c0c0, 0x0fcfc3cc, 0x17c7d3d4, 0x3888b0b8,
		0x0f0f030c, 0x0e8e828c, 0x02424240, 0x23032320, 0x11819190, 0x2c4c606c, 0x1bcbd3d8, 0x2484a0a4,
		0x34043034, 0x31c1f1f0, 0x08484048, 0x02c2c2c0, 0x2f4f636c, 0x3d0d313c, 0x2d0d212c, 0x00404040,
		0x3e8eb2bc, 0x3e0e323c, 0x3c8cb0bc, 0x01c1c1c0, 0x2a8aa2a8, 0x3a8ab2b8, 0x0e4e424c, 0x15455154,
		0x3b0b3338, 0x1cccd0dc, 0x28486068, 0x3f4f737c, 0x1c8c909c, 0x18c8d0d8, 0x0a4a4248, 0x16465254,
		0x37477374, 0x2080a0a0, 0x2dcde1ec, 0x06464244, 0x3585b1b4, 0x2b0b2328, 0x25456164, 0x3acaf2f8,
		0x23c3e3e0, 0x3989b1b8, 0x3181b1b0, 0x1f8f939c, 0x1e4e525c, 0x39c9f1f8, 0x26c6e2e4, 0x3282b2b0,
		0x31013130, 0x2acae2e8, 0x2d4d616c, 0x1f4f535c, 0x24c4e0e4, 0x30c0f0f0, 0x0dcdc1cc, 0x08888088,
		0x16061214, 0x3a0a3238, 0x18485058, 0x14c4d0d4, 0x22426260, 0x29092128, 0x07070304, 0x33033330,
		0x28c8e0e8, 0x1b0b1318, 0x05050104, 0x39497178, 0x10809090, 0x2a4a6268, 0x2a0a2228, 0x1a8a9298
	};

	private static final int _SS1[] = {
		0x38380830, 0xe828c8e0, 0x2c2d0d21, 0xa42686a2, 0xcc0fcfc3, 0xdc1eced2, 0xb03383b3, 0xb83888b0,
		0xac2f8fa3, 0x60204060, 0x54154551, 0xc407c7c3, 0x44044440, 0x6c2f4f63, 0x682b4b63, 0x581b4b53,
		0xc003c3c3, 0x60224262, 0x30330333, 0xb43585b1, 0x28290921, 0xa02080a0, 0xe022c2e2, 0xa42787a3,
		0xd013c3d3, 0x90118191, 0x10110111, 0x04060602, 0x1c1c0c10, 0xbc3c8cb0, 0x34360632, 0x480b4b43,
		0xec2fcfe3, 0x88088880, 0x6c2c4c60, 0xa82888a0, 0x14170713, 0xc404c4c0, 0x14160612, 0xf434c4f0,
		0xc002c2c2, 0x44054541, 0xe021c1e1, 0xd416c6d2, 0x3c3f0f33, 0x3c3d0d31, 0x8c0e8e82, 0x98188890,
		0x28280820, 0x4c0e4e42, 0xf436c6f2, 0x3c3e0e32, 0xa42585a1, 0xf839c9f1, 0x0c0d0d01, 0xdc1fcfd3,
		0xd818c8d0, 0x282b0b23, 0x64264662, 0x783a4a72, 0x24270723, 0x2c2f0f23, 0xf031c1f1, 0x70324272,
		0x40024242, 0xd414c4d0, 0x40014141, 0xc000c0c0, 0x70334373, 0x64274763, 0xac2c8ca0, 0x880b8b83,
		0xf437c7f3, 0xac2d8da1, 0x80008080, 0x1c1f0f13, 0xc80acac2, 0x2c2c0c20, 0xa82a8aa2, 0x34340430,
		0xd012c2d2, 0x080b0b03, 0xec2ecee2, 0xe829c9e1, 0x5c1d4d51, 0x94148490, 0x18180810, 0xf838c8f0,
		0x54174753, 0xac2e8ea2, 0x08080800, 0xc405c5c1, 0x10130313, 0xcc0dcdc1, 0x84068682, 0xb83989b1,
		0xfc3fcff3, 0x7c3d4d71, 0xc001c1c1, 0x30310131, 0xf435c5f1, 0x880a8a82, 0x682a4a62, 0xb03181b1,
		0xd011c1d1, 0x20200020, 0xd417c7d3, 0x00020202, 0x20220222, 0x04040400, 0x68284860, 0x70314171,
		0x04070703, 0xd81bcbd3, 0x9c1d8d91, 0x98198991, 0x60214161, 0xbc3e8eb2, 0xe426c6e2, 0x58194951,
		0xdc1dcdd1, 0x50114151, 0x90108090, 0xdc1cccd0, 0x981a8a92, 0xa02383a3, 0xa82b8ba3, 0xd010c0d0,
		0x80018181, 0x0c0f0f03, 0x44074743, 0x181a0a12, 0xe023c3e3, 0xec2ccce0, 0x8c0d8d81, 0xbc3f8fb3,
		0x94168692, 0x783b4b73, 0x5c1c4c50, 0xa02282a2, 0xa02181a1, 0x60234363, 0x20230323, 0x4c0d4d41,
		0xc808c8c0, 0x9c1e8e92, 0x9c1c8c90, 0x383a0a32, 0x0c0c0c00, 0x2c2e0e22, 0xb83a8ab2, 0x6c2e4e62,
		0x9c1f8f93, 0x581a4a52, 0xf032c2f2, 0x90128292, 0xf033c3f3, 0x48094941, 0x78384870, 0xcc0cccc0,
		0x14150511, 0xf83bcbf3, 0x70304070, 0x74354571, 0x7c3f4f73, 0x34350531, 0x10100010, 0x00030303,
		0x64244460, 0x6c2d4d61, 0xc406c6c2, 0x74344470, 0xd415c5d1, 0xb43484b0, 0xe82acae2, 0x08090901,
		0x74364672, 0x18190911, 0xfc3ecef2, 0x40004040, 0x10120212, 0xe020c0e0, 0xbc3d8db1, 0x04050501,
		0xf83acaf2, 0x00010101, 0xf030c0f0, 0x282a0a22, 0x5c1e4e52, 0xa82989a1, 0x54164652, 0x40034343,
		0x84058581, 0x14140410, 0x88098981, 0x981b8b93, 0xb03080b0, 0xe425c5e1, 0x48084840, 0x78394971,
		0x94178793, 0xfc3cccf0, 0x1c1e0e12, 0x80028282, 0x20210121, 0x8c0c8c80, 0x181b0b13, 0x5c1f4f53,
		0x74374773, 0x54144450, 0xb03282b2, 0x1c1d0d11, 0x24250521, 0x4c0f4f43, 0x00000000, 0x44064642,
		0xec2dcde1, 0x58184850, 0x50124252, 0xe82bcbe3, 0x7c3e4e72, 0xd81acad2, 0xc809c9c1, 0xfc3dcdf1,
		0x30300030, 0x94158591, 0x64254561, 0x3c3c0c30, 0xb43686b2, 0xe424c4e0, 0xb83b8bb3, 0x7c3c4c70,
		0x0c0e0e02, 0x50104050, 0x38390931, 0x24260622, 0x30320232, 0x84048480, 0x68294961, 0x90138393,
		0x34370733, 0xe427c7e3, 0x24240420, 0xa42484a0, 0xc80bcbc3, 0x50134353, 0x080a0a02, 0x84078783,
		0xd819c9d1, 0x4c0c4c40, 0x80038383, 0x8c0f8f83, 0xcc0ecec2, 0x383b0b33, 0x480a4a42, 0xb43787b3
	};

	private static final int _SS2[] = {
		0xa1a82989, 0x81840585, 0xd2d416c6, 0xd3d013c3, 0x50541444, 0x111c1d0d, 0xa0ac2c8c, 0x21242505,
		0x515c1d4d, 0x43400343, 0x10181808, 0x121c1e0e, 0x51501141, 0xf0fc3ccc, 0xc2c80aca, 0x63602343,
		0x20282808, 0x40440444, 0x20202000, 0x919c1d8d, 0xe0e020c0, 0xe2e022c2, 0xc0c808c8, 0x13141707,
		0xa1a42585, 0x838c0f8f, 0x03000303, 0x73783b4b, 0xb3b83b8b, 0x13101303, 0xd2d012c2, 0xe2ec2ece,
		0x70703040, 0x808c0c8c, 0x333c3f0f, 0xa0a82888, 0x32303202, 0xd1dc1dcd, 0xf2f436c6, 0x70743444,
		0xe0ec2ccc, 0x91941585, 0x03080b0b, 0x53541747, 0x505c1c4c, 0x53581b4b, 0xb1bc3d8d, 0x01000101,
		0x20242404, 0x101c1c0c, 0x73703343, 0x90981888, 0x10101000, 0xc0cc0ccc, 0xf2f032c2, 0xd1d819c9,
		0x202c2c0c, 0xe3e427c7, 0x72703242, 0x83800383, 0x93981b8b, 0xd1d011c1, 0x82840686, 0xc1c809c9,
		0x60602040, 0x50501040, 0xa3a02383, 0xe3e82bcb, 0x010c0d0d, 0xb2b43686, 0x929c1e8e, 0x434c0f4f,
		0xb3b43787, 0x52581a4a, 0xc2c406c6, 0x70783848, 0xa2a42686, 0x12101202, 0xa3ac2f8f, 0xd1d415c5,
		0x61602141, 0xc3c003c3, 0xb0b43484, 0x41400141, 0x52501242, 0x717c3d4d, 0x818c0d8d, 0x00080808,
		0x131c1f0f, 0x91981989, 0x00000000, 0x11181909, 0x00040404, 0x53501343, 0xf3f437c7, 0xe1e021c1,
		0xf1fc3dcd, 0x72743646, 0x232c2f0f, 0x23242707, 0xb0b03080, 0x83880b8b, 0x020c0e0e, 0xa3a82b8b,
		0xa2a02282, 0x626c2e4e, 0x93901383, 0x414c0d4d, 0x61682949, 0x707c3c4c, 0x01080909, 0x02080a0a,
		0xb3bc3f8f, 0xe3ec2fcf, 0xf3f033c3, 0xc1c405c5, 0x83840787, 0x10141404, 0xf2fc3ece, 0x60642444,
		0xd2dc1ece, 0x222c2e0e, 0x43480b4b, 0x12181a0a, 0x02040606, 0x21202101, 0x63682b4b, 0x62642646,
		0x02000202, 0xf1f435c5, 0x92901282, 0x82880a8a, 0x000c0c0c, 0xb3b03383, 0x727c3e4e, 0xd0d010c0,
		0x72783a4a, 0x43440747, 0x92941686, 0xe1e425c5, 0x22242606, 0x80800080, 0xa1ac2d8d, 0xd3dc1fcf,
		0xa1a02181, 0x30303000, 0x33343707, 0xa2ac2e8e, 0x32343606, 0x11141505, 0x22202202, 0x30383808,
		0xf0f434c4, 0xa3a42787, 0x41440545, 0x404c0c4c, 0x81800181, 0xe1e829c9, 0x80840484, 0x93941787,
		0x31343505, 0xc3c80bcb, 0xc2cc0ece, 0x303c3c0c, 0x71703141, 0x11101101, 0xc3c407c7, 0x81880989,
		0x71743545, 0xf3f83bcb, 0xd2d81aca, 0xf0f838c8, 0x90941484, 0x51581949, 0x82800282, 0xc0c404c4,
		0xf3fc3fcf, 0x41480949, 0x31383909, 0x63642747, 0xc0c000c0, 0xc3cc0fcf, 0xd3d417c7, 0xb0b83888,
		0x030c0f0f, 0x828c0e8e, 0x42400242, 0x23202303, 0x91901181, 0x606c2c4c, 0xd3d81bcb, 0xa0a42484,
		0x30343404, 0xf1f031c1, 0x40480848, 0xc2c002c2, 0x636c2f4f, 0x313c3d0d, 0x212c2d0d, 0x40400040,
		0xb2bc3e8e, 0x323c3e0e, 0xb0bc3c8c, 0xc1c001c1, 0xa2a82a8a, 0xb2b83a8a, 0x424c0e4e, 0x51541545,
		0x33383b0b, 0xd0dc1ccc, 0x60682848, 0x737c3f4f, 0x909c1c8c, 0xd0d818c8, 0x42480a4a, 0x52541646,
		0x73743747, 0xa0a02080, 0xe1ec2dcd, 0x42440646, 0xb1b43585, 0x23282b0b, 0x61642545, 0xf2f83aca,
		0xe3e023c3, 0xb1b83989, 0xb1b03181, 0x939c1f8f, 0x525c1e4e, 0xf1f839c9, 0xe2e426c6, 0xb2b03282,
		0x31303101, 0xe2e82aca, 0x616c2d4d, 0x535c1f4f, 0xe0e424c4, 0xf0f030c0, 0xc1cc0dcd, 0x80880888,
		0x12141606, 0x32383a0a, 0x50581848, 0xd0d414c4, 0x62602242, 0x21282909, 0x03040707, 0x33303303,
		0xe0e828c8, 0x13181b0b, 0x01040505, 0x71783949, 0x90901080, 0x62682a4a, 0x22282a0a, 0x92981a8a
	};

	private static final int _SS3[] = {
		0x08303838, 0xc8e0e828, 0x0d212c2d, 0x86a2a426, 0xcfc3cc0f, 0xced2dc1e, 0x83b3b033, 0x88b0b838,
		0x8fa3ac2f, 0x40606020, 0x45515415, 0xc7c3c407, 0x44404404, 0x4f636c2f, 0x4b63682b, 0x4b53581b,
		0xc3c3c003, 0x42626022, 0x03333033, 0x85b1b435, 0x09212829, 0x80a0a020, 0xc2e2e022, 0x87a3a427,
		0xc3d3d013, 0x81919011, 0x01111011, 0x06020406, 0x0c101c1c, 0x8cb0bc3c, 0x06323436, 0x4b43480b,
		0xcfe3ec2f, 0x88808808, 0x4c606c2c, 0x88a0a828, 0x07131417, 0xc4c0c404, 0x06121416, 0xc4f0f434,
		0xc2c2c002, 0x45414405, 0xc1e1e021, 0xc6d2d416, 0x0f333c3f, 0x0d313c3d, 0x8e828c0e, 0x88909818,
		0x08202828, 0x4e424c0e, 0xc6f2f436, 0x0e323c3e, 0x85a1a425, 0xc9f1f839, 0x0d010c0d, 0xcfd3dc1f,
		0xc8d0d818, 0x0b23282b, 0x46626426, 0x4a72783a, 0x07232427, 0x0f232c2f, 0xc1f1f031, 0x42727032,
		0x42424002, 0xc4d0d414, 0x41414001, 0xc0c0c000, 0x43737033, 0x47636427, 0x8ca0ac2c, 0x8b83880b,
		0xc7f3f437, 0x8da1ac2d, 0x80808000, 0x0f131c1f, 0xcac2c80a, 0x0c202c2c, 0x8aa2a82a, 0x04303434,
		0xc2d2d012, 0x0b03080b, 0xcee2ec2e, 0xc9e1e829, 0x4d515c1d, 0x84909414, 0x08101818, 0xc8f0f838,
		0x47535417, 0x8ea2ac2e, 0x08000808, 0xc5c1c405, 0x03131013, 0xcdc1cc0d, 0x86828406, 0x89b1b839,
		0xcff3fc3f, 0x4d717c3d, 0xc1c1c001, 0x01313031, 0xc5f1f435, 0x8a82880a, 0x4a62682a, 0x81b1b031,
		0xc1d1d011, 0x00202020, 0xc7d3d417, 0x02020002, 0x02222022, 0x04000404, 0x48606828, 0x41717031,
		0x07030407, 0xcbd3d81b, 0x8d919c1d, 0x89919819, 0x41616021, 0x8eb2bc3e, 0xc6e2e426, 0x49515819,
		0xcdd1dc1d, 0x41515011, 0x80909010, 0xccd0dc1c, 0x8a92981a, 0x83a3a023, 0x8ba3a82b, 0xc0d0d010,
		0x81818001, 0x0f030c0f, 0x47434407, 0x0a12181a, 0xc3e3e023, 0xcce0ec2c, 0x8d818c0d, 0x8fb3bc3f,
		0x86929416, 0x4b73783b, 0x4c505c1c, 0x82a2a022, 0x81a1a021, 0x43636023, 0x03232023, 0x4d414c0d,
		0xc8c0c808, 0x8e929c1e, 0x8c909c1c, 0x0a32383a, 0x0c000c0c, 0x0e222c2e, 0x8ab2b83a, 0x4e626c2e,
		0x8f939c1f, 0x4a52581a, 0xc2f2f032, 0x82929012, 0xc3f3f033, 0x49414809, 0x48707838, 0xccc0cc0c,
		0x05111415, 0xcbf3f83b, 0x40707030, 0x45717435, 0x4f737c3f, 0x05313435, 0x00101010, 0x03030003,
		0x44606424, 0x4d616c2d, 0xc6c2c406, 0x44707434, 0xc5d1d415, 0x84b0b434, 0xcae2e82a, 0x09010809,
		0x46727436, 0x09111819, 0xcef2fc3e, 0x40404000, 0x02121012, 0xc0e0e020, 0x8db1bc3d, 0x05010405,
		0xcaf2f83a, 0x01010001, 0xc0f0f030, 0x0a22282a, 0x4e525c1e, 0x89a1a829, 0x46525416, 0x43434003,
		0x85818405, 0x04101414, 0x89818809, 0x8b93981b, 0x80b0b030, 0xc5e1e425, 0x48404808, 0x49717839,
		0x87939417, 0xccf0fc3c, 0x0e121c1e, 0x82828002, 0x01212021, 0x8c808c0c, 0x0b13181b, 0x4f535c1f,
		0x47737437, 0x44505414, 0x82b2b032, 0x0d111c1d, 0x05212425, 0x4f434c0f, 0x00000000, 0x46424406,
		0xcde1ec2d, 0x48505818, 0x42525012, 0xcbe3e82b, 0x4e727c3e, 0xcad2d81a, 0xc9c1c809, 0xcdf1fc3d,
		0x00303030, 0x85919415, 0x45616425, 0x0c303c3c, 0x86b2b436, 0xc4e0e424, 0x8bb3b83b, 0x4c707c3c,
		0x0e020c0e, 0x40505010, 0x09313839, 0x06222426, 0x02323032, 0x84808404, 0x49616829, 0x83939013,
		0x07333437, 0xc7e3e427, 0x04202424, 0x84a0a424, 0xcbc3c80b, 0x43535013, 0x0a02080a, 0x87838407,
		0xc9d1d819, 0x4c404c0c, 0x83838003, 0x8f838c0f, 0xcec2cc0e, 0x0b33383b, 0x4a42480a, 0x87b3b437
	};
	
	private static int _GetB0(int A) { return (A >>  0) & 0xFF; }	// byte : -128 ~ 127
	private static int _GetB1(int A) { return (A >>  8) & 0xFF; }
	private static int _GetB2(int A) { return (A >> 16) & 0xFF; }
	private static int _GetB3(int A) { return (A >> 24) & 0xFF; }
	
	// SEED128
	private static final void _RoundKeyUpdate0(int[] K, int K_offset, int[] U, int KC) {
		int T0 = U[0] + U[2] - KC;
		int T1 = U[1] + KC - U[3];
		K[K_offset+0] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)];
		K[K_offset+1] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)];
		T0 = U[0]; 
		U[0] = (U[0] >>> 8) ^ (U[1] << 24) ;
		U[1] = (U[1] >>> 8) ^ (T0   << 24) ;
	}

	// SEED128
	private static final void _RoundKeyUpdate1(int[] K, int K_offset, int[] U, int KC) {
		int T0 = U[0] + U[2] - KC;
		int T1 = U[1] + KC - U[3];
		K[K_offset+0] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)] ;
		K[K_offset+1] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)] ;
		T0 = U[2];
		U[2] = (U[2] << 8) ^ (U[3] >>> 24) ;
		U[3] = (U[3] << 8) ^ (T0   >>> 24) ;
	}

	// SEED256
	private static final void _RoundKeyUpdate0(int[] K, int K_offset, int[] U, int KC, int rot) {
		int T0 = U[3], T1 ;
		U[3] = (U[3] >>> rot) ^ (U[2] << (32-rot)) ;
		U[2] = (U[2] >>> rot) ^ (U[1] << (32-rot)) ;
		U[1] = (U[1] >>> rot) ^ (U[0] << (32-rot)) ;
		U[0] = (U[0] >>> rot) ^ (T0   << (32-rot)) ;
		
		T0 = (((U[0] + U[2]) ^ U[4]) - U[5]) ^ KC ;
		T1 = (((U[1] - U[3]) ^ U[6]) + U[7]) ^ KC ;
		K[K_offset+0] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)] ;
		K[K_offset+1] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)] ;
	}

	// SEED256
	private static final void _RoundKeyUpdate1(int[] K, int K_offset, int[] U, int KC, int rot) {
		int T0 = U[4], T1 ;
		U[4] = (U[4] << rot) ^ (U[5] >>> (32-rot));
		U[5] = (U[5] << rot) ^ (U[6] >>> (32-rot));
		U[6] = (U[6] << rot) ^ (U[7] >>> (32-rot));
		U[7] = (U[7] << rot) ^ (T0   >>> (32-rot));
		T0 = (((U[0] + U[2]) ^ U[4]) - U[5]) ^ KC ;
		T1 = (((U[1] - U[3]) ^ U[6]) + U[7]) ^ KC ;
		K[K_offset+0] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)];
		K[K_offset+1] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)];
	}
	
	Mode mode = Mode.ECB ;
	Bit bit = Bit.SEED128 ;
	Padding padding = Padding.PKCS7 ;
	int _option = Option.NONE.option() ;
	int[] roundKey = new int[0] ;
	byte[] iv = new byte[0] ;
	byte[] ctr = new byte[0] ;
	
	boolean isEncrypt = true ;
	byte[] seasoning = new byte[0] ;
	/** Block처리하며 남은 Binary	*/	ArrayList<Byte> remain_data = null ;
	/** return해야할 Binary 		*/	ArrayList<Byte> ret_binary  = new ArrayList<Byte>();
	
	/**
	 * 암호화 방식 정하기
	 * @param mode		Mod.ECB, Mode.CBC, Mode.CTR 중 택일
	 * @param bit		Bit.SEED128, Bit.SEED256 중 택일
	 * @param padding	Padding.BIT, Padding.X923, Padding.PKCS7 중 택일
	 */
	public SEED(Mode mode, Bit bit, Padding padding) {
		this.mode = mode ;
		this.bit = bit ;
		this.padding = padding ;
		this._option = Option.NONE.option() ;
	}
	
	/**
	 * Option을 넣기. (단, Option.NONE은 Clear된다.)
	 * @param option	Option을 참조하여 넣는다.
	 */
	public void option(Option option) {
		switch(option) {
		case NONE	:	this._option = option.option() ;	break ;
		default		:	this._option |= option.option() ;	break ;
		}
	}
	
	/**
	 * 해당 Option이 있는가?
	 * @param option	Option을 참조하여 넣는다.
	 * @return			true: 있음, false: 없음
	 */
	public boolean is(Option option) {
		return Option.is(this._option, option) ;
	}
	/**
	 * SEED.CBC_MODE일 때 initial vector 설정하기
	 * @param iv	initial vector 16 Byte
	 */
	public void setInitialVector(byte[] iv) {
		if (iv.length != 16)	throw new ZEEDException(Error.IV_LENGTH, "InitialVector length != 16") ;
		this.iv = iv ;
	}

	/**
	 * SEED.CTR_MODE일 때 counter 설정하기
	 * @param ctr	counter 16 Byte
	 */
	public void setCounter(byte[] ctr) {
		if (ctr.length != 16)	throw new ZEEDException(Error.CTR_LENGTH, "Counter length != 16") ;
		this.ctr = ctr ;
	}
	
	private static int _b2i(byte[] bin, int offset, int length) {
		int ret = 0;
		for (int i = 0; i < length; ++i) {
			ret <<= 8;
			ret |= bin[offset+i] & 0xFF;
		}
		return ret;
	}
	
	private static void _i2b(byte[] ret, int offset, int value, int size) {
		for (int i = size - 1; i >= 0; --i) {
			ret[offset+i] = (byte)(value & 0xFF);
			value >>>= 8;
		}
	}
	
	/**
	@brief UserKey를 이용하여 RoundKey 생성
	@param userKey : RoundKey를 생성할 기본 키
	@return roundKey (SEED_128 : 16byte 또는 SEED_256 : 32byte)
	*/
	private int[] _getRoundKey(byte[] userKey) {
		switch(this.bit)
		{
		case SEED128 :
						{
							int[] U = new int[4] ;
							for(int i = 0; i < 4; ++i)
								U[i] = _b2i(userKey, i *4, 4) ;
							
							int[] K = new int[32] ;
							
							int[] KC = {
									0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc,
									0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf,
									0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1,
									0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b,
							} ;
							
							_RoundKeyUpdate0(K,  0, U, KC[ 0]);
							_RoundKeyUpdate1(K,  2, U, KC[ 1]);
							_RoundKeyUpdate0(K,  4, U, KC[ 2]);
							_RoundKeyUpdate1(K,  6, U, KC[ 3]);
							_RoundKeyUpdate0(K,  8, U, KC[ 4]);
							_RoundKeyUpdate1(K, 10, U, KC[ 5]);
							_RoundKeyUpdate0(K, 12, U, KC[ 6]);
							_RoundKeyUpdate1(K, 14, U, KC[ 7]);
							_RoundKeyUpdate0(K, 16, U, KC[ 8]);
							_RoundKeyUpdate1(K, 18, U, KC[ 9]);
							_RoundKeyUpdate0(K, 20, U, KC[10]);
							_RoundKeyUpdate1(K, 22, U, KC[11]);
							_RoundKeyUpdate0(K, 24, U, KC[12]);
							_RoundKeyUpdate1(K, 26, U, KC[13]);
							_RoundKeyUpdate0(K, 28, U, KC[14]);
							
							int T0 = U[0] + U[2] - KC[15];
							int T1 = U[1] - U[3] + KC[15];
							K[30] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)]; // K_16,0
							K[31] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)]; // K_16,1
							return K ;
						}
						
		case SEED256 :
						{
							int[] U = new int[8] ;
							for(int i = 0; i < 8; ++i)
								U[i] = _b2i(userKey, i * 4, 4) ;
							
							int[] K = new int[48] ;
							
							int[] KC = {
								0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc, 0xe3779b99, 0xc6ef3733,
								0x8dde6e67, 0x1bbcdccf, 0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1,
								0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b, 0x79b99e37, 0xf3733c6e,
								0xe6e678dd, 0xcdccf1bb, 0x9b99e377, 0x3733c6ef, 0x6e678dde, 0xdccf1bbc,
							} ;
							
							int T0 = (((U[0] + U[2]) ^ U[4]) - U[5]) ^ KC[0] ;
							int T1 = (((U[1] - U[3]) ^ U[6]) + U[7]) ^ KC[0] ;
							K[0] = _SS0[_GetB0(T0)] ^ _SS1[_GetB1(T0)] ^ _SS2[_GetB2(T0)] ^ _SS3[_GetB3(T0)];
							K[1] = _SS0[_GetB0(T1)] ^ _SS1[_GetB1(T1)] ^ _SS2[_GetB2(T1)] ^ _SS3[_GetB3(T1)];
							
							_RoundKeyUpdate0(K,  2, U, KC[ 1],  9);
							_RoundKeyUpdate1(K,  4, U, KC[ 2],  9);
							_RoundKeyUpdate0(K,  6, U, KC[ 3], 11);
							_RoundKeyUpdate1(K,  8, U, KC[ 4], 11);
							_RoundKeyUpdate0(K, 10, U, KC[ 5], 12);
							_RoundKeyUpdate1(K, 12, U, KC[ 6], 12);
							_RoundKeyUpdate0(K, 14, U, KC[ 7],  9);
							_RoundKeyUpdate1(K, 16, U, KC[ 8],  9);
							_RoundKeyUpdate0(K, 18, U, KC[ 9], 11);
							_RoundKeyUpdate1(K, 20, U, KC[10], 11);
							_RoundKeyUpdate0(K, 22, U, KC[11], 12);
							_RoundKeyUpdate1(K, 24, U, KC[12], 12);
							_RoundKeyUpdate0(K, 26, U, KC[13],  9);
							_RoundKeyUpdate1(K, 28, U, KC[14],  9);
							_RoundKeyUpdate0(K, 30, U, KC[15], 11);
							_RoundKeyUpdate1(K, 32, U, KC[16], 11);
							_RoundKeyUpdate0(K, 34, U, KC[17], 12);
							_RoundKeyUpdate1(K, 36, U, KC[18], 12);
							_RoundKeyUpdate0(K, 38, U, KC[19],  9);
							_RoundKeyUpdate1(K, 40, U, KC[20],  9);
							_RoundKeyUpdate0(K, 42, U, KC[21], 11);
							_RoundKeyUpdate1(K, 44, U, KC[22], 11);
							_RoundKeyUpdate0(K, 46, U, KC[23], 12);
							return K ;
						}
		}
		
		return null ;
	}
	
	private static final void _SEED_Round(int LR[], int L0, int L1, int R0, int R1, int[] K, int K_offset) {
		int T[] = new int[2];		// Temporary variables for round function F
		
		T[0] = LR[R0] ^ K[K_offset+0];
		T[1] = LR[R1] ^ K[K_offset+1];
		T[1] ^= T[0];
		T[1] = _SS0[_GetB0(T[1])] ^ _SS1[_GetB1(T[1])] ^ _SS2[_GetB2(T[1])] ^ _SS3[_GetB3(T[1])];
		T[0] += T[1];
		T[0] = _SS0[_GetB0(T[0])] ^ _SS1[_GetB1(T[0])] ^ _SS2[_GetB2(T[0])] ^ _SS3[_GetB3(T[0])];
		T[1] += T[0];
		T[1] = _SS0[_GetB0(T[1])] ^ _SS1[_GetB1(T[1])] ^ _SS2[_GetB2(T[1])] ^ _SS3[_GetB3(T[1])];
		T[0] += T[1];
		LR[L0] ^= T[0];
		LR[L1] ^= T[1];
	}

	private static final int LR_L0 = 0;
	private static final int LR_L1 = 1;
	private static final int LR_R0 = 2;
	private static final int LR_R1 = 3;

	/**
	 * block(128 bit) 암호화
	 * @param plain			암호화할 plain (입력 평문)	
	 * @param p_offset	 	plain offset
	 * @param cipher		암호화된 cipher (출력 암호문)
	 * @param c_offset		cipher offset
	 * @param pdwRoundKey	암호화 Round Key
	 */
	private static void _SEED_Encrypt(byte[] plain, int p_offset, byte[] cipher, int c_offset, int[] pdwRoundKey) {
		int LR[] = { 0, 0, 0, 0} ;	// Iuput/output values at each rounds
		int K[] = pdwRoundKey;		// Pointer of round keys
		
		LR[LR_L0] = _b2i(plain, p_offset + 0, 4) ;
		LR[LR_L1] = _b2i(plain, p_offset + 4, 4) ;
		LR[LR_R0] = _b2i(plain, p_offset + 8, 4) ;
		LR[LR_R1] = _b2i(plain, p_offset +12, 4) ;
		
		for(int i = 0; (i+3) < K.length; i += 4) {
			_SEED_Round(LR, LR_L0, LR_L1, LR_R0, LR_R1, K,  i+0);
			_SEED_Round(LR, LR_R0, LR_R1, LR_L0, LR_L1, K,  i+2);
		}
		
		_i2b(cipher, c_offset+ 0, LR[LR_R0], 4) ;
		_i2b(cipher, c_offset+ 4, LR[LR_R1], 4) ;
		_i2b(cipher, c_offset+ 8, LR[LR_L0], 4) ;
		_i2b(cipher, c_offset+12, LR[LR_L1], 4) ;
	}

	private void _blockEncrypt(byte[] plain, int p_offset, byte[] cipher, int c_offset) {
		switch(this.mode)
		{
		case ECB :
					_SEED_Encrypt(plain, p_offset, cipher, c_offset, roundKey) ;
					return ;
		
		case CBC :
					{
						byte[] temp = new byte[_BLOCK_SIZE] ;
						_BLOCK_XOR(temp, 0, plain, p_offset, seasoning, 0);
						_SEED_Encrypt(temp, 0, cipher, c_offset, roundKey) ;
						System.arraycopy(cipher, c_offset, seasoning, 0, _BLOCK_SIZE);
					}
					return ;
		case CTR :
					{
						byte[] temp = new byte[_BLOCK_SIZE] ;
						_SEED_Encrypt(seasoning, 0, temp, 0, roundKey) ;
						_BLOCK_XOR(cipher, c_offset, plain, p_offset, temp, 0) ;
						_UpdateCounter(seasoning, 1);
					}
					return ;
		}
	}
	
	/**
	 * block(128 bit) 복호화
	 * @param cipher		복호화할 cipher(입력 암호문)
	 * @param c_offset		cipher offset
	 * @param plain 		복호화된 plain(출력 평문)
	 * @param p_offset	 	plain offset
	 * @param pdwRoundKey	복호화 Round Key
	 */
	private static void _SEED_Decrypt(byte[] cipher, int c_offset, byte[] plain, int p_offset, int[] pdwRoundKey) {
		int LR[] = new int[4];				// Iuput/output values at each rounds
		int K[] = pdwRoundKey;				// Pointer of round keys
	
		LR[LR_L0] = _b2i(cipher, c_offset + 0, 4) ;
		LR[LR_L1] = _b2i(cipher, c_offset + 4, 4) ;
		LR[LR_R0] = _b2i(cipher, c_offset + 8, 4) ;
		LR[LR_R1] = _b2i(cipher, c_offset +12, 4) ;
	
		for(int i = K.length; i > 3; i -= 4) {
			_SEED_Round(LR, LR_L0, LR_L1, LR_R0, LR_R1, K, i-2);
			_SEED_Round(LR, LR_R0, LR_R1, LR_L0, LR_L1, K, i-4);
		}
	
		_i2b(plain, p_offset+ 0, LR[LR_R0], 4) ;
		_i2b(plain, p_offset+ 4, LR[LR_R1], 4) ;
		_i2b(plain, p_offset+ 8, LR[LR_L0], 4) ;
		_i2b(plain, p_offset+12, LR[LR_L1], 4) ;
	}
	
	/**
	 * block(128 bit) 복호화
	 * @param cipher		복호화할 cipher(입력 암호문)
	 * @param c_offset		cipher offset
	 * @param plain 		복호화된 plain(출력 평문)
	 * @param p_offset	 	plain offset
	 */
	private void _blockDecrypt(byte[] cipher, int c_offset, byte[] plain, int p_offset) {
		switch(this.mode)
		{
		case ECB :
					_SEED_Decrypt(cipher, c_offset, plain, p_offset, roundKey) ;
					return ;
		case CBC : 
					{
						_SEED_Decrypt(cipher, c_offset, plain, p_offset, roundKey) ;
						_BLOCK_XOR(plain, p_offset, seasoning, 0);
						System.arraycopy(cipher, c_offset, seasoning, 0, _BLOCK_SIZE);
					}
					return ;
		case CTR : 
					{
						_SEED_Encrypt(seasoning, 0, plain, p_offset, roundKey) ;
						_BLOCK_XOR(plain, p_offset, cipher, c_offset);
						_UpdateCounter(seasoning, 1);
					}
					return ;
		}
	}
	
	private static byte[] PaddingZero(byte[] data, int data_length, int block_size) {
		int padding_count = block_size - (data_length % block_size) ;
		
		byte[] ret = new byte[data_length + padding_count] ;
		
		System.arraycopy(data, 0, ret, 0, data_length);
		for(int i = 0; i < padding_count; ++i)
			ret[data_length + i] = (byte)0x00 ;	// All 0x00 Padding
		
		return ret ;
	}
	
	/**
	 * 128bit(16Byte)단위로 맞추기(padding) 3번째 방식
	 * @param data 맞출 Binary Data
	 * @return 맞춘 Binary Data
	 */
	private static byte[] _PaddingPKCS7(byte[] data, int data_length, int block_size) {
		int padding_count = block_size - (data_length % block_size) ;
		
		byte[] ret = new byte[data_length + padding_count] ;
		
		System.arraycopy(data, 0, ret, 0, data_length);
		for(int i = 0; i < padding_count; ++i)
			ret[data_length + i] = (byte)padding_count ;
		
		return ret ;
	}
	
	private static byte[] _PaddingBit(byte[] data, int data_length, int block_size) {
		int padding_count = block_size - (data_length % block_size) ;
		
		byte[] ret = new byte[data_length + padding_count] ;
		
		System.arraycopy(data, 0, ret, 0, data_length);
		for(int i = 0; i < padding_count; ++i) {
			if(i == 0)
				ret[data_length + i] = (byte)0x80 ;	// 첫번째 Padding만 0x80
			else
				ret[data_length + i] = (byte)0x00 ;	// 나머지 0x00 Padding
		}
		
		return ret ;
	}
	
	private static byte[] _PaddingX923(byte[] data, int data_length, int block_size) {
		int padding_count = block_size - (data_length % block_size) ;
		
		byte[] ret = new byte[data_length + padding_count] ;
		
		System.arraycopy(data, 0, ret, 0, data_length);
		for(int i = 0; i < padding_count; ++i)
			ret[data_length + i] = (byte)0x00 ;		// 나머지 0x00 Padding
		ret[ret.length-1] = (byte)padding_count ;	// 마지막만 padding_count
		
		return ret ;
	}
	
	private byte[] Padding(byte[] data, int data_length, int block_size) {
		switch(this.padding) {
		case BIT 	: return _PaddingBit(data, data_length, block_size) ;
		case PKCS7	: return _PaddingPKCS7(data, data_length, block_size) ;
		case X923	: return _PaddingX923(data, data_length, block_size) ;
		default		: throw new ZEEDException(Error.CANNOT_SUPPORT_PADDING) ;
		}
	}
	
	private static void _BLOCK_XOR(byte[] data, int data_offset, byte[] value, int value_offset) {
		for(int i = 0; i < _BLOCK_SIZE; ++i)
			data[data_offset + i] ^= value[value_offset + i] ;
	}

	private static void _BLOCK_XOR(byte[] data, int data_offset, byte[] value1, int value1_offset, byte[] value2, int value2_offset) {
		for(int i = 0; i < _BLOCK_SIZE; ++i)
			data[data_offset + i] = (byte)(value1[value1_offset + i] ^ value2[value2_offset + i]);
	}
	
	private static void _UpdateCounter(byte[] buffer, int nIncreaseValue) {
		int counter = nIncreaseValue ;
		for(int i = buffer.length-1; counter != 0 && i >= 0; --i) {
			counter += (buffer[i] & 0xFF) ;
			buffer[i] = (byte)(counter & 0xFF) ;
			counter = counter >>> 8 ;
		}
	}

	/**
	 * 사용자 비밀번호을 넣기
	 * @param userKey	SEED.SEED_128(Default)이면 16 Byte를 SEED.SEED_256이면 32 Byte를 넣는다.
	 */
	public void setUserKey(byte[] userKey) {
		if (userKey.length == 0)				throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		if (userKey.length != this.bit.bit()/8)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length != " + (this.bit.bit()/8)) ;

		this.roundKey = _getRoundKey(userKey);
	}

	/**
	 * 사용자 비밀번호을 넣기(내부적으로 All Zero Padding을 한다.)
	 * @param userKey	비밀번호를 1 ~ 16자리(SEED_256이면 32자리까지) ASCII만 넣는다.  
	 */
	public void setUserKey(String userKey) {
		if (userKey.length() == 0)					throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		if (userKey.length() > this.bit.bit()/8)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length > " + (this.bit.bit()/8)) ;

		setUserKey(_GetKeyBytes(userKey, this.bit.bit()/8)) ;
	}
	
	/**
	 * 암/복호화 시작 설정하기
	 * init() 후 process() 또는 append()를 하고, 마지막에 finish()를 꼭 한다. 
	 * @param action	암호화 시작이면 SEED.Action.ENCRYT를, 복호화 시작이면 SEED.Action.DECRYPT를 넣는다.
	 */
	public void init(Action action)
	{
		this.isEncrypt = (action == Action.ENCRYPT) ;
		this.remain_data = null ;
		this.ret_binary.clear() ;
		switch(this.mode)
		{
		case ECB :
					break ;
		case CBC : 
					{
						if(iv.length == 0)	iv = new byte[_BLOCK_SIZE] ;
			
						seasoning = new byte[_BLOCK_SIZE];
						System.arraycopy(iv, 0, seasoning, 0, _BLOCK_SIZE);
					}
					break ;
		case CTR :
					{
						if(ctr.length == 0)	ctr = new byte[_BLOCK_SIZE] ;

						seasoning = new byte[_BLOCK_SIZE] ;
						System.arraycopy(ctr, 0, seasoning, 0, _BLOCK_SIZE);
					}
					break ;
		}
	}
	
	/**
	 * 암/복호화 대상Data을 반복적으로 추가하기
	 * init()를 먼저 한 후, append()를 반복적으로 호출하고, 반드시 finish()로 마무리한다.
	 * @param data		추가할 Data
	 * @param data_size	추가할 Data 길이
	 */
	public void append(byte[] data, int data_size) {
		byte[] ret = process(data, data_size) ;
		for(byte b : ret)
			ret_binary.add(b) ;
	}
	
	/**
	 * 암/복호화 대상Data을 반복적으로 추가하기
	 * init()를 먼저 한 후, append()를 반복적으로 호출하고, 반드시 finish()로 마무리한다.
	 * @param data		추가할 Data
	 */
	public void append(byte[] data) {
		byte[] ret = process(data, data.length) ;
		for(byte b : ret)
			ret_binary.add(b) ;
	}
	
	/**
	 * 암/복호화을 반복적으로 하기
	 * init()를 먼저 한 후, process()를 반복적으로 호출하고, 반드시 finish()로 마무리한다. 
	 * @param data		암/복호화할 Data
	 * @param data_size	암/복호화할 Data 길이
	 * @return 암/복호화된 결과
	 */
	public byte[] process(byte[] data, int data_size) {
		if (roundKey.length == 0)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		
		if (data_size <= 0)			return new byte[0] ;
		
		if(remain_data == null)
			remain_data = new ArrayList<Byte>();
		
		if (isEncrypt) {
			byte[] ret = new byte[((remain_data.size() + data_size) / _BLOCK_SIZE) * _BLOCK_SIZE] ;
			
			if(ret.length == 0) {	// 한 Block이 못 되면.
				for(int i = 0; i < data_size; ++i)
					remain_data.add(data[i]) ;
				return ret ;
			}
			
			int r_index = 0, d_index = 0 ;
			byte[] temp = new byte[_BLOCK_SIZE] ;
			if(remain_data.size() != 0) {
				int i = 0 ;
				for(byte b : remain_data)
					temp[i++] = b ;

				d_index = _BLOCK_SIZE - remain_data.size() ;
				System.arraycopy(data, 0, temp, remain_data.size(), d_index);
			
				_blockEncrypt(temp, 0, ret, 0) ;
				r_index += _BLOCK_SIZE ;
			}
				
			for(; d_index + _BLOCK_SIZE <= data_size; d_index += _BLOCK_SIZE, r_index += _BLOCK_SIZE)
				_blockEncrypt(data, d_index, ret, r_index) ;
			
			remain_data.clear() ;
			for(int i = d_index; i < data_size; ++i)
				remain_data.add(data[i]) ;
			
			if(ret_binary == null)		return ret ;
			if(ret_binary.size() == 0)	return ret ;
			
			///////////////////////////////////////////////////////////
			// return해야할 ret_binary + 이번 ret 을 합하여 Return
			{
				byte[] ret_buf = new byte[ret_binary.size() + ret.length] ;
				int r = 0; 
				for(byte b : ret_binary)	ret_buf[r++] = b ;
				System.arraycopy(ret, 0, ret_buf, r, ret.length) ;
				ret_binary.clear() ;
				
				return ret_buf ;
			}
		}
		else {	// Decrypt
			int ret_size = (remain_data.size() + data_size - _BLOCK_SIZE) ;	// Last Padding Block를 제외하고,
			int block_size = ret_size / _BLOCK_SIZE ;
			
			if(ret_size < 0 || block_size == 0) {
				for(int i = 0; i < data_size; ++i)
					remain_data.add(data[i]) ;
				return new byte[0] ;
			}
			
			byte[] ret = new byte[block_size * _BLOCK_SIZE] ;
			int i = 0, j = 0;
			for(; i < ret.length && i < remain_data.size(); ++i)
				ret[i] = remain_data.get(i) ;
			
			for(j = 0; i < ret.length && j < data_size;)
				ret[i++] = data[j++] ;
			
			if(remain_data.size() - ret.length > 0) {
				ArrayList<Byte> tmp = new ArrayList<Byte>() ;
				for(int ii = i; ii < remain_data.size(); ++ii)
					tmp.add(remain_data.get(ii)) ;
				remain_data = tmp ;
			}
			else {
				remain_data.clear() ;
			}
			
			for(; j < data_size;)
				remain_data.add(data[j++]) ;
			
			byte[] ret_value = new byte[ret.length] ;
			for(i = 0; i < ret.length; i += _BLOCK_SIZE)
				_blockDecrypt(ret, i, ret_value, i) ;

			if(ret_binary == null)		return ret_value ;
			if(ret_binary.size() == 0)	return ret_value ;
			///////////////////////////////////////////////////////////
			// return해야할 ret_binary + 이번 ret_value 을 합하여 Return
			{
				byte[] ret_buf = new byte[ret_binary.size() + ret_value.length] ;
				int r = 0; 
				for(byte b : ret_binary)	ret_buf[r++] = b ;
				System.arraycopy(ret_value, 0, ret_buf, r, ret_value.length) ;
				ret_binary.clear() ;
			
				return ret_buf ;
			}
		}
	}
	
	/**
	 * 암/복호화을 반복적으로 하기
	 * init()를 먼저 한 후, process()를 반복적으로 호출하고, 반드시 finish()로 마무리한다. 
	 * @param data		암/복호화할 Data
	 * @return 암/복호화된 결과
	 */
	public byte[] process(byte[] data) {
		return process(data, data.length) ;
	}

	/**
	 * 암/복호화을 마무리하기
	 * init()를 먼저 한 후, process()/append()를 반복적으로 호출하고, 반드시 finish()로 마무리한다.
	 * 복호화시 ZEEDException의 오류코드가 SEED_PADDING_ERROR 발생하면, 비밀번호를 다시 확인한다.
	 * SEED_CIPHER_LENGTH_ERROR가 발생하면, 복호화 Data가 16의 배수가 아닌 경우이다.
	 * @return 암/복호화된 결과 (append()한 경우 누적된 결과이다.)
	 */
	public byte[] finish() {
		if(remain_data == null)	return new byte[0] ;
		
		byte[] last = null ;
		
		if(isEncrypt) {
			byte[] last_buffer = new byte[remain_data.size()] ;
			for(int i = 0; i < last_buffer.length; ++i)
				last_buffer[i] = remain_data.get(i) ;
			
			last = Padding(last_buffer, last_buffer.length, _BLOCK_SIZE) ;
			
			_blockEncrypt(last, 0, last, 0) ;
		}
		else {
			if(remain_data.size() != _BLOCK_SIZE)	throw new ZEEDException(Error.CIPHER_LENGTH, "cipher length % 16 != 0") ;
			
			byte[] temp = new byte[_BLOCK_SIZE] ;
			int i = 0;
			for(byte b : remain_data)
				temp[i++] = b ;
			_blockDecrypt(temp, 0, temp, 0) ;
			
			int padding_count = _GetPaddingCount(temp) ;
			last = new byte[temp.length - padding_count] ;
			System.arraycopy(temp, 0, last, 0, last.length) ;
		}
		
		if(ret_binary == null)		return last ;
		if(ret_binary.size() == 0)	return last ;
		
		byte[] ret = new byte[ret_binary.size() + last.length] ;
		int i = 0; 
		for(byte b : ret_binary)	ret[i++] = b ;
		System.arraycopy(last, 0, ret, i, last.length) ;
		ret_binary.clear() ;
		return ret ;
	}
	
	/**
	 * 암호화하기
	 * @param plain	암호화할 대상(평문)
	 * @return 암호화된 결과(암호문)
	 */
	public byte[] encrypt(byte[] plain)
	{
		if (roundKey.length == 0)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		if (plain == null)			return null ;
		if (plain.length == 0)		return new byte[0] ;
		
		init(Action.ENCRYPT) ;
		
		byte[] data = Padding(plain, plain.length, _BLOCK_SIZE) ;
		for(int i = 0; i < data.length; i += _BLOCK_SIZE)
			_blockEncrypt(data, i, data, i) ;
		
		return data ;
	}

	public byte[] encrypt(byte[] plain, String userKey) throws ZEEDException {
		this.setUserKey(userKey) ;
		return this.encrypt(plain) ;
	}
	
	public byte[] encrypt(byte[] plain, byte[] userKey) throws ZEEDException {
		this.setUserKey(userKey) ;
		return this.encrypt(plain) ;
	}
	
	public void encrypt(InputStream is, OutputStream os) throws ZEEDException, IOException {
		if (roundKey.length == 0)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;

		init(Action.ENCRYPT) ;
		
//		byte[] buffer = new byte[4096] ;
//		for(int read_byte_count = 0; (read_byte_count = is.read(buffer)) > 0;)
//			os.write(this.process(buffer, read_byte_count)) ;
//		os.write(this.finish()) ;
		
		byte[] buffer = new byte[_BLOCK_SIZE] ;
		int read_byte_count = 0 ;
		int i = 0;
		for(;(read_byte_count = is.read(buffer)) == _BLOCK_SIZE; ++i) {
			_blockEncrypt(buffer, 0, buffer, 0) ;
			os.write(buffer) ;
		}

		if(read_byte_count <= 0) {
			if(i == 0)	return ;	// empty inputstream
			read_byte_count = 0 ;
		}
		
		buffer = Padding(buffer, read_byte_count, _BLOCK_SIZE) ;
		_blockEncrypt(buffer, 0, buffer, 0) ;
		os.write(buffer) ;
		os.flush();
	}
	
	public void encrypt(InputStream is, OutputStream os, String userKey) throws ZEEDException, IOException {
		this.setUserKey(userKey) ;
		this.encrypt(is, os) ;
	}
	
	public void encrypt(InputStream is, OutputStream os, byte[] userKey) throws ZEEDException, IOException {
		this.setUserKey(userKey) ;
		this.encrypt(is, os) ;
	}
	
	private static byte[] _GetKeyBytes(String userKey, int size) {
		byte[] uk = userKey.getBytes() ;
		for(int i = 0; i < uk.length; ++i) {
			if (uk[i] <= 0x20 || uk[i] >= 0x7F)
				throw new ZEEDException(Error.KEY_IS_ONLY_ASCII, "userKey is not ascii character") ;
		}
		return (uk.length == size) ? uk : PaddingZero(uk, uk.length, size) ;
	}
	
	public static String Encode(byte[] binary, EncodingTable encodingTable) {
		if(encodingTable == null)	return Base62.encode(binary) ;
		
		String table = encodingTable.table();
		switch(table.length())
		{
		case 16 :	// nibble(2^4:16) 단위 encoding
					{
						StringBuffer ret = new StringBuffer(binary.length * 2) ;
						for(int i = 0; i < binary.length; ++i) {
							ret.append(table.charAt((binary[i] >> 4) & 0x0F)) ;
							ret.append(table.charAt((binary[i] >> 0) & 0x0F)) ;
						}
						return ret.toString() ;
					}
		case 64 :
		case 65 :	// 6 bit 단위 encoding
					{
						char padding = (table.length() == 65) ? table.charAt(64) : (char)0x00 ;
						int ret_size = (binary.length / 3 * 4) ;
						if (binary.length % 3 != 0) {
							if(padding != (char)0x00)
								ret_size += 4 ;
							else
								ret_size += (binary.length % 3) + 1 ;
						}
						
						StringBuffer ret = new StringBuffer(ret_size) ;
						int value = 0;
						for(int i = 0; i < binary.length; ++i) {
							switch (i % 3) {
							case 0 :
									value = (binary[i] >> 2) & 0x3F ;
									ret.append(table.charAt(value)) ;
									
									value = (binary[i] & 0x03) << 4 ;
									
									if(i+1 == binary.length) {
										ret.append(table.charAt(value)) ;
										if(padding != (char)0x00) {
											ret.append((char)padding) ;
											ret.append((char)padding) ;
										}
										return ret.toString() ;
									}
									break ;
									
							case 1 :
									value |= (binary[i] >> 4) & 0x0F ;
									ret.append(table.charAt(value)) ;
									
									value = (binary[i] & 0x0F) << 2 ;
									
									if(i+1 == binary.length) {
										ret.append(table.charAt(value)) ;
										if(padding != (char)0x00) {
											ret.append((char)padding) ;
										}
										return ret.toString() ;
									}
									break ;
									
							case 2 :
									value |= (binary[i] >> 6) & 0x03 ;
									ret.append(table.charAt(value)) ;
									
									value = binary[i] & 0x3F ;
									ret.append(table.charAt(value)) ;
									break ;
							}
						}
						return ret.toString() ;
					}
		case 85 :
					{
						int tuple = 0 ;
						int count = 0 ;
						byte[] buf = new byte[5];
						StringBuffer ret = new StringBuffer() ;
						for(int off = 0; off < binary.length; ++off) {
							switch(count++) {
							case 0 : tuple |= ((binary[off] & 0xFF) << 24);	break;
							case 1 : tuple |= ((binary[off] & 0xFF) << 16);	break;
							case 2 : tuple |= ((binary[off] & 0xFF) <<  8);	break;
							case 3 : tuple |= ((binary[off] & 0xFF) <<  0);
									if((encodingTable == EncodingTable.ASCII85_ADOBE) && tuple == 0) {	// Use Null Compression
										ret.append('z');
									} else if((encodingTable == EncodingTable.ASCII85_ADOBE) && tuple == 0x20202020) {
										ret.append('y');
									} else {
										long longTuple = 0 | (tuple & 0xffffffffL);
										for(int i = 4; i >= 0; --i, longTuple /= 85)
											buf[i] = (byte)(longTuple % 85);

										for(int i = 0; i <= 4; ++i)
											ret.append(table.charAt(buf[i])) ;
									}
									tuple = 0;
									count = 0 ;
									break ;
							}
						}
						
						if(count > 0) {
							long longTuple = 0 | (tuple & 0xffffffffL);
							for(int i = 4; i >= 0; --i, longTuple /= 85)
								buf[i] = (byte)(longTuple % 85) ;
							
							for(int i = 0; i <= count; ++i)
								ret.append(table.charAt(buf[i])) ;
						}
						
						return ret.toString() ;
					}
		default :
					{
						throw new ZEEDException(Error.CANNOT_SUPPORT_ENCODING_TABLE) ;
					}
		}
	}
	
	public static byte[] Decode(String str, EncodingTable encodingTable) {
		if(encodingTable == null)	return Base62.decode(str) ;
			
		int value = 0x00;
		int bit_count = 0 ;
		int remain_bit = 0 ;
		int bit_size = 0 ;
		
		String table = encodingTable.table() ;
		switch(table.length())
		{	
		case 16 :	bit_size = 4 ;	break ;	// nibble(2^4:16) 단위 decoding
		case 64 :
		case 65 :	bit_size = 6 ;	break ;
		case 85 :					break ;
		default :	throw new ZEEDException(Error.CANNOT_SUPPORT_ENCODING_TABLE) ;
		}

		switch(table.length())
		{
		case 16 :
		case 64 :
		case 65 :
					{
						int found_index = -1 ;
						ByteBuffer bb = ByteBuffer.allocate(str.length());
						for (char ch : str.toCharArray()) {
							found_index = table.indexOf(ch) ;
							if (found_index == -1) {
								if(Character.isWhitespace(ch))	continue ;
								
								switch(encodingTable) {
								case HEXA_LARGE	:	found_index = EncodingTable.HEXA_SMALL.table().indexOf(ch) ;	break ;
								case HEXA_SMALL	:	found_index = EncodingTable.HEXA_LARGE.table().indexOf(ch) ;	break ;
								default			:	break ;
								}
								
								if(found_index == -1)
									throw new ZEEDException(Error.INVALID_DECODING_CHARACTER, "cannot support decoding character") ;
							}
							
							if (found_index == 64)	break ;
							
							bit_count += bit_size ;
							value <<= bit_size ;
							value |= found_index ;

							if (bit_count >= 8) {
								remain_bit = bit_count - 8 ;
								bb.put((byte)((value >> remain_bit) & 0xFF)) ;
								value &= (1 << remain_bit) - 1 ;
								bit_count -= 8 ;
							}
						}
						
						byte[] binary = new byte[bb.position()] ;
						bb.flip() ;
						bb.get(binary) ;
						return binary ;
					}
		case 85 :
					{
						long[] POW85 = { 85 * 85 * 85 * 85, 85 * 85 * 85, 85 * 85, 85, 1 } ;
						int bytes = 0 ;
						long tuple = 0L ;
						ByteBuffer bb = ByteBuffer.allocate(str.length());
						for (char ch : str.toCharArray()) {
							if(Character.isWhitespace(ch))	continue ;
							
							if(bytes == 0 && encodingTable == EncodingTable.ASCII85_ADOBE) {
								if(ch == 'y')  {
									for(int i = 0; i < 4; ++i)
										bb.put((byte)0x20) ;
									continue ;
								}
								if(ch == 'z') {
									for(int i = 0; i < 4; ++i)
										bb.put((byte)0x00) ;
									continue ;
								}
							}

							int b = table.indexOf(ch) ;
							if(b < 0)	throw new IllegalArgumentException("Illegal ascii85 character 0x" + Integer.toString(ch, 16));

							tuple += b * POW85[bytes] ;
							if(++bytes == 5) {
								bb.put((byte)((tuple >> 24) & 0xFF)) ;
								bb.put((byte)((tuple >> 16) & 0xFF)) ;
								bb.put((byte)((tuple >>  8) & 0xFF)) ;
								bb.put((byte)((tuple >>  0) & 0xFF)) ;
								tuple = 0 ;
								bytes = 0 ;
							}
						}

						if(bytes > 0) {
							for(int i = bytes; i < 5; ++i) {
								tuple += 84 * POW85[i] ;	
							}
							for(int i = 1; i < bytes; ++i) {
								bb.put((byte)((tuple >> (24 - (i-1) * 8)) & 0xFF)) ;
							}
						}
						
						byte[] binary = new byte[bb.position()] ;
						bb.flip() ;
						bb.get(binary) ;
						return binary ;
					}
		default :	throw new ZEEDException(Error.CANNOT_SUPPORT_ENCODING_TABLE) ;
		}

	}

	/**
	 * 암호화하기
	 * @param plain			암호화할 대상(평문)
	 * @param userKey		암호화키
	 * @return Base62처리된 암호화된 결과(암호문)  [ https://github.com/zhangsob/Base62/ ]
	 */
	public String encrypt(String plain, String userKey) {
		return encrypt(plain, userKey, Charset.defaultCharset(), null) ;
	}
	
	/**
	 * 암호화하기
	 * @param plain			암호화할 대상(평문)
	 * @param userKey		암호화키
	 * @param charset		암호화는 Binary 기준이므로 plain의 Charset를 설정한다. 
	 * @return Base62처리된 암호화된 결과(암호문)  [ https://github.com/zhangsob/Base62/ ]
	 */
	public String encrypt(String plain, String userKey, Charset charset) {
		return encrypt(plain, userKey, charset, null) ;
	}
	
	/**
	 * 암호화하기
	 * @param plain			암호화할 대상(평문)
	 * @param userKey		암호화키
	 * @param charset		암호화는 Binary 기준이므로 plain의 Charset를 설정한다. 
	 * @param encodingTable	암호화된 결과도 Binary이므로 String만들 encoding하는 방식
	 * @return 암호화된 결과(암호문)
	 */
	public String encrypt(String plain, String userKey, Charset charset, EncodingTable encodingTable) {
		this.setUserKey(userKey) ;
		byte[] cipher = encrypt(plain.getBytes(charset == null ? Charset.defaultCharset() : charset));
		return Encode(cipher, encodingTable) ;
	}
	
	public byte[] decrypt(byte[] cipher, String userKey) {
		this.setUserKey(userKey) ;
		return this.decrypt(cipher) ;
	}
	
	public byte[] decrypt(byte[] cipher, byte[] userKey) {
		this.setUserKey(userKey) ;
		return this.decrypt(cipher) ;
	}
	
	public void decrypt(InputStream is, OutputStream os) throws ZEEDException, IOException {
		if (roundKey.length == 0)	throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		
		init(Action.DECRYPT) ;
		
//		byte[] buffer = new byte[4096] ;
//		for(int read_byte_count = 0; (read_byte_count = is.read(buffer)) > 0;)
//			os.write(this.process(buffer, read_byte_count)) ;
//		os.write(this.finish()) ;
		
		byte[] buffer = new byte[_BLOCK_SIZE] ;
		byte[] plain = new byte[_BLOCK_SIZE] ;
		int read_byte_count = 0 ;
		int i = 0 ;
		for(; (read_byte_count = is.read(buffer)) == _BLOCK_SIZE; ++i) {
			if(i != 0)	os.write(plain) ;
			_blockDecrypt(buffer, 0, plain, 0) ;
		}

		if(read_byte_count <= 0) {
			if(i == 0)	return ;	// empty inputstream
			read_byte_count = 0 ;
		}
		
		if(read_byte_count > 0)		throw new ZEEDException(Error.CIPHER_LENGTH, "cipher length % 16 != 0") ;
		
		os.write(plain, 0, _BLOCK_SIZE - _GetPaddingCount(plain)) ;
		os.flush();
	}
	
	public void decrypt(InputStream is, OutputStream os, String userKey) throws ZEEDException, IOException {
		this.setUserKey(userKey) ;
		this.decrypt(is, os) ;
	}
	
	public void decrypt(InputStream is, OutputStream os, byte[] userKey) throws ZEEDException, IOException {
		this.setUserKey(userKey) ;
		this.decrypt(is, os) ;
	}
	
	private int _GetPaddingCount(byte[] data)
	{
		int padding_count = 0 ;
		switch(this.padding)
		{
		case BIT :
					for(int i = 0; i < data.length; ++i) {
						byte b = data[data.length-1-i] ;
						if(b == 0x00)	continue ;
						
						if(b == (byte)0x80)
							padding_count = i+1 ;
						
						break ;
					}
					break ;
					
		case PKCS7 :
		case X923  :
					padding_count = data[data.length-1] & 0xFF ;
					break ;
		}
		
		if(padding_count < 1) {
			if(is(Option.DECRYPT_EMPTY_PADDING_OK))
				padding_count = 0 ;
			else
				throw new ZEEDException(Error.PADDING, "padding_count < 1") ;	// 복호화키가 틀린 경우
		}
		
		if(padding_count > 16) {
			if(is(Option.DECRYPT_EMPTY_PADDING_OK))
				padding_count = 0 ;
			else
				throw new ZEEDException(Error.PADDING, "padding_count > 16") ;	// 복호화키가 틀린 경우
		}
						
		switch(this.padding)
		{
		case BIT  :
					break ;
		case PKCS7: 
					for(int i = 0; i < padding_count; ++i) {
						if(padding_count != data[data.length - (1 + i)])
							throw new ZEEDException(Error.PADDING, "padding mismatch") ;	// 복호화키가 틀린 경우
					}
					break ;
					
		case X923 :
					for(int i = 1; i < padding_count; ++i) {
						if(0x00 != data[data.length - (1 + i)])
							throw new ZEEDException(Error.PADDING, "padding mismatch") ;	// 복호화키가 틀린 경우
					}
					break ;
		}
		
		if(padding_count == 0 && is(Option.DECRYPT_EMPTY_PADDING_OK) == false)
			throw new ZEEDException(Error.EMPTY_PADDING) ;
		
		return padding_count ;
	}
	
	/**
	 * 복호화하기(Binary to Binary)
	 * @param cipher	복호화할 대상(암호문)
	 * @return 복호화된 결과(평문)
	 */
	public byte[] decrypt(byte[] cipher) {
		if (cipher == null)						return null ;
		if (cipher.length == 0)					return new byte[0] ;
		
		if (roundKey.length == 0)				throw new ZEEDException(Error.KEY_LENGTH, "userKey length is zero") ;
		if ((cipher.length % _BLOCK_SIZE) != 0)	throw new ZEEDException(Error.CIPHER_LENGTH, "cipher length % 16 != 0") ;

		init(Action.DECRYPT) ;
		
		byte[] data = new byte[cipher.length] ;
		for(int i = 0; i < cipher.length; i += _BLOCK_SIZE)
			_blockDecrypt(cipher, i, data, i) ;
		
		int padding_count = _GetPaddingCount(data) ;
		
		byte[] ret = new byte[data.length - padding_count] ;
		System.arraycopy(data, 0, ret, 0, ret.length);
		
		return ret ;
	}

	/**
	 * 복호화하기(String to String)
	 * @param cipher		복호화할 암호문 Data [ Base62처리된 ( https://github.com/zhangsob/Base62/ ) ]
	 * @param userKey		복호화키 (암호화키와 동일)
	 * @return 				복호화된 Data(즉, 원문)
	 */
	public String decrypt(String cipher, String userKey) {
		return decrypt(cipher, userKey, Charset.defaultCharset(), null) ;
	}
	
	/**
	 * 복호화하기(String to String)
	 * @param cipher		복호화할 암호문 Data [ Base62처리된 ( https://github.com/zhangsob/Base62/ ) ]
	 * @param userKey		복호화키 (암호화키와 동일)
	 * @param charset		암호화시 한글 Charset
	 * @return 				복호화된 Data(즉, 원문)
	 */
	public String decrypt(String cipher, String userKey, Charset charset) {
		return decrypt(cipher, userKey, charset, null) ;
	}

	/**
	 * 복호화하기(String to String[한글])
	 * @param cipher		복호화할 암호문 Data
	 * @param userKey		복호화키 (암호화키와 동일)
	 * @param charset		암호화시 한글 Charset
	 * @param encodingTable	암호화시 Binary를 String화 Encoding Table
	 * @return				복호화된 Data(즉, 원문)
	 */
	public String decrypt(String cipher, String userKey, Charset charset, EncodingTable encodingTable) {
		this.setUserKey(userKey) ;
		byte[] _plain = this.decrypt(Decode(cipher, encodingTable)) ;
		return new String(_plain, charset == null ? Charset.defaultCharset() : charset) ;
	}
}

