package zeed;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

class SEEDTest {
	boolean equals(byte[] a, byte[] b) {
		if(a.length != b.length)	return false ;
		for(int i = 0; i < a.length; ++i)
			if(a[i] != b[i])
				return false ;
		return true ;
	}
	
	//@Test
	void OptionTest() {
		String plain_text = "1234123412341234" ;
		String userKey = "1234" ;
		{
			SEED.Mode mode = SEED.Mode.CTR ;
			SEED.Bit bit = SEED.Bit.SEED256 ;
			SEED.Padding padding = SEED.Padding.BIT;
			SEED seed = new SEED(mode, bit, padding);
			
			{
				seed.option(SEED.Option.DECRYPT_EMPTY_PADDING_OK) ;
				SEED.EncodingTable table = SEED.EncodingTable.HEXA_LARGE ;
				//System.out.println(" plain_text:"+ plain_text) ;
				String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("UTF-8"), table) ;
				cypher_text = cypher_text.substring(0, cypher_text.length() - 32) ;	// EMPTY PADDING
				//System.out.println("cypher_text["+cypher_text.length()+"]:"+ cypher_text) ;
				table = SEED.EncodingTable.HEXA_SMALL ;
				//System.out.println(" plain_text="+ seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)) ;
				assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)), "string2string UTF-8 BASE64URL should return 'true'");
			}
		}
	}
	
	//@Test 
	void binary2binary() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		byte[] plain_text = "1234한글".getBytes() ;
		byte[] ciper_text = seed.encrypt(plain_text) ;
		assertTrue(equals(seed.decrypt(ciper_text), plain_text), "binary2binary should return 'true'");
	}
	
	//@Test
	void binary2binary2() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		
		StringBuffer sb = new StringBuffer() ; 
		seed.init(SEED.Action.ENCRYPT); 
		for(int i = 0; i < 10; ++i) {
			String tmp = String.format("1234한글%d\n", i) ;
			sb.append(tmp) ;
			seed.append(tmp.getBytes()) ;
		}
		byte[] ciper_text = seed.finish() ;
		
		assertTrue(sb.toString().equals(new String(seed.decrypt(ciper_text))), "binary2binary2 should return 'true'");
	}
	
	//@Test
	void string2string() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		String userKey = "1234" ;
		String plain_text = "1234한글%d." ;
		{
			String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("UTF-8")) ;
			assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"))), "string2string UTF-8 should return 'true'");
		}
		{
			String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("EUC-KR")) ;
			assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("EUC-KR"))), "string2string EUC-KR should return 'true'");
		}
		{
			String cypher_text = seed.encrypt(plain_text, userKey) ;
			assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey)), "string2string. should return 'true'");
		}
	}
	
	//@Test
	void string2stringFullTest() {
		
		for(int i = 0; i < 100; ++i) {
			String plain_text = String.format("ABCDabcd1234한글%d.", i) ;
			for(int k = 0; k < 1000; ++k)
			{
				String userKey = "" + k ;	//1234" ;
				for(SEED.Mode mode : SEED.Mode.values())
				for(SEED.Bit bit : SEED.Bit.values())
				for(SEED.Padding padding : SEED.Padding.values())
				{
					SEED seed = new SEED(mode, bit, padding);
					for(SEED.EncodingTable table : SEED.EncodingTable.values()) {
						//if(mode == SEED.Mode.CTR && bit == SEED.Bit.SEED_256 && padding == SEED.Padding.PKCS7 && table == SEED.EncodingTable.BASE64URL)	continue ;	// 일단 Skip
						//System.out.println("----SEED("+mode+","+bit+","+padding+")---------"+table+"-------------") ;
						String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("UTF-8"), table) ;
						//System.out.println(" plain_text:"+ plain_text) ;
						//System.out.println(i + " cypher_text["+cypher_text.length()+"]:"+ cypher_text) ;
						//System.out.println(" plain_text="+ seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)) ;
						assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)),
									String.format("string2stringFullTest (%s %s) should return 'true'",
											seed, table
									));
					}
					{
						//System.out.println("----SEED("+mode+","+bit+","+padding+")----------------------") ;
						String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("UTF-8")) ;
						//System.out.println(" plain_text:"+ plain_text) ;
						//if(k == 0)	System.out.println(i + " cypher_text["+cypher_text.length()+"]:"+ cypher_text) ;
						//System.out.println(" plain_text="+ seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)) ;
						assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"))), 
									String.format("string2stringFullTest (%s) should return 'true'",
											seed
									));
					}
				}
			}
		}
	}
	
	//@Test
	void EmptyTest() {
		String plain_text = "" ;
		String userKey = "0" ;
		{
			SEED.Mode mode = SEED.Mode.ECB ;
			SEED.Bit bit = SEED.Bit.SEED128 ;
			SEED.Padding padding = SEED.Padding.X923;
			SEED seed = new SEED(mode, bit, padding);
			
			{
				SEED.EncodingTable table = SEED.EncodingTable.HEXA_LARGE ;
				System.out.println(" plain_text:"+ plain_text) ;
				String cypher_text = seed.encrypt(plain_text, userKey, Charset.forName("UTF-8"), table) ;
				System.out.println("cypher_text["+cypher_text.length()+"]:"+ cypher_text) ;
				System.out.println(" plain_text="+ seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)) ;
				assertTrue(plain_text.equals(seed.decrypt(cypher_text, userKey, Charset.forName("UTF-8"), table)), "BugFix UTF-8 BASE64URL should return 'true'");
			}
		}
	}
	
	//@Test
	void fileEncrypt() {
		byte[] tmp = new byte[100] ;
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		seed.init(SEED.Action.ENCRYPT) ;
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt")) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg"))) {
			for(int read_byte_count = 0; (read_byte_count = fis.read(tmp)) > 0;)
				fos.write(seed.process(tmp, read_byte_count)) ;
			fos.write(seed.finish()) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("fileEncrypt ms : " + (System.currentTimeMillis() - start)) ;
	}

	//@Test
	void emptyFileEncrypt() {
		byte[] tmp = new byte[100] ;
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		seed.init(SEED.Action.ENCRYPT) ;
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/empty.txt.encrypt")) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/empty.txt")) ;
		) {
			for(int read_byte_count = 0; (read_byte_count = fis.read(tmp)) > 0;)
				fos.write(seed.process(tmp, read_byte_count)) ;
			fos.write(seed.finish()) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("emptyFileEncrypt ms : " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void fileDecrypt(){
		byte[] tmp = new byte[256] ;
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		seed.init(SEED.Action.DECRYPT) ;
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt.decrypt")) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt")) ;
		) {
			for(int read_byte_count = 0; (read_byte_count = fis.read(tmp)) > 0;)
				fos.write(seed.process(tmp, read_byte_count)) ;
			fos.write(seed.finish()) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("fileDecrypt ms : " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void emptyFileDecrypt(){
		byte[] tmp = new byte[256] ;
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		seed.init(SEED.Action.DECRYPT) ;
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/empty.txt.16.encrypt.decrypt")) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/empty.txt.16.encrypt")) ;
		) {
			for(int read_byte_count = 0; (read_byte_count = fis.read(tmp)) > 0;)
				fos.write(seed.process(tmp, read_byte_count)) ;
			fos.write(seed.finish()) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("emptyFileDecrypt ms : " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void emptyFileEncrypt2() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/empty.txt.encrypt2")) ;
			BufferedOutputStream bos = new BufferedOutputStream(fos) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/empty.txt")) ;
			BufferedInputStream bis = new BufferedInputStream(fis) ;
		) {
			//seed.encrypt(fis, fos) ;
			seed.encrypt(bis, bos) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("emptyFileEncrypt2 ms : " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void emptyfileDecrypt2() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		seed.init(SEED.Action.DECRYPT) ;
		
		long start = System.currentTimeMillis();
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/empty.txt.encrypt2.decrypt")) ;
			BufferedOutputStream bos = new BufferedOutputStream(fos) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/empty.txt.encrypt2")) ;
			BufferedInputStream bis = new BufferedInputStream(fis) ;
		) {
			//seed.decrypt(fis, fos) ;
			seed.decrypt(bis, bos) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("emptyfileDecrypt2 ms = " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void fileEncrypt2() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		long start = System.currentTimeMillis();
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt2")) ;
			BufferedOutputStream bos = new BufferedOutputStream(fos) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg")) ;
			BufferedInputStream bis = new BufferedInputStream(fis) ;
		) {
			//seed.encrypt(fis, fos) ;
			seed.encrypt(bis, bos) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("fileEncrypt2 ms : " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void fileDecrypt2() {
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		seed.init(SEED.Action.DECRYPT) ;
		
		long start = System.currentTimeMillis();
		try(FileOutputStream fos = new FileOutputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt2.decrypt")) ;
			BufferedOutputStream bos = new BufferedOutputStream(fos) ;
			FileInputStream fis = new FileInputStream(new File("C:/temp/20220921KBBK0101100000047001050RC.tif.jpg.encrypt2")) ;
			BufferedInputStream bis = new BufferedInputStream(fis) ;
		) {
			//seed.decrypt(fis, fos) ;
			seed.decrypt(bis, bos) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ZEEDException e) {
			e.printStackTrace();
		}
		System.out.println("fileDecrypt2 ms = " + (System.currentTimeMillis() - start)) ;
	}
	
	//@Test
	void ByteArrayStream() {
		//long start = System.currentTimeMillis();
		File file = new File("C:/temp/20220921KBBK0101100000047001050FC.tif.jpg") ;
		ByteBuffer bb = ByteBuffer.allocate((int)file.length()) ;
		try(FileInputStream fis = new FileInputStream(file) ;
			BufferedInputStream bis = new BufferedInputStream(fis) ;
		) {
			byte[] buf = new byte[256] ;
			for(int read_byte_count = 0; (read_byte_count = bis.read(buf)) > 0;)
					bb.put(buf, 0, read_byte_count) ;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		byte[] plain_text = new byte[bb.position()] ;
		bb.flip() ;
		bb.get(plain_text) ;
		
		SEED seed = new SEED(SEED.Mode.ECB, SEED.Bit.SEED256, SEED.Padding.PKCS7);
		seed.setUserKey("1234");
		
		byte[] ciper_text = null ;
		try(ByteArrayInputStream bais = new ByteArrayInputStream(plain_text);
			ByteArrayOutputStream baos = new ByteArrayOutputStream())
		{
			seed.encrypt(bais, baos) ;
			ciper_text = baos.toByteArray() ;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		byte[] decrypted_text = null ;
		try(ByteArrayInputStream bais = new ByteArrayInputStream(ciper_text);
			ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				seed.decrypt(bais, baos) ;
				decrypted_text = baos.toByteArray() ;
		} catch (IOException e) {
			e.printStackTrace();
		}
		//System.out.println("ms : " + (System.currentTimeMillis() - start)) ;
		assertTrue(equals(decrypted_text, plain_text), "ByteArrayStream should return 'true'");
	}
	
	@Test
	void EncodeDecodeTest()
	{
		String plain_text = "ABCabc123한글" ;
		for(SEED.EncodingTable table : SEED.EncodingTable.values()) {
			String tmp = "" ;
			for(int i = 0; i < 20; ++i) {
				tmp += plain_text ;
				byte[] bin = tmp.substring(0, tmp.length() - i).getBytes() ;
				String txt = SEED.Encode(bin, table) ;
				System.out.println("txt:" + txt) ;
				assertTrue(equals(SEED.Decode(txt, table), bin), "EncodeDecodeTest should return 'true'");
			}
		}
	}
}
