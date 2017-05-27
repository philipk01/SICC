package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import java.util.Arrays;
import javax.smartcardio.*;
import java.io.*;
import java.security.*;


public class Client {

	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private static final short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private static final int  SUCCESS_RESPONS = 36864;
	
	private final static byte GET_SERIAL_INS= 0x24;
	
	//INS codes for different SPs
	private final static byte GET_eGov_DATA=(byte)0x05;
//	private final static byte GET_Health_DATA=(byte)0x06;	
//	private final static byte GET_SN_DATA=(byte)0x07;
//	private final static byte GET_def_DATA=(byte)0x08;
	//	timestamp implementation to be discussed
	//private final static byte GET_TS_DATA=(byte)0x09;
	private static byte REQ_VALIDATION_INS=(byte)0x16;
	
	//individuals identified by a service-specific pseudonym
	private  byte[] nym_Gov = new byte[]{0x11}; // to have something to test data saving on javacard
	private byte[] nym_Health = new byte[]{0x12}; // to have something to test data saving on javacard
	private byte[] nym_SN = new byte[]{0x13}; // to have something to test data saving on javacard
	private byte[] nym_def = new byte[]{0x14}; // to have something to test data saving on javacard
	
	private byte[] name;
	private byte[] address;
	private byte[] country;
	private byte[] birthdate;
	private byte[] age;
	private byte[] gender;
	private byte[] picture;
	private byte[] bloodType;
	
	//Certificates and Keys
	private final static byte CertC0=(byte)0x20;	//common cert
	private final static byte SKC0=(byte)0x21;
	private final static byte CertCA=(byte)0x22;	//CA
	private final static byte CertG=(byte)0x23;	//cert for gov timestam
	private final static byte SKG=(byte)0x24;
	private final static byte CertSP=(byte)0x25;	//cert in each domain
	private final static byte SKsp=(byte)0x26;
	private final static byte Ku=(byte)0x27;
	private final static byte PKG=(byte)0x28;
	
	/**
	 * @param args
	 */
	
	static TSClient TS = new TSClient();
	
	public static void main(String[] args) throws Exception {
		IConnection c;
		boolean simulation = true;		// Choose simulation vs real card here

		if (simulation) {
			//Simulation:	
			c = new SimulatedConnection();
		} else {
			//Real Card:
			c = new Connection();
			((Connection)c).setTerminal(0); //depending on which cardreader you use
		}
		
		c.connect(); 
		
		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */
			
			CommandAPDU a;
			ResponseAPDU r;
			
			if (simulation) {
				//0. create applet (only for simulator!!!)
				//Constructs a CommandAPDU from the four header bytes, command data, and expected response data length. (see link above)
				// 0x7f = 127 in decimal
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("select installer applet failed");
				
				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Applet creation failed");
				
				//1. Select applet  (not required on a real card, applet is selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Applet selection failed");
			}
			
//Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW()==SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=SUCCESS_RESPONS ) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
			
			
//Send time to card, receive boolean
//			//In progress...
//			//first step to get signed time from G then pass it along
//			//SSLServerThread st = new SSLServerThread();//tried this but...
//			String timeResponse = TS.getTime("a");
//			System.out.println("Recieved Time: " + timeResponse);
//			//the card needs to handle singed time from client
//			
//			byte[] signedTime = "SignedTime".getBytes("ASCII");
//			a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_VALIDATION_INS, 0x00, 0x00, signedTime); 
//			r = c.transmit(a); 
//			System.out.println("\nsigned Data - HEX: "+toHex(signedTime));
//			// checkSW(response); 
//
//			byte[] signature = r.getData();
//			//get time from Server
// 
//			//certificate handling
//			//the card needs to handle singed time from client
//			byte[] signedData = "SignedTime".getBytes("ASCII");
//			a = new CommandAPDU(IDENTITY_CARD_CLA, REQ_VALIDATION_INS, 0x00, 0x00, signedData); 
//			r = c.transmit(a); 
//			System.out.println("\nsigned Data - HEX: "+toHex(signedData));
//			// checkSW(response); 
//
//			signature = r.getData();
//			System.out.println();
//			System.out.printf("Signature from card: %s\n", toHex(signature));
            
// get Serial#, example to get data from card
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00);
			r = c.transmit(a);
//			
			byte[] b = r.getData();
			byte[] s = new byte[r.getNr()-6]; //number of data bytes in the response body - 6 padding bytes
			//check padding of data bytes, what are the extra bytes?
			for(int i=6; i <b.length; i++){
				s[i-6] = (byte)b[i];
			}
			System.out.println(b.length);
			System.out.println(Arrays.toString(s));


//eGov data
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_eGov_DATA, 0x00, 0x00);
			r = c.transmit(a);
			
			byte[] g =r.getData();
			char[] h = new char[r.getNr()]; //number of data bytes in the response body
			
			for(int i=6; i <g.length; i++){
			h[i-6] = (char)g[i]; //creating a variable able to be operated on
			}
			System.out.print("Gov Data: ");
			System.out.println(h); //test implementation
				
			}
		
		finally {
			System.out.println("\n------ end connection ------");
			c.close();  // close the connection with the card
		}
	}
	
//	public static Signature getSig(Signature){
//		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false) ; //OR ALG_RSA_SHA_512_PKCS1
//		signature.initSign(privateKey, Signature.M);
//	}
	
    public static String toHex(byte[] bytes) { 
        StringBuilder buff = new StringBuilder(); 
        for (byte b : bytes) { 
            buff.append(String.format("%02X", b)); 
        } 
        return buff.toString(); 
    } 
	
}
	