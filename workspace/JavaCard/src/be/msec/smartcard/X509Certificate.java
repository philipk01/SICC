//package be.msec.smartcard;
//
//import java.io.IOException;
////import java.io.UnsupportedEncodingException;
//
//import javacard.framework.ISO7816;
//import javacard.framework.ISOException;
//import javacard.framework.Util;
//import javacard.security.KeyBuilder;
//import javacard.security.MessageDigest;
//import javacard.security.PublicKey;
//import javacard.security.RSAPublicKey;
//import javacardx.crypto.Cipher;
//
//
//
///**
//* This class implements methods for creating X.509 certificates and
//* accessing their attributes such as subject/issuer names, public keys
//* and validity information. Publicly visible methods methods are
//* modeled after those in the X509Certificate classes
//* from J2SE (standard edition) but there are some differences and
//* these are documented below. <P />
//* NOTE: For now, only X.509 certificates containing RSA public keys
//* and signed either using md2WithRSA, md5WithRSA, or sha-1WithRSA are
//* supported.
//* This version of the implementation is unable to parse certificates
//* containing DSA keys or signed using DSA. Certificates containing
//* RSA keys but signed using an unsupported algorithm
//* can be parsed but cannot be verified. Not all version 3 extensions are
//* supported (only subjectAltName, basicConstraints, keyUsage and
//* extendedKeyUsage are recognized) but if an unrecognized
//* extension is marked critical, an error notification is generated.
//* <P />
//*/
//public class X509Certificate {
//
//   /** Indicates a no error condition. */
//   public static final byte NO_ERROR = 0;
//   
//   /** X509Certificate Errors **/
//  public final static short SW_CERT_PARSE_FAILED = 0x6301;
//  public final static short SW_MATCH1_FAILED = 0x6302;
//  public final static short SW_MATCH2_FAILED = 0x6303;
//  public final static short SW_LEN_1_ERROR = 0x6304;
//  public final static short SW_LEN_2_ERROR = 0x6305;
//  public final static short SW_UTCTIME_1_ERROR = 0x6306;
//  public final static short SW_UTCTIME_2_ERROR = 0x6307;
//  public final static short SW_UTCTIME_3_ERROR = 0x6308;
//  public final static short SW_EXTENSIONS_INVALID = 0x6309;
//  public final static short SW_CERT_DATA_INVALID = 0x630A;
//  public final static short SW_CERT_ISSUER_INVALID = 0x630B;
//  public final static short SW_CERT_SUBJECT_INVALID = 0x630C;
//  public final static short SW_CERT_SIG_INVALID = 0x630D;
//  
//  
//   /**
//    * Indicates that no information is available on
//    * the pathLengthConstraint associated with this certificate
//    * (this could happen if the certifiate is a v1 or v2 cert or
//    * a v3 cert without basicConstraints or a non-CA v3 certificate).
//    */
//   public static final short MISSING_PATH_LENGTH_CONSTRAINT = -1;
//   /** Indicates there is no limit to the server certificate chain length. */
//   public static final short UNLIMITED_CERT_CHAIN_LENGTH = 32767;
//
//   /** We expect issuer/subject names to fit within these many bytes. */
//   private static final short MAX_NAME_LENGTH = 300;
//
//   /** ASN ANY_STRING type used in certificate parsing (0x00). */
//   private static final byte ANY_STRING_TYPE = 0x00; // our own impl
//
//   /** ASN INTEGER type used in certificate parsing (0x02). */
//   private static final byte INTEGER_TYPE = 0x02;
//   /** ASN BIT STRING type used in certificate parsing (0x03). */
//   private static final byte BITSTRING_TYPE = 0x03;
//   /** ASN OCTET STRING type used in certificate parsing (0x04). */
//   private static final byte OCTETSTR_TYPE = 0x04;
//   /** ASN OBJECT ID type used in certificate parsing (0x06). */
//   private static final byte OID_TYPE = 0x06;
//   /** ASN UTF8 STRING type used in certificate parsing (0x0c). */
//   private static final byte UTF8STR_TYPE = 0x0c;
//   /** ASN UNICODE STRING type used in certificate parsing (0x12). */
//   private static final byte UNIVSTR_TYPE = 0x12;
//   /** ASN PRINT STRING type used in certificate parsing (0x13). */
//   private static final byte PRINTSTR_TYPE = 0x13;
//   /** ASN TELETEX STRING type used in certificate parsing (0x14). */
//   private static final byte TELETEXSTR_TYPE = 0x14;
//
//   /** ASN IA5 STRING type used in certificate parsing (0x16). */
//   private static final byte IA5STR_TYPE = 0x16; // Used for EmailAddress
//   /** ASN SEQUENCE type used in certificate parsing (0x30). */
//   private static final byte SEQUENCE_TYPE = 0x30;
//   /** ASN SET type used in certificate parsing (0x31). */
//   private static final byte SET_TYPE = 0x31;
//
//   /** Email address (rfc 822) alternative name type code. */
//   public static final byte TYPE_EMAIL_ADDRESS = 1;
//   /** DNS name alternative name type code. */
//   public static final byte TYPE_DNS_NAME = 2;
//   /** URI alternative name type code. */
//   public static final byte TYPE_URI = 6;
//
//   /** Bit mask for digital signature key usage.  */
//   public static final short DIGITAL_SIG_KEY_USAGE = 0x00000001;
//   /** Bit mask for non repudiation key usage. */
//   public static final short NON_REPUDIATION_KEY_USAGE = 0x00000002;
//   /** Bit mask for key encipherment key usage. */
//   public static final short KEY_ENCIPHER_KEY_USAGE = 0x00000004;
//   /** Bit mask for data encipherment key usage. */
//   public static final short DATA_ENCIPHER_KEY_USAGE = 0x00000008;
//   /** Bit mask for key agreement key usage. */
//   public static final short KEY_AGREEMENT_KEY_USAGE = 0x00000010;
//   /** Bit mask for key certificate sign key usage. */
//   public static final short CERT_SIGN_KEY_USAGE = 0x00000020;
//   /** Bit mask for CRL sign key usage. */
//   public static final short CRL_SIGN_KEY_USAGE = 0x00000040;
//   /** Bit mask for encipher only key usage. */
//   public static final short ENCIPHER_ONLY_KEY_USAGE = 0x00000080;
//   /** Bit mask for decipher only key usage. */
//   public static final short DECIPHER_ONLY_KEY_USAGE = 0x00000100;
//
//   /** Bit mask server auth for extended key usage. */
//   public static final short SERVER_AUTH_EXT_KEY_USAGE = 0x00000002;
//   /** Bit mask client auth for extended key usage. */
//   public static final short CLIENT_AUTH_EXT_KEY_USAGE = 0x00000004;
//   /** Bit code signing mask for extended key usage. */
//   public static final short CODE_SIGN_EXT_KEY_USAGE = 0x00000008;
//   /** Bit email protection mask for extended key usage. */
//   public static final short EMAIL_EXT_KEY_USAGE = 0x00000010;
//   /** Bit IPSEC end system mask for extended key usage. */
//   public static final short IPSEC_END_SYS_EXT_KEY_USAGE = 0x00000020;
//   /** Bit IPSEC tunnel mask for extended key usage. */
//   public static final short IPSEC_TUNNEL_EXT_KEY_USAGE = 0x00000040;
//   /** Bit IPSEC user mask for extended key usage. */
//   public static final short IPSEC_USER_EXT_KEY_USAGE = 0x00000080;
//   /** Bit time stamping mask for extended key usage. */
//   public static final short TIME_STAMP_EXT_KEY_USAGE = 0x00000100;
//
//   /**
//    * The validity period is contained in thirteen bytes
//    * yymmddhhmmss followed by 'Z' (for zulu ie GMT), if yy < 50
//    * assume 20yy else 19yy.
//    */
//   private static final short UTC_LENGTH = 13;
//
//   /**
//    * Maps byte codes that follow id-at (0x55 0x04) to corresponding name
//    * component tags (e.g. Commom Name, or CN, is 0x55, 0x04, 0x03 and
//    * Country, or C, is 0x55, 0x04, 0x06). See getName. See X.520 for
//    * the OIDs and RFC 1779 for the printable labels. Place holders for
//    * unknown labels have a 0 as the first byte.
//    */
//   private static final byte[] b1 = { 0 };
//   private static final byte[] b2 = { 0 };
//   private static final byte[] b3 = { 0 };
//   private static final byte[] cn = { 'C', 'N' };
//   private static final byte[] sn = { 'S', 'N' };
//   private static final byte[] b4 = { 0 };
//   private static final byte[] c = { 'C' };
//   private static final byte[] l = { 'l' };
//   private static final byte[] st = { 'S', 'T' };
//   private static final byte[] street = { 'S', 'T', 'R', 'E', 'E', 'T' };
//   private static final byte[] o = { 'O' };
//   private static final byte[] ou = { 'O', 'U' };
//   //private static final byte[][] nameAttr = {b1, b2, b3, cn, sn, b4, c, l , st, street, o , ou};
//   
////          { 0 },
////          { 0 },
////          { 0 },
////           { 'C', 'N' }, // Common name: id-at 3
////           { 'S', 'N' }, // Surname: id-at 4
////           { 0 },
////           { 'C' }, // Country: id-at 6
////           { 'L' }, // Locality: id-at 7
////           { 'S', 'T' }, // State or province: id-at 8
////           { 'S', 'T', 'R', 'E', 'E', 'T' }, // Street address: id-at 9
////           { 'O' }, // Organization: id-at 10
////           { 'O', 'U' }, // Organization unit: id-at 11
////   };
//
//   /** Email attribute label in bytes. "EmailAddress" */
//   private static final byte[] EMAIL_ATTR_LABEL = { 'E', 'm', 'a',
//           'i', 'l', 'A', 'd', 'd', 'r', 'e', 's', 's' };
//
//   /** Email attribute object identifier. */
//   private static final byte[] EMAIL_ATTR_OID = { (byte) 0x2a,
//           (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7,
//           (byte) 0x0d, (byte) 0x01, (byte) 0x09, (byte) 0x01 };
//
//   /** Includes DER encoding for OID 1.2.840.113549.1.1. */
//   private static final byte[] PKCS1Seq = { (byte) 0x30, (byte) 0x0d,
//           (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86,
//           (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d,
//           (byte) 0x01, (byte) 0x01, };
//
//   /*
//    * These signature algorithms are encoded as PKCS1Seq followed by
//    * a single byte with the corresponding value shown below, e.g.
//    * md5WithRSAEncryption OBJECT IDENTIFIER  ::=  {
//    *     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
//    *     pkcs-1(1) 4 
//    * }
//    */
//   /** Uknown algorithm (-1). */
//   private static final byte NONE = -1;
//   /** RAS ENCRYPTION (0x01). */
//   private static final byte RSA_ENCRYPTION = 0x01;
//   
//   /** SHA1_RSA algorithm (0x05). */
//   private static final byte SHA1_RSA = 0x05;
//
//   /**
//    * Expected prefix in decrypted value when SHA-1 hash is used for signing
//    * 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14.
//    */
//   private static final byte[] PREFIX_SHA1 = { (byte) 0x30,
//           (byte) 0x21, (byte) 0x30, (byte) 0x09, (byte) 0x06,
//           (byte) 0x05, (byte) 0x2b, (byte) 0x0e, (byte) 0x03,
//           (byte) 0x02, (byte) 0x1a, (byte) 0x05, (byte) 0x00,
//           (byte) 0x04, (byte) 0x14 };
//
//   /** ASN encoding for NULL. */
//   private static final byte[] NullSeq = { (byte) 0x05, (byte) 0x00 };
//
//   /** This is how the encoding of validity information begins. */
//   private static final byte[] ValiditySeq = { (byte) 0x30,
//           (byte) 0x1e };
//
//   /** This is how the encoding of UTCTime begins. */
//   private static final byte[] UTCSeq = { (byte) 0x17, (byte) 0x0d };
//
//   /** Includes DER encoding for id-kp (key purpose). */
//   private static final byte[] ID_KP = { (byte) 0x2b, (byte) 0x06,
//           (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
//           (byte) 0x03 };
//
//   /** True iff subject matches issuer. */
//   private boolean selfSigned;
//   /** X.509 version. For more readable code the version field starts a 1. */
//   private byte version = 1;
//   /** MD5 fingerprint of the certificate. */
//   private byte[] fp = null;
//   /** Certificate serial number. */
//   private byte[] serialNumber;
//   /** Certificate subject. */
//   private byte[] subject;
//   /** Certificate issuer. */
//   private byte[] issuer;
//   /** Beginning of certificate validity period. */
//   private Date from;
//   /** End of certificate validity period. */
//   private Date until;
//   /** Certificate RSA Public key. */
//   private RSAPublicKey pubKey = null;
//
//   /** Index inside encoding. */
//   private short idx = 0;
//   /** Contains Certificate DER encoding. */
//   private byte[] enc = null;
//   /** Offset where TBSCertificate starts. */
//   private short TBSStart = 0;
//   /** Length of TBSCertificate. */
//   private short TBSLen = 0;
//   /** Algorithm used to sign the cert. */
//   private byte sigAlg = NONE;
//   /** Issuer signature on certificate. */
//   private byte[] signature = null;
//   /**  Hash of TBSCertificate. */
//   private byte[] TBSCertHash = null;
//   /**  True iff cert has unrecognized critical extension. */
//   private boolean badExt = false;
//   /**  Alternate name. */
//
//   /** format of the subject alternative name, 2 means a DNS name */
//   private byte subAltNameType;
//   /** subject alternative name */
//   private Object subAltName;
//   /** does the cert include BasicConstaints. */
//   private boolean hasBC = false;
//   /** CA value in BasicConstraints. */
//   private boolean isCA = false;
//   /** Path Length constriant from Basic constraints. */
//   private short pLenConstr = MISSING_PATH_LENGTH_CONSTRAINT;
//   /** Collection of keyUsage bits. */
//   private short keyUsage = -1;
//   /** Collection of extended keyUsage bits. */
//   private short extKeyUsage = -1;
//
//   /** Private constructor */
//   public X509Certificate() {
//   }
//
//   /**
//    * Matches the contents of buf against this certificates DER
//    * encoding (enc) starting at the current offset (idx).
//    * <P />
//    * @param buf buffer whose contents are to be matched against the
//    *            certificate encoding
//    * @exception Exception if the match fails
//    */
//   private void match(byte[] buf) throws Exception {
//       if ((short)(idx + buf.length) < (short)enc.length) {
//           for (short i = 0; i < (short)buf.length; i++) {
//               if (enc[(short)(idx++)] != buf[(short)i])
//                  ISOException.throwIt(SW_MATCH1_FAILED);
//           }
//       } else {
//          ISOException.throwIt(SW_MATCH2_FAILED);
//       }
//   }
//
//   /**
//    * Matches the specified ASN type against this certificates DER
//    * encoding (enc) starting at the current offset (idx) and returns
//    * its encoded length.
//    * <P />
//    * @param type ASN type to be matched
//    * @return the size in bytes of the sub-encoding associated with
//    *         the given type
//    * @exception IOException if the length is not formated correctly
//    */
//   private short getLen(byte type) {
//
//       if ((enc[(short)idx] == type) || ((type == ANY_STRING_TYPE) && // ordered by likelihood of match
//               ((enc[idx] == PRINTSTR_TYPE)
//                       || (enc[idx] == TELETEXSTR_TYPE)
//                       || (enc[idx] == UTF8STR_TYPE)
//                       || (enc[idx] == IA5STR_TYPE) || (enc[idx] == UNIVSTR_TYPE)))) {
//           idx++;
//           short size = (short)(enc[idx++] & 0xff);
//           if (size >= 128) {
//               short tmp = (short)(size - 128);
//               // NOTE: for now, all sizes must fit short two bytes
//               if ((tmp > 2) || ((short)(idx + tmp) > enc.length)) {
//                  ISOException.throwIt(SW_LEN_1_ERROR);
//               } else {
//                   size = 0;
//                   while (tmp > 0) {
//                       size = (short)((size << 8) + (enc[(short)(idx++)] & 0xff));
//                       tmp--;
//                   }
//               }
//           }
//           return size;
//       }
//       ISOException.throwIt(SW_LEN_2_ERROR);
//       return (short)0;
//   }
//
//   /**
//    * Expects to see a PKCS1 algorithm identifier in the DER encoding
//    * (enc) starting at the current offset (idx).
//    * <P />
//    * @return a single-byte algorithm identifier, e.g. MD5_RSA, MD2_RSA
//    * @exception IOException if an error is encountered during parsing
//    */
//   private byte getAlg() {
//       byte val=0;
//
//       try {
//           match(PKCS1Seq);
//           val = enc[idx++];
//           match(NullSeq);
//           return val;
//       } catch (Exception e) {
//          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//       }
//       return val;
//   }
//
//   /**
//    * Parses a SubjectName or IssuerName in the DER encoding
//    * (enc) starting at the current offset (idx) and ending
//    * at end.
//    * <P />
//    * @param end ending offset for the DER-encoded name
//    * @return a human friendly byte[] representation of the name
//    */
//   private byte[] getName(short end) {
//       byte[] name = new byte[3];
//       //Util.arrayCopy(enc, idx, name, (short)0, (short)(end-idx));
//
//       
//       for(short i = idx; i < end-3;i++){
//          if(enc[i] == (byte) 68 && enc[i+1] == (byte) 79 && enc[i+2] == (byte) 77){
//             Util.arrayCopy(enc,(short)(i+3), name, (short)0, (short)3);
//          }
//       }
//       
//       idx = end;
//       //System.out.println(new String(name));
//       
//       //for(short i=0; i<end;i++) {
//         // System.out.print(name[i] + " ");
//       //}
//       
//       return name;
////       
////       short nameLen = 0;
////       short len = 0;
////       short cidx; // index where the most recently seen name component starts
////       short clen; // Component length
////       byte[] label = null;
////       short aidx;
////
////       while (idx < end) {
////           if (nameLen != 0) {
////               // this is not the first time so insert a separator
////               name[(short)(nameLen++)] = (byte) ';';
////           }
////
////           getLen(SET_TYPE);
////           getLen(SEQUENCE_TYPE);
////
////           /*
////            * Save the start of name component, e.g CommonName
////            * ... and its length
////            */
////           clen = getLen(OID_TYPE);
////           cidx = idx;
////           idx += clen;
////
////           /*
////            * At this point we tag the name component, e.g. C= or hex
////            * if unknown.
////            */
////           if ((clen == 3) && (enc[cidx] == 0x55)
////                   && (enc[cidx + 1] == 0x04)) {
////               // begins with id-at, so try to see if we have a label
////               aidx = (short)(enc[cidx + 2] & 0xFF);
////               if ((aidx < nameAttr.length)
////                       && (nameAttr[aidx][0] != 0)) {
////                  label = new byte[nameAttr[aidx].length];
////                  Util.arrayCopy(nameAttr[aidx], (short)0, label, (short)0, (short)nameAttr[aidx].length);
////               } else {
////                  Util.arrayCopy(enc, cidx, label, (short)0, clen);
////               }
////           } else if (Util.arrayCompare(enc, cidx, EMAIL_ATTR_OID, (short)0,(short)
////                   EMAIL_ATTR_OID.length)==0) {
////              Util.arrayCopy(EMAIL_ATTR_LABEL, (short)0, label, (short)0, (short)EMAIL_ATTR_LABEL.length);
////           } else {
////              Util.arrayCopy(enc, cidx, label, (short)0, clen);
////           }
////
////           for (short i = 0; i < label.length; i++) {
////               name[(short)(nameLen++)] = (byte) label[i];
////           }
////
////           name[nameLen++] = (byte) '=';
////
////           len = getLen(ANY_STRING_TYPE);
////
////           if (len > 0) {
////               for (short i = 0; i < len; i++) {
////                   name[(short)(nameLen++)] = enc[(short)(idx++)];
////               }
////           }
////       }
////       
////       return name;
//   }
//
//   /**
//    * Gets a byte[] representation of the UTC time whose DER ecnoding
//    * is contained in the specified buffer.
//    * <P />
//    * @param buf buffer containing the DER encoding of UTC Time
//    * @param off starting offset of the encoding inside buf
//    * @return a byte[] represntation of the UTC time in the form
//    * yy/mm/dd hh:mm:ss
//    * @exception IOException if an error is encountered during parsing
//    */
//   private static Date getUTCTime(byte[] buf, short off)
//           throws IOException {
//       short[] period = new short[6]; // year, month, day, hour, minute, second
//
//       if (buf[(short)(off + UTC_LENGTH - 1)] != (byte) 'Z')
//          ISOException.throwIt(SW_UTCTIME_1_ERROR);
//       for (short i = 0; i < 6; i++) {
//           period[i] = 0;
//           if ((buf[(short)(2 * i + off)] < (byte) '0')
//                   || (buf[(short)(2 * i + off)] > (byte) '9'))
//              ISOException.throwIt(SW_UTCTIME_2_ERROR);
//           period[i] = (short)(buf[(short)(2 * i + off)] - (short) '0');
//           if ((buf[(short)(2 * i + off + 1)] < (byte) '0')
//                   || (buf[(short)(2 * i + off + 1)] > (byte) '9'))
//              ISOException.throwIt(SW_UTCTIME_3_ERROR);
//           period[i] = (short)((period[i] * 10)
//                   + (buf[(short)(2 * i + off + 1)] - (short) '0'));
//       }
//
//       if (period[(short)0] < 50) { // from rfc2459
//           period[(short)0] += 2000;
//       } else {
//           period[(short)0] += 1900;
//       }
//
//       return new Date(period);
//   }
//
//   /**
//    * Parses X.509v3 extensions in the certificate encoding until
//    * the specified index.
//    * <p />
//    * @param end index of the last byte in the certificate encoding
//    *        to be processed
//    */
//   private void parseExtensions(short end) {
//       /*
//        * NOTE: If one does not wish to support v3 extensions
//        * at all (to save code), one can simply set badExt to
//        * true and return -- the code that actually parses extensions
//        * can be commented out
//        */
//       short extId = -1;
//       short extIdIdx = 0;
//       short extIdLen = 0;
//       boolean crit;
//       short extValIdx = 0;
//       short extValLen = 0;
//       short tmp;
//
//       getLen((byte) 0xa3); // extensions start with 0xa3
//       getLen(SEQUENCE_TYPE);
//       while (idx < end) {
//           extId = -1;
//           getLen(SEQUENCE_TYPE);
//           extIdLen = getLen(OID_TYPE);
//           extIdIdx = idx;
//           idx += extIdLen;
//           crit = false;
//           if ((enc[(short)idx] == 0x01) && (enc[(short)(idx + 1)] == 0x01)) {
//               idx += 2;
//               crit = (enc[idx++] == (byte) 0xff) ? true : false;
//           }
//           extValLen = getLen(OCTETSTR_TYPE);
//           extValIdx = idx;
//           if ((enc[(short)extIdIdx] == 0x55) && (enc[(short)(extIdIdx + 1)] == 0x1d)) {
//               // Do we recognize this? NOTE: id-ce is 0x55, 0x1d
//               switch (enc[(short)(extIdIdx + 2)] & 0xff) {
//               case 0x0f: // keyUsage = id-ce 15
//                   extId = 15;//"KU";
//                   if (keyUsage == -1) {
//                       keyUsage = 0;
//                   }
//
//                   tmp = (short)(getLen(BITSTRING_TYPE) - 1);
//                   short unused = enc[(short)(idx++)]; // get unused bits in last octet
//                   byte b = 0;
//
//                   // process each bit in the bitbyte[] starting with
//                   // the most significant
//                   for (short i = 0; i < (short)((tmp << 3) - unused); i++) {
//                       if ((i % 8) == 0) {
//                           b = enc[(short)(idx++)];
//                       }
//
//                       if (b < 0) {
//                           keyUsage |= 1 << i;
//                       }
//
//                       b = (byte) (b << 1);
//                   }
//
//                   break;
//
//               case 0x11: // subAltName = id-ce 17
//                   short start = (short)(idx + 4);
//                   short length = (short)(extValLen - 4);
//                   extId = 17;//"SAN";
//
//                   /*
//                    * First byte stores the type e.g. 1=rfc822Name(email),
//                    * 2=dNSName, 6=URI etc
//                    */
//                   subAltNameType = (byte) (enc[(short)(idx + 2)] - 0x80);
//
//                 
//                   switch (subAltNameType) {
//                   case TYPE_EMAIL_ADDRESS:
//                   case TYPE_DNS_NAME:
//                   case TYPE_URI:
////                       for (short i = 0; i < length; i++) {
////                           temp.append((byte) enc[start + i]);
////                       }
////
////                       subAltName = temp.tobyte[]();
//                       break;
//
//                   default:
//                       subAltName = new byte[length];
//                       for (short i = 0; i < length; i++) {
//                           ((byte[]) subAltName)[i] = enc[(short)(start + i)];
//                       }
//                   }
//                   break;
//               case 0x13: // basicConstr = id-ce 19
//                   hasBC = true;
//                   extId = 19;//"BC";
//                   tmp = getLen(SEQUENCE_TYPE);
//                   if (tmp == 0)
//                       break;
//                   // ca is encoded as an ASN boolean (default is false)
//                   if ((enc[(short)idx] == 0x01) && (enc[(short)(idx + 1)] == 0x01)
//                           && (enc[(short)(idx + 2)] == (byte) 0xff)) {
//                       isCA = true;
//                       idx += 3;
//                   }
//
//                   /*
//                    * path length constraint is encoded as optional ASN
//                    * integer
//                    */
//                   if ((enc[idx] == 0x02) && (enc[(short)(idx + 1)] != 0)) {
//                       tmp = getLen(INTEGER_TYPE);
//                       pLenConstr = 0;
//                       for (short i = 0; i < tmp; i++) {
//                           pLenConstr = (short)((pLenConstr << 16)
//                                   + enc[(short)(idx + i)]);
//                       }
//                       idx += tmp;
//                   } else {
//                       if (isCA)
//                           pLenConstr = UNLIMITED_CERT_CHAIN_LENGTH;
//                   }
//                   break;
//
//               case 0x25: // extendedKeyUsage = id-ce 37
//                   extId = 37;// "EKU";
//                   if (extKeyUsage == -1) {
//                       extKeyUsage = 0;
//                   }
//
//                   getLen(SEQUENCE_TYPE);
//                   short kuOidLen;
//                   while (idx < (short)(extValIdx + extValLen)) {
//                       kuOidLen = getLen(OID_TYPE);
//                       if ((kuOidLen == (short)(ID_KP.length + 1))
//                               && Util.arrayCompare(enc, idx, ID_KP, (short)0,
//                                     (short)ID_KP.length)==0
//                               && (enc[(short)(idx + ID_KP.length)] > 0)
//                               && (enc[(short)(idx + ID_KP.length)] < 9)) {
//                           extKeyUsage |= (1 << (enc[(short)(idx + ID_KP.length)]));
//                       } else {
//                           if (crit)
//                               badExt = true;
//                       }
//                       idx += kuOidLen;
//                   }
//
//                   if (!crit) {
//                       // ignore extended key usage if not critical
//                       extKeyUsage = -1;
//                   }
//
//                   break;
//               /*
//                * Extensions which we do not currently support include:
//                * subjectDirectoryAttribute 0x09,
//                * subjectKeyIdentifier 0x0e, privateKeyUsagePeriod 0x10,
//                * issuerAltName 0x12, cRLNumber 0x14, reasonCode 0x15,
//                * instructionCode 0x17, invalidityDate 0x18,
//                * deltaCRLIndicator 0x1b, issuingDistributionPoint 0x1c,
//                * certificateIssuer 0x1d, nameConstraints 0x1e,
//                * cRLDistributionPoints 0x1f, certificatePolicies 0x20,
//                * policyMappings 0x21, authorityKeyIdentifier 0x23,
//                * policyConstraints 0x24
//                */
//               }
//           }
//
//                        if ((extId == -1) && crit)
//               badExt = true;
//
//           idx = (short)(extValIdx + extValLen);
//       }
//
//       if (idx != end) {
//          ISOException.throwIt(SW_EXTENSIONS_INVALID);
//       }
//
//   } // Done processing extensions
//
//   /**
//    * Creates a certificate by parsing the ASN.1 DER X.509 certificate
//    * encoding in the specified buffer.<BR />
//    * <B>NOTE:</B> In the standard edition, equivalent functionality
//    * is provided by CertificateFactory.generateCertificate(InputStream).
//    * <P />
//    * @param buf byte array to be read
//    * @param off offset within the byte array
//    * @param len number of bytes to be read
//    * @return a certificate object corresponding to the DER encoding
//    *         or null (in case of an encoding problem)
//    * @exception IOException if there is a parsing error
//    */
//   public void parseCertificate(byte[] buf,
//           short off, short len){
//       /*
//        * force bad parameter errors now, so later we can consider any out of
//        * bounds errors to be parsing errors
//        */
//       short test = (short)(buf[(short)off] + (short)buf[(short)(len - 1)] + (short)buf[(short)(off + len - 1)]);
//
//       try {
//           short start = 0;
//           short size = 0;
//           byte[] hash = new byte[20]; // for SHA1 fingerprint
//
//           short publicKeyLen;
//           short publicKeyPos;
//           short modulusPos;
//           short modulusLen;
//           short exponentPos;
//           short exponentLen;
//
//           // Compute the MD5 fingerprint
//           MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
//           
//           md.doFinal(buf, (short)off, (short)len, hash, (short)0);
//
//           /*
//            * Create a new certificate and fill its attributes by parsing
//            * the DER encoding
//            */
//
//           // Prepare to parse this certificate
//           this.idx = 0;
//           // Set the encoding
//           this.enc = new byte[len];
//           Util.arrayCopy(buf, (short)off, this.enc, (short)0, (short)len);
//           // ... and the fingerprint
//           this.fp = new byte[hash.length];
//           Util.arrayCopy(hash, (short)0, this.fp, (short)0, (short)hash.length);
//
//           /*
//            * A Certificate is a sequence of a TBSCertificate, a signature
//            * algorithm identifier and the signature
//            */
//           this.getLen(SEQUENCE_TYPE);
//           // Now read the TBS certificate
//           this.TBSStart = this.idx;
//           size = this.getLen(SEQUENCE_TYPE);
//         
//           short sigAlgIdx = (short)(this.idx + size);
//           this.TBSLen = (short)(sigAlgIdx - this.TBSStart);
//           // Now parse the version
//           if ((this.enc[this.idx] & 0xf0) == 0xa0) {
//              this.idx++;
//             
//               size = (short)(this.enc[this.idx++] & 0xff);
//               if ((short)(this.idx + size) > this.enc.length) {
//                  ISOException.throwIt(SW_CERT_DATA_INVALID);
//               }
//
//               this.version = (byte) (this.enc[(short)(this.idx + (size - 1))]);
//               this.idx += size;
//           } else {
//              this.version = 1; // No explicit version value
//           }
//
//           // Expect the serial number coded as an integer
//           size = this.getLen(INTEGER_TYPE);
//           serialNumber = new byte[size];
//           Util.arrayCopy(this.enc, this.idx, serialNumber, (short)0, (short)size);
//           this.idx += size;
//
//           // Expect the signature AlgorithmIdentifier
//           byte id = this.getAlg();
//                       
//           // Expect the issuer name
//           start = this.idx;
//           size = this.getLen(SEQUENCE_TYPE);
//           short end = (short)(this.idx + size);
//           try {
//              this.issuer = this.getName(end);
//               
//           } catch (Exception e) {
//              ISOException.throwIt(SW_CERT_ISSUER_INVALID);
//           }
//           
//         
//           // Validity is a sequence of two UTCTime values
//           try {
//              this.match(ValiditySeq);
//               // get start time
//              this.match(UTCSeq);
//              this.from = getUTCTime(this.enc, this.idx);
//              this.idx += UTC_LENGTH;
//               // get end time
//              this.match(UTCSeq);
//              this.until = getUTCTime(this.enc, this.idx);
//              this.idx += UTC_LENGTH;
//           } catch (Exception e) {
//              ISOException.throwIt(SW_CERT_DATA_INVALID);
//           }
//
//           // Expect the subject name
//           start = this.idx;
//           size = this.getLen(SEQUENCE_TYPE);
//           end = (short)(this.idx + size);
//         
//           if (size != 0) {
//               try {
//                  this.subject = this.getName(end);
//               } catch (Exception e) {
//                  ISOException.throwIt(SW_CERT_SUBJECT_INVALID);
//               }
//           }
//           if (Util.arrayCompare(subject, (short)0, issuer, (short)0, (short)subject.length)==0) {
//               selfSigned = true;
//           }
//           //System.out.println(new String(subject));
//           // NOTE: the subject can be null (empty sequence) if
//           // subjectAltName is present
//
//           // Parse the subject public key information
//         
//
//           publicKeyLen = this.getLen(SEQUENCE_TYPE);
//           publicKeyPos = this.idx;
//
//           // Match the algorithm Id
//           id = this.getAlg();
//           
//
//           if (id != RSA_ENCRYPTION) {
//               // skip the public key
//              this.idx = (short)(publicKeyPos + publicKeyLen);
//           }
//
//           // Get the bit byte[]
//           this.getLen(BITSTRING_TYPE);
//           if (this.enc[this.idx++] != 0x00) {
//              ISOException.throwIt(SW_CERT_DATA_INVALID);
//           }
//
//           this.getLen(SEQUENCE_TYPE);
//           size = this.getLen(INTEGER_TYPE);
//           if (this.enc[this.idx] == (byte) 0x00) {
//               // strip off the sign byte
//               size--;
//               this.idx++;
//           }
//
//           // Build the RSAPublicKey
//           modulusPos = this.idx;
//           modulusLen = size;         
//
//           this.idx += size;
//
//           size = this.getLen(INTEGER_TYPE);
//           if (this.enc[this.idx] == (byte) 0x00) {
//               // strip off the sign byte
//               size--;
//               this.idx++;
//           }
//
//           exponentPos = this.idx;
//           exponentLen = size;           
//           
//           this.pubKey =(RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)(modulusLen*8), false);
//           pubKey.setExponent(this.enc, (short)exponentPos, (short)exponentLen);
//           pubKey.setModulus(this.enc, (short)modulusPos, (short)modulusLen);
//
//           this.idx += size;
//           if (this.idx != sigAlgIdx) {
//              if (this.version <= 1) {
////                 ISOException.throwIt(SW_CERT_DATA_INVALID);
//               } else {
//                  this.parseExtensions(sigAlgIdx);
//               }
//           }
//
//           // get the signatureAlgorithm
//           this.sigAlg = this.getAlg();
//
//           
//           /*
//            * If this is a supported signature algorithm, compute and save
//            * the hash of TBSCertificate. A null TBSCertHash indicates
//            * the use of an unsupported signature algorithm (see verify())
//            */
//           md = null;
//           if (this.sigAlg == SHA1_RSA) {
//               md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
//           }
//
//           if (md != null) {
//              this.TBSCertHash = new byte[md.getLength()];
//               md.doFinal(buf, (short)(off + this.TBSStart), (short)this.TBSLen, this.TBSCertHash, (short)0);
//           }
//
//           // get the signature
//           size = this.getLen(BITSTRING_TYPE);
//           if (this.enc[this.idx++] != 0x00) {
//              ISOException.throwIt(SW_CERT_SIG_INVALID);
//           }
//
//           /*
//            * We pad the signature to a multiple of 8-bytes before storing
//            * since we only support RSA modulus lengths that are multiples
//            * of 8 bytes and the two should match for decryption to succeed.
//            */
//           short sigLen = (short)(((short)((size - 1) + 7) >>> 3) << 3);
//           this.signature = new byte[sigLen];
//           Util.arrayCopy(this.enc, (short)this.idx, this.signature,
//                   (short)(sigLen - (size - 1)), (short)(size - 1));
//
//         
//           return;
//       } catch (Exception e) {
//          ISOException.throwIt(SW_CERT_PARSE_FAILED);
//       }
//   }
//
//
//
//   /**
//    * Gets the MD5 fingerprint of this certificate.<BR />
//    * <b>NOTE:</b> this implementation returns a byte array filled
//    * with zeros if there is no fingerprint associated with this
//    * certificate. This may happen if a null was passed to the
//    * X509Certificate constructor.
//    * <P />
//    * @return a byte array containing this certificate's MD5 hash
//    */
//   public byte[] getFingerprint() {
//       byte[] res = new byte[16];
//       if (fp != null)
//          Util.arrayCopy(fp, (short)0, res, (short)0, (short)res.length);
//       return res;
//   }
//
//   /**
//    * Gets the name of this certificate's issuer. <BR />
//    * <B>NOTE:</B> FORMAT is: C=BE;OU=eGOV;CN=NAME
//    * <P />
//    * @return a byte[] containing this certificate's issuer in
//    * user-friendly form
//    */
//   public byte[] getIssuer() {
//       return issuer;
//   }
//
//   /**
//    * Gets the name of this certificate's subject. <BR />
//    * <B>NOTE:</B> FORMAT is: C=BE;OU=eGOV;CN=NAME
//    * <P />
//    * @return a byte[] containing this certificate's subject in
//    * user-friendly form
//    */
//   public byte[] getSubject() {
//       return subject;
//   }
//
//   /**
//    * Gets the NotBefore date from the certificate's validity period.
//    * <P />
//    * @return a date before which the certificate is not valid
//    */
//   public Date getNotBefore() {
//       return from;
//   }
//
//   /**
//    * Gets the NotAfter date from the certificate's validity period.
//    *
//    * @return a date after which the certificate is not valid (expiration
//    * date)                                           
//    */
//   public Date getNotAfter() {
//       return until;
//   }
//
//   /**
//    * Checks if a certificate has any (version 3) extensions that
//    * were not properly processed and continued use of this certificate
//    * may be inconsistent with the issuer's intent. This may happen, for
//    * example, if the certificate has unrecognized critical extensions.
//    *
//    * @exception CertificateException with a reason ofr BAD_EXTENSIONS if
//    *    there are any bad extensions
//    */
//   public void checkExtensions() {
//       if (badExt) {
//          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//       }
//   }
//
//   /**
//    * Checks if the certificate is valid on the specified time. It is
//    * if the specified time is within the certificate's validity
//    * period.
//    * @param time the time in milliseconds for which a certificate's
//    * validity is to be checked
//    */
//   public short checkValidity(Date time) {
//     
//       if (time.isDateOlder(from)==-1) { //time < from
//          return (short)1; //not yet valid
//       }
//
//       if (time.isDateOlder(until)==1) { //time > until
//           return (short)-1; // expired
//       }
//       return (short)0; //valid
//   }
// 
//
//   /**
//    * Gets the public key from this certificate.
//    * <P />
//    * @return the public key contained in the certificate
//    *
//    * @exception CertificateException if public key is not a supported type
//    *            (could not be parsed).
//    */
//   public PublicKey getPublicKey()  {
//       if (pubKey == null) {
//          ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
//       }
//       return pubKey;
//   }
//
//   /**
//    * Gets the raw X.509 version number of this certificate. Version 1 is 0.
//    *
//    * @return the X.509 logic version number (1, 2, 3) of the certificate
//    */
//   public short getVersion() {
//       return (short)(version+1);
//   }
//
//   /**
//    * Gets the certificate constraints path length from the
//    * <code>BasicConstraints</code> extension. <P />
//    *
//    * The <code>BasicConstraints</code> extension identifies whether the
//    * subject of the certificate is a Certificate Authority (CA) and how
//    * deep a certification path may exist through the CA. The
//    * <code>pathLenConstraint</code> field (see below) is meaningful only
//    * if <code>cA</code> is set to TRUE. In this case, it gives the maximum
//    * number of CA certificates that may follow this certificate in a
//    * certification path. A value of zero indicates that only an end-entity
//    * certificate may follow in the path. <P />
//    *
//    * Note that for RFC 2459 this extension is always marked critical
//    * if <code>cA</code> is TRUE, meaning this certificate belongs to a
//    * Certificate Authority. <P />
//    *
//    * The ASN.1 definition for this is:
//    * <PRE>
//    *  BasicConstraints ::= SEQUENCE {
//    *        cA                  BOOLEAN DEFAULT FALSE,
//    *        pathLenConstraint   INTEGER (0..MAX) OPTIONAL
//    *  }
//    *  </PRE>
//    *
//    * @return MISSING_PATH_LENGTH_CONSTRAINT if the
//    * <code>BasicConstraints</code> extension is absent or the subject
//    * of the certificate is not a CA. If the subject of the certificate
//    * is a CA and <code>pathLenConstraint</code> does not appear,
//    * <code>UNLIMITED_CERT_CHAIN_LENGTH</code> is returned to indicate that
//    * there is no limit to the allowed length of the certification path.
//    * In all other situations, the actual value of the
//    * <code>pathLenConstraint</code> is returned.
//    */
//   public short getBasicConstraints() {
//       if (isCA) {
//           return pLenConstr;
//       } else {
//           return MISSING_PATH_LENGTH_CONSTRAINT;
//       }
//   }
//
//   /**
//    * Gets a bit vector (in the form of an short) in which
//    * each position represents a purpose for which the public key in
//    * the certificate may be used (iff that bit is set). The correspondence
//    * between bit positions and purposes is as follows: <BR />
//    * <TABLE>
//    * <TR><TD>digitalSignature</TD> <TD>0</TD> </TR>
//    * <TR><TD>nonRepudiation</TD>   <TD>1</TD> </TR>
//    * <TR><TD>keyEncipherment</TD>  <TD>2</TD> </TR>
//    * <TR><TD>dataEncipherment</TD> <TD>3</TD> </TR>
//    * <TR><TD>keyAgreement</TD>     <TD>4</TD> </TR>
//    * <TR><TD>keyCertSign</TD>      <TD>5</TD> </TR>
//    * <TR><TD>cRLSign</TD>          <TD>6</TD> </TR>
//    * <TR><TD>encipherOnly</TD>     <TD>7</TD> </TR>
//    * <TR><TD>decipherOnly</TD>     <TD>8</TD> </TR>
//    * </TABLE>
//    * <P />
//    * @return a bitvector indicating approved key usage of the certificate
//    * public key, -1 if a KeyUsage extension is not present.
//    */
//   public short getKeyUsage() {
//       return keyUsage;
//   }
//
//   /**
//    * Gets a bit vector (in the form of an short) in which
//    * each position represents a purpose for which the public key in
//    * the certificate may be used (iff that bit is set). The correspondence
//    * between bit positions and purposes is as follows: <BR />
//    * <TABLE>
//    * <TR><TD>serverAuth</TD>       <TD>1</TD> </TR>
//    * <TR><TD>clientAuth</TD>       <TD>2</TD> </TR>
//    * <TR><TD>codeSigning</TD>      <TD>3</TD> </TR>
//    * <TR><TD>emailProtection</TD>  <TD>4</TD> </TR>
//    * <TR><TD>ipsecEndSystem</TD>   <TD>5</TD> </TR>
//    * <TR><TD>ipsecTunnel</TD>      <TD>6</TD> </TR>
//    * <TR><TD>ipsecUser</TD>        <TD>7</TD> </TR>
//    * <TR><TD>timeStamping</TD>     <TD>8</TD> </TR>
//    * </TABLE>
//    * <P />
//    * @return a bitvector indicating extended usage of the certificate
//    * public key, -1 if a critical extendedKeyUsage extension is not present.
//    */
//   public short getExtKeyUsage() {
//       return extKeyUsage;
//   }
//
//   /**
//    * Gets the type of subject alternative name.
//    *
//    * @return type of subject alternative name
//    */
//   public short getSubjectAltNameType() {
//       return subAltNameType;
//   }
//
//   /**
//    * Gets the subject alternative name or null if it was not in the
//    * certificate.
//    *
//    * @return type of subject alternative name or null
//    */
//   public Object getSubjectAltName() {
//       return subAltName;
//   }
//
//   /**
//    * Gets the printable form of the serial number of this
//    * <CODE>Certificate</CODE>.
//    * If the serial number within the <CODE>certificate</CODE>
//    * is binary is should be formatted as a byte[] using
//    * hexadecimal notation with each byte represented as two
//    * hex digits separated byte ":" (Unicode x3A).
//    * For example,  27:56:FA:80.
//    * @return A byte[] containing the serial number
//    * in user-friendly form; <CODE>NULL</CODE> is returned
//    * if there is no serial number.
//    */
//   public byte[] getSerialNumber() {
//       return serialNumber;
//   }
//
//   /**
//    * Checks if this certificate was signed using the private key
//    * corresponding to the specified public key.
//    *
//    * @param k public key to be used for verifying certificate signature
//    *
//    * @exception CertificateException if there is an error
//    */
//   public void verify(PublicKey k) {
//       RSAPublicKey pk;
//
//       if (!(k instanceof  PublicKey)) {
//          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//       }
//
//       pk = (RSAPublicKey) k;
//
//       /*
//        * NOTE: uncomment if selfSigned certificates must not be checked
//        *
//       if (selfSigned) {
//           if (pubKey.equals(pk)) {
//               return;
//           }
//
//           ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//           return;
//       }
//        */
//       if (signature == null) {
//          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//          return;
//       }
//
//       if (TBSCertHash == null) {
//          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//          return;
//       }
//
//       short modLen = pk.getSize();
//       byte[] result = new byte[(short)(modLen/8)];
//
//       short val;
//
//       /*
//        * NOTE: We can not use the Signature class because, at this
//        * point, we do not have TBSCertificate (just its hash). The
//        * Signature class needs raw data and computes a hash internally.
//        */
//       try {
//           Cipher rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
//
//           rsa.init(pk, Cipher.MODE_DECRYPT);
//           val = rsa.doFinal(signature, (short)0, (short)signature.length, result, (short)0);
//       } catch (Exception e) {
//          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
//          return ;
//       }
//
//       /*
//        * NOTE: the decrypted value includes an ASN DER
//        * encoding of
//        * DigestInfo ::= SEQUENCE {
//        *       digestAlgorithm DigestAlgorithmIdentifier,
//        *       digest Digest }
//        * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//        * Digest ::= OCTET byte[]
//        *
//        *
//        * For SHA-1, the 20-byte hash will be preceded by
//        * 3021300906052b0e03021a05000414
//        * 30 21       33: SEQUENCE
//        * 30 09        9: . SEQUENCE
//        * 06 05        5: . . OID 1.3.14.3.2.26 (SHA-1 digest OID)
//        *              0: 2b 0e 03 02 1a
//        * 05 00        0: . . NULL (null parameters)
//        * 04 14       20: . <20-byte hash>
//        */
//
//       if ((sigAlg == SHA1_RSA)
//               && (val == (short)(PREFIX_SHA1.length + TBSCertHash.length))
//               && Util.arrayCompare(result, (short)0, PREFIX_SHA1, (short)0,
//                     (short)PREFIX_SHA1.length)==0
//               && Util.arrayCompare(result, (short)PREFIX_SHA1.length,
//                       TBSCertHash, (short)0, (short)TBSCertHash.length)==0) {
//           return;
//       }
//
//       ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//   }
//
//   /**
//    * Gets the name of the algorithm used to sign the certificate.
//    * <P />
//    * @return the name of signature algorithm
//    */
//   public byte[] getSigAlgName() {
//       /*
//        * These are ordered to maximize the likelihood of an
//        * early match, md5WithRSA seems the most common
//        */
//      if (sigAlg == SHA1_RSA)
//         return new byte[]{'S','H','A','1','w','i','t','h','R','S','A'};
//       else if (sigAlg == NONE)
//           return new byte[]{'N','o','n','e'};
//      else
//         return new byte[]{'U','n','k','n','o','w','n','(',sigAlg,')'};
//   }
//
// 
//}