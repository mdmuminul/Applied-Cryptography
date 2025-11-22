package appcrypto;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took 3.0 hours (please specify here how much time your solution required)

public class TestApplet extends Applet {
	
	private KeyPair keypair;
	private RSAPublicKey pub;
	private Cipher rsa;
	private byte[] ramBuf;
	private boolean keyGenerated;
	
	public static void install(byte[] ba, short offset, byte len) {
		(new TestApplet()).register();
	}

	private TestApplet() {
		keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
		pub = (RSAPublicKey) keypair.getPublic();
		rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		ramBuf = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		keyGenerated = false;
	}
	
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		byte ins = buf[ISO7816.OFFSET_INS];
		
		switch (ins) {
		case (byte) 0x02:
			generateKey();
			return;
		case (byte) 0x04:
			sendExponent(apdu, buf);
			return;
		case (byte) 0x06:
			sendModulus(apdu, buf);
			return;
		case (byte) 0x08:
			decryptCiphertext(apdu, buf);
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}

	private void generateKey() {
		if (!keyGenerated) {
			keypair.genKeyPair();
			rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
			keyGenerated = true;
		}
	}

	private void sendExponent(APDU apdu, byte[] buf) {
		if (!keyGenerated) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		short len = pub.getExponent(buf, (short) 0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short) 0, len);
	}

	private void sendModulus(APDU apdu, byte[] buf) {
		if (!keyGenerated) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		short len = pub.getModulus(buf, (short) 0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short) 0, len);
	}

	private void decryptCiphertext(APDU apdu, byte[] buf) {
		if (!keyGenerated) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}

		ramBuf[0] = buf[ISO7816.OFFSET_P1];
		ramBuf[1] = buf[ISO7816.OFFSET_P2];

		short ramOffset = 2;
		short offset = ISO7816.OFFSET_CDATA;
		short bytesRead = apdu.setIncomingAndReceive();

		while (bytesRead > 0) {
			Util.arrayCopyNonAtomic(buf, offset, ramBuf, ramOffset, bytesRead);
			ramOffset += bytesRead;
			bytesRead = apdu.receiveBytes(offset);
		}

		short cipherLen = ramOffset;
		short plainLen = rsa.doFinal(ramBuf, (short) 0, cipherLen, ramBuf, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength(plainLen);
		apdu.sendBytes((short) 0, plainLen);
	}
}
