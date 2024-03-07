package dam.psp;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Certificator implements Runnable {

	Socket sCliente;
	DataInputStream in;

	public Certificator(Socket s) {
		
		try {
			this.sCliente = s;
			in = new DataInputStream(s.getInputStream());
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (sCliente != null)
				try {
					sCliente.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

	@Override
	public void run() {
		try {
			String command = in.readUTF();
			switch (command) {
			case "hash": {
				getHash();
				break;
			}
			case "cert": {
				saveCert();
				break;
			}
			case "cifrar": {
				encode();
				break;
			}
			default:
				sendError("ERROR:'" + command + "' no se reconoce como una petición válida");
			}
		} catch (SocketTimeoutException e) {
			sendError("ERROR:Read timed out");
		} catch (EOFException e) {
			sendError("ERROR:Se esperaba una petición");
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				sCliente.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	private void getHash() {
		try {
			MessageDigest md;
			String algoritmo = in.readUTF();
			md = MessageDigest.getInstance(algoritmo);
			byte[] bytes = in.readAllBytes();
			if (bytes.length > 0) {
				String cadena = Base64.getEncoder().encodeToString(md.digest(bytes));
				sendAnswer("OK:" + cadena);
			} else
				sendError("ERROR:Se esperaban datos");
		} catch (SocketTimeoutException e) {
			sendError("ERROR:Read timed out");
		} catch (EOFException e) {
			sendError("ERROR:Se esperaba un algoritmo");
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	private void saveCert() {
		try {
			String alias = in.readUTF();
			try {
				String base = in.readUTF();
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				byte[] byteEncoded = Base64.getDecoder().decode(base);
				Certificate cert = f.generateCertificate(new ByteArrayInputStream(byteEncoded));
				Servidor.ks.setCertificateEntry(alias, cert);
				MessageDigest md;
				md = MessageDigest.getInstance("SHA-256");
				md.update(base.getBytes());
				String cadena = Base64.getEncoder().encodeToString(md.digest());
				sendAnswer("OK:" + cadena);
			} catch (CertificateException e) {
			} catch (IllegalArgumentException e) {
				sendError("ERROR:Se esperaba Base64");
			} catch (EOFException e) {
				sendError("ERROR:Se esperaba un certificado");
			} catch (SocketTimeoutException e) {
				sendError("ERROR:Read timed out");
			}
		} catch (EOFException e) {
			sendError("ERROR:Se esperaba un alias");
		} catch (SocketTimeoutException e) {
			sendError("ERROR:Read timed out");
		} catch (IOException e) {
		} catch (KeyStoreException e) {
		} catch (NoSuchAlgorithmException e) {
		}

	}

	private void encode() {
		String alias = "";
		try {
			alias = in.readUTF();
			Certificate cert = Servidor.ks.getCertificate(alias);
			if (cert == null)
				sendAnswer("ERROR:'" + alias + "' no es un certificado");
			else {
				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
				int n;
				byte[] bloque = new byte[256];
				DataOutputStream out = new DataOutputStream(sCliente.getOutputStream());
				int contador = 0;
				while ((n = in.read(bloque)) != -1) {
					contador++;
					byte[] cifrado = c.doFinal(bloque, 0, n);
					out.writeUTF("OK:" + Base64.getEncoder().encodeToString(cifrado));
				}
				if (contador == 0) {
					sendAnswer("ERROR:Se esperaban datos");
				}
			}
		} catch (SocketTimeoutException e) { // No entiendo porque no entra aqui, la verdad
			sendError("ERROR:Read timed out");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {
			sendError("ERROR:Se esperaba un alias");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			sendError("ERROR:'" + alias + "' no contiene una clave RSA");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

	}

	private void sendAnswer(String command) {
		try {
			new DataOutputStream(sCliente.getOutputStream()).writeUTF(command);
		} catch (SocketTimeoutException e) {
			try {
				new DataOutputStream(sCliente.getOutputStream()).writeUTF("ERROR:Read timed out");
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void sendError(String command) {
		try {
			new DataOutputStream(sCliente.getOutputStream()).writeUTF(command);
			sCliente.close();
		} catch (SocketTimeoutException e) {
			try {
				new DataOutputStream(sCliente.getOutputStream()).writeUTF("ERROR:Read timed out");
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
