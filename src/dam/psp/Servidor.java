package dam.psp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {

	static KeyStore ks;

	public static void main(String[] args) throws IOException {
		ExecutorService executor = Executors.newFixedThreadPool(100);
		try (ServerSocket sSocket = new ServerSocket(9000)) {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			System.out.println("Servidor  puerto 9000");
			while (true) {
				Socket sCliente = sSocket.accept();
				sCliente.setSoTimeout(5000);
				executor.execute(new Certificator(sCliente));
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}

}
