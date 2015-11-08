package org.jboss.as.security.remoting;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.cert.CertificateEncodingException;

import org.jboss.as.security.SecurityLogger;
import org.jboss.as.security.remoting.RemotingLoginModule;

/**
 * 
 */

/**
 * @author cadjai
 * 
 */
public class ExtendedRemotingLoginModule extends RemotingLoginModule {

	private static final SecurityLogger LOGGER = SecurityLogger.ROOT_LOGGER;

	private static final String USE_CLIENT_CERT_OPTION = "useClientCert";

	private static final String[] ALL_OPTIONS = new String[] { USE_CLIENT_CERT_OPTION };

	private boolean useClientCert = false;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		addValidOptions(ALL_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);
		if (options.containsKey(USE_CLIENT_CERT_OPTION)) {
			useClientCert = Boolean.parseBoolean(options.get(
					USE_CLIENT_CERT_OPTION).toString());
		}
	}

	@Override
	public boolean login() throws LoginException {

		boolean isLoggedIn = super.login();

		if (useClientCert) {
			Object credential = sharedState
					.get("javax.security.auth.login.password");
			X509Certificate cert = getX509FromRawCertificate((javax.security.cert.X509Certificate) credential);
			if (cert != null) {
				sharedState.put("javax.security.auth.login.password", cert);
			}
		}
		loginOk = isLoggedIn;
		return isLoggedIn;
	}

	/**
	 * Adding this to convert the javax.security.cert.X509Certificate to the
	 * newer java.security.cert.X509Certificate because the former is deprecated
	 * and most APIs that will use the useClientCert option of the
	 * RemotingLoginModule will expect the latter format.
	 * 
	 * @param credential
	 * @return
	 */
	private X509Certificate getX509FromRawCertificate(
			javax.security.cert.X509Certificate credential) {
		java.security.cert.X509Certificate cert = null;
		byte[] encRaw;

		try {
			encRaw = credential.getEncoded();
			ByteArrayInputStream bais = new ByteArrayInputStream(encRaw);
			CertificateFactory certFact = CertificateFactory
					.getInstance("X509");
			cert = (X509Certificate) certFact.generateCertificate(bais);
		} catch (CertificateEncodingException e) {
			LOGGER.error(
					"Error Encoding the raw javax.security.cert.X509Certificate ",
					e);
		} catch (CertificateException e) {
			LOGGER.error(
					"Error Generating a java.security.cert.X509Certificate ", e);
		}

		return cert;
	}

}
