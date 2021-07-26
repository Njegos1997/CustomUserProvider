package com.example.demo.auth.provider.user;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomUserStorageProvider
		implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, UserQueryProvider {

	private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
	private KeycloakSession ksession;
	private ComponentModel model;
	private Properties properties;
	private HashMapUserStore hashMapUserStore;

	protected Map<String, UserModel> loadedUsers = new HashMap<>();

	public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model,
			HashMapUserStore hashMapUserStore) {
		this.ksession = ksession;
		this.model = model;
		this.hashMapUserStore = hashMapUserStore;
	}

	public CustomUserStorageProvider(KeycloakSession session) {
		this.ksession = session;
	}

	@Override
	public void close() {
		log.info("[I30] close()");

	}

	@Override
	public UserModel getUserById(String id, RealmModel realm) {
		log.info("[I35] getUserById({})", id);
		/*
		 * log.info("[I35] getUserById({})", id); StorageId sid = new StorageId(id);
		 * return getUserByUsername(sid.getExternalId(), realm);
		 */
		StorageId storageId = new StorageId(id);
		String username = storageId.getExternalId();
		return getUserByUsername(username, realm);
	}

	@Override
	public UserModel getUserByUsername(String username, RealmModel realm) {
		log.info("[I41] getUserByUsername({})", username);
		UserModel adapter = loadedUsers.get(username);
		if (adapter == null) {
			User user = new User(username, "");
			if (user != null) {
				adapter = createAdapter(realm, username);
				loadedUsers.put(username, adapter);
			}
		}
		return adapter;
	}

	protected UserModel createAdapter(RealmModel realm, final String email) {
		return new AbstractUserAdapter(ksession, realm, model) {
			@Override
			public String getUsername() {
				return email;
			}
			
			@Override
			public String getEmail() {
				return email;
			}
		};
	}

	@Override
	public UserModel getUserByEmail(String email, RealmModel realm) {
		log.info("[I48] getUserByEmail({})", email);
		UserModel adapter = loadedUsers.get(email);
		if (adapter == null) {
			User user = new User(email, "");
			if (user != null) {
				adapter = createAdapter(realm, email);
				loadedUsers.put(email, adapter);
			}
		}
		return adapter;
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		log.info("[I57] supportsCredentialType({})", credentialType);
		// return PasswordCredentialModel.TYPE.endsWith(credentialType);
		return credentialType.equals(PasswordCredentialModel.TYPE);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})", realm.getName(), user.getUsername(),
				credentialType);
		// In our case, password is the only type of credential, so we allways return
		// 'true' if
		// this is the credentialType
		try {
			String password = hashMapUserStore.getUser(user.getUsername()).getPassword();
			return credentialType.equals(PasswordCredentialModel.TYPE) && password != null;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		// return supportsCredentialType(credentialType);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
		log.info("[I57] isValid(realm={},user={},credentialInput.type={})", realm.getName(), user.getUsername(),
				credentialInput.getType());

		boolean successfulLogin = false;
		log.info("successfulLogin: ", successfulLogin);

		try {
			
			String result = sendPOST("http://localhost:8765/assetmax/moik/ext/login/login", user.getUsername(), credentialInput.getChallengeResponse());
			log.info(result);

			log.info("success");

			if (!supportsCredentialType(credentialInput.getType()))
			{
				log.info("NINE DOBRO");
				return false;
			}

			try {
				if (result.contains("tokenId")) {
					log.info("LOGOVAN JEEEE");
					successfulLogin = true;
				}

			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}

		} catch (IOException e) {
			log.info("Error In In valid", e);
		}

		return successfulLogin;

	}

	@Override
	public int getUsersCount(RealmModel realm) {
		log.info("[I93] getUsersCount: realm={}", realm.getName());
		/*
		 * try (Connection c = DbUtil.getConnection(this.model)) { Statement st =
		 * c.createStatement(); st.execute("select count(*) from users"); ResultSet rs =
		 * st.getResultSet(); rs.next(); return rs.getInt(1); } catch (SQLException ex)
		 * { throw new RuntimeException("Database error:" + ex.getMessage(), ex); }
		 */
		return 0;
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm) {
		return getUsers(realm, 0, 5000); // Keep a reasonable maxResults
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
		log.info("[I113] getUsers: realm={}", realm.getName());

		/*
		 * try (Connection c = DbUtil.getConnection(this.model)) { PreparedStatement st
		 * = c.prepareStatement(
		 * "select username, firstName,lastName, email, birthDate from users order by username limit ? offset ?"
		 * ); st.setInt(1, maxResults); st.setInt(2, firstResult); st.execute();
		 * ResultSet rs = st.getResultSet(); List<UserModel> users = new ArrayList<>();
		 * while (rs.next()) { users.add(mapUser(realm, rs)); } return users; } catch
		 * (SQLException ex) { throw new RuntimeException("Database error:" +
		 * ex.getMessage(), ex); }
		 */
		return null;
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm) {
		return searchForUser(search, realm, 0, 5000);
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
		log.info("[I139] searchForUser: realm={}", realm.getName());
		/*
		 * try (Connection c = DbUtil.getConnection(this.model)) { PreparedStatement st
		 * = c.prepareStatement(
		 * "select username, firstName,lastName, email, birthDate from users where username like ? order by username limit ? offset ?"
		 * ); st.setString(1, search); st.setInt(2, maxResults); st.setInt(3,
		 * firstResult); st.execute(); ResultSet rs = st.getResultSet(); List<UserModel>
		 * users = new ArrayList<>(); while (rs.next()) { users.add(mapUser(realm, rs));
		 * } return users; } catch (SQLException ex) { throw new
		 * RuntimeException("Database error:" + ex.getMessage(), ex); }
		 */
		return null;
	}

	@Override
	public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
		return searchForUser(params, realm, 0, 5000);
	}

	@Override
	public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult,
			int maxResults) {
		return getUsers(realm, firstResult, maxResults);
	}

	@Override
	public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
		return Collections.emptyList();
	}

	@Override
	public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
		return Collections.emptyList();
	}

	@Override
	public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
		return Collections.emptyList();
	}

	private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {

		DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
		CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
				.email(rs.getString("email")).firstName(rs.getString("firstName")).lastName(rs.getString("lastName"))
				.birthDate(rs.getDate("birthDate")).build();

		return user;
	}

	private static String sendPOST(String url, String email, String password) throws IOException {

		String result = "";
		HttpPost post = new HttpPost(url);
		log.info(email);
		log.info(password);

		// add request parameters or form parameters
		List<NameValuePair> urlParameters = new ArrayList<>();
		urlParameters.add(new BasicNameValuePair("auth", "emailpassword"));
		urlParameters.add(new BasicNameValuePair("email", email));
		urlParameters.add(new BasicNameValuePair("password", password));

		post.setEntity(new UrlEncodedFormEntity(urlParameters));

		try (CloseableHttpClient httpClient = HttpClients.createDefault();
				CloseableHttpResponse response = httpClient.execute(post)) {

			result = EntityUtils.toString(response.getEntity());
		}

		return result;
	}

}
