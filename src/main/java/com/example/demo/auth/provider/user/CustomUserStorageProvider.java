package com.example.demo.auth.provider.user;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.NewCookie;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class CustomUserStorageProvider
		implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, UserQueryProvider {

	private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
	private KeycloakSession ksession;
	private ComponentModel model;
	public static String assetmaxToken;
	public static String actionableContent;
	private String responseBody;

	protected Map<String, UserModel> loadedUsers = new HashMap<>();

	public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
		this.ksession = ksession;
		this.model = model;
	}

	public CustomUserStorageProvider(KeycloakSession session) {
		this.ksession = session;
	}

	@Override
	public UserModel getUserById(String id, RealmModel realm) {
		log.info("[I35] getUserById({})", id);

		StorageId storageId = new StorageId(id);
		String username = storageId.getExternalId();
		return getUserByUsername(username, realm);
	}

	@Override
	public UserModel getUserByUsername(String username, RealmModel realm) {
		log.info("[I41] getUserByUsername({})", username);
		UserModel adapter = loadedUsers.get(username);;
		if (adapter == null) {
			// User user = new User(username, "");
			// if (user != null) {
			adapter = createAdapter(realm, username);
			loadedUsers.put(username, adapter);
			// }
		}
		return adapter;
	}

	protected UserModel createAdapter(RealmModel realm, final String email) {
		return new AbstractUserAdapter(ksession, realm, model) {

			@Override
			public String getUsername() {
				return email;
			}

			/*
			 * @Override public String getEmail() { return email; }
			 */
		};
	}

	@Override
	public UserModel getUserByEmail(String email, RealmModel realm) {
		log.info("[I48] getUserByEmail({})", email);

		UserModel adapter = loadedUsers.get(email);
		if (adapter == null) {
			// User user = new User(email, "");
			// if (user != null) {
			adapter = createAdapter(realm, email);
			loadedUsers.put(email, adapter);
		}
		return adapter;
	}

	@Override
	public boolean supportsCredentialType(String credentialType) {
		log.info("[I57] supportsCredentialType({})", credentialType);
		return credentialType.equals(PasswordCredentialModel.TYPE);
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})", realm.getName(), user.getUsername(),
				credentialType);
		return supportsCredentialType(credentialType);
	}

	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
		log.info("[I57] isValid(realm={},user={},credentialInput.type={})", realm.getName(), user.getUsername(),
				credentialInput.getType());

		boolean isSuccessfulLogedIn = false;

		try {

			CloseableHttpResponse response = login("https://demo.iam.evooq.io/assetmax/moik/ext/login/login",
					user.getUsername(), credentialInput.getChallengeResponse());


			LoginResponse loginBodyResponse = mapLoginResponse(responseBody);
			log.info(loginBodyResponse.getTokenId());

			log.info(responseBody);
			addEvooqCookie(response, loginBodyResponse);

			assetmaxToken = loginBodyResponse.getTokenId();
			
			getUserInfo();
			if (!supportsCredentialType(credentialInput.getType())) {
				return false;
			}
			if (loginBodyResponse.getTokenId() != null) {
				isSuccessfulLogedIn = true;
			} else {
				return false;
			}

		} catch (IOException e) {
			log.info("Error In In valid", e);
		}

		return isSuccessfulLogedIn;

	}

	private LoginResponse mapLoginResponse(String loginResponse) {

		ObjectMapper mapper = new ObjectMapper();
		LoginResponse loginBodyResponse = new LoginResponse();
		try {
			loginBodyResponse = mapper.readValue(loginResponse, LoginResponse.class);
			return loginBodyResponse;
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return loginBodyResponse;
	}

	private CloseableHttpResponse login(String url, String email, String password) throws IOException {

		HttpPost post = new HttpPost(url);
		log.info(email);
		log.info(password);

		// add request parameters
		List<NameValuePair> urlParameters = new ArrayList<>();
		urlParameters.add(new BasicNameValuePair("auth", "emailpassword"));
		urlParameters.add(new BasicNameValuePair("email", email));
		urlParameters.add(new BasicNameValuePair("password", password));

		post.setEntity(new UrlEncodedFormEntity(urlParameters));
		
		try (CloseableHttpClient httpClient = HttpClients.createDefault();
				CloseableHttpResponse response = httpClient.execute(post)) {

			responseBody = EntityUtils.toString(response.getEntity());
			log.info("RESPONSE" + responseBody);
	
			return response;
		}

	}
	
	private CloseableHttpResponse getUserInfo() {
		
		BasicCookieStore cookieStore = new BasicCookieStore();
	    BasicClientCookie cookie = new BasicClientCookie("tokenId", assetmaxToken);
	    cookie.setDomain("demo.iam.evooq.io");
	    cookie.setPath("/");
	    cookieStore.addCookie(cookie);
		
	    HttpGet get = new HttpGet("https://demo.iam.evooq.io/assetmax/moik/ext/auth/current-user");
	    
	    HttpContext localContext = new BasicHttpContext();
	    localContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);
	    get.setHeader("tokenId", assetmaxToken);
	    log.info("IN INFO TOKEN" + assetmaxToken);
		CookieHelper.addCookie("tokenId", assetmaxToken, "/", null, null, NewCookie.DEFAULT_MAX_AGE,
				false, false);
	    try (CloseableHttpClient client = HttpClients.createDefault()) {

			   CloseableHttpResponse response = client.execute(get, localContext);
			   String userInfo = EntityUtils.toString(response.getEntity());
			   log.info("USER INFO:", userInfo);
			   UserInfo mappedUser = mapUserInfo(userInfo);
			   log.info("MAPPPED" + mappedUser.getRecords().get(0).getUser_additional_info());
			   actionableContent = mappedUser.getRecords().get(0).getUser_additional_info();
			   return response;

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return null;

	}
	
	private UserInfo mapUserInfo(String userInfo) {

		ObjectMapper mapper = new ObjectMapper();
		UserInfo userInfoMapped = new UserInfo();
		try {
			userInfoMapped = mapper.readValue(userInfo, UserInfo.class);
			return userInfoMapped;
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return userInfoMapped;
	}

	private void addEvooqCookie(CloseableHttpResponse response, LoginResponse loginBodyResponse) {

		response.addHeader("Set-Cookie", "tokenId=" + loginBodyResponse.getTokenId() + ";Path=/");

		CookieHelper.addCookie("tokenId", loginBodyResponse.getTokenId(), "/", null, null, NewCookie.DEFAULT_MAX_AGE,
				false, false);
	}

	@Override
	public int getUsersCount(RealmModel realm) {
		log.info("[I93] getUsersCount: realm={}", realm.getName());
		return 0;
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm) {
		return getUsers(realm, 0, 5000); // Keep a reasonable maxResults
	}

	@Override
	public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
		log.info("[I113] getUsers: realm={}", realm.getName());
		return null;
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm) {
		return searchForUser(search, realm, 0, 5000);
	}

	@Override
	public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
		log.info("[I139] searchForUser: realm={}", realm.getName());
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

	@Override
	public void close() {
		log.info("[I30] close()");
	}

}
