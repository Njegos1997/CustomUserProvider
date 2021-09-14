package com.example.demo.auth.provider.user;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomOIDCProtocolMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

	public static final String PROVIDER_ID = "oidc-customprotocolmapper";

	private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

	private static final Logger log = LoggerFactory.getLogger(CustomOIDCProtocolMapper.class);

	static {

		ProviderConfigProperty property;

		property = new ProviderConfigProperty();
		property.setName(ProtocolMapperUtils.MULTIVALUED);
		property.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
		property.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
		property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		configProperties.add(property);
		OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
		OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomOIDCProtocolMapper.class);

	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {

		return configProperties;
	}

	@Override
	public String getDisplayCategory() {

		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getDisplayType() {

		return "Evooq Protocol Mapper";
	}

	@Override
	public String getId() {
		log.info("SOAM: inside getId");
		
		return PROVIDER_ID;
	}

	@Override
	public String getHelpText() {
		log.info("SOAM: inside getHelpText");
		
		return "some help text";
	}

	public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
			KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
		log.info("SOAM: inside transformAccessToken");
		
		token.getOtherClaims().put("assetmaxToken", CustomUserStorageProvider.assetmaxToken);
		token.getOtherClaims().put("actionableContent", CustomUserStorageProvider.actionableContent);

		setClaim(token, mappingModel, userSession, session, clientSessionCtx);
		return token;
	}

	public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo,
			String tokenClaimName) {

		ProtocolMapperModel mapper = new ProtocolMapperModel();
		mapper.setName(name);
		mapper.setProtocolMapper(PROVIDER_ID);
		mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
		Map<String, String> config = new HashMap<String, String>();
		config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, tokenClaimName);
		if (accessToken)
			config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
		if (idToken)
			config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
		mapper.setConfig(config);
		return mapper;
	}
}
