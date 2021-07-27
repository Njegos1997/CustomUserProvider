package com.example.demo.auth.provider.user;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomUserStorageProviderFactory
		implements UserStorageProviderFactory<CustomUserStorageProvider> {
	
	private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProviderFactory.class);
	public static final String PROVIDER_NAME = "custom-user-provider";
	
	@Override
	public CustomUserStorageProvider create(KeycloakSession ksession, ComponentModel model) {
		log.info("[I63] creating new CustomUserStorageProvider");
        return new CustomUserStorageProvider(ksession, model);
	}

	@Override
	public String getId() {
		 log.info("[I69] getId()");
	        return PROVIDER_NAME;
	}
	 
}
