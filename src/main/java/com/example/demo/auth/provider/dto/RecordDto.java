package com.example.demo.auth.provider.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RecordDto {

	private String userAdditionalInfo;
	
	@JsonProperty("user_additional_info")
	public String getUserAdditionalInfo() {
		return userAdditionalInfo;
	}
	
	public void setUserAdditionalInfo(String userAdditionalInfo) {
		this.userAdditionalInfo = userAdditionalInfo;
	}
	
}
