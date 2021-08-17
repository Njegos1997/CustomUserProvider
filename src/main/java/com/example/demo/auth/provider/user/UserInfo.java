package com.example.demo.auth.provider.user;

import java.util.ArrayList;
import java.util.List;

public class UserInfo {

	private int total;
	private List<Records> records = new ArrayList<>();
	private boolean success;
	private String message;
	
	
	
	public boolean isSuccess() {
		return success;
	}
	public void setSuccess(boolean success) {
		this.success = success;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public int getTotal() {
		return total;
	}
	public void setTotal(int total) {
		this.total = total;
	}
	public List<Records> getRecords() {
		return records;
	}
	public void setRecords(List<Records> records) {
		this.records = records;
	} 
	

	
}
