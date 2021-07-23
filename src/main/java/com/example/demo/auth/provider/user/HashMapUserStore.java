package com.example.demo.auth.provider.user;

import java.util.HashMap;

public class HashMapUserStore {

	private HashMap<String, User> hashMapStorage;
	
	public HashMapUserStore() {
		this.hashMapStorage = new HashMap<>();
		this.hashMapStorage.put("alex", new User("alex", "alex"));
		this.hashMapStorage.put("kevin", new User("kevin", "kevin"));
	}
	
	public User getUser(String username){
        return this.hashMapStorage.get(username);
    }
}
