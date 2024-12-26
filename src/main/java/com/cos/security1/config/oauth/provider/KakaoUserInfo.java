package com.cos.security1.config.oauth.provider;

import java.util.LinkedHashMap;
import java.util.Map;

public class KakaoUserInfo implements OAuth2UserInfo{

    private Map<String, Object> attributes; // oauth2User.getAttributes()

    public KakaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {


        Object object = attributes.get("kakao_account");
        LinkedHashMap accountMap = (LinkedHashMap) object;
        String email = (String) accountMap.get("email");

        int atIndex = email.indexOf('@');
        String localPart = email.substring(0, atIndex);
        return localPart + "@kakao.com";
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
