package com.tsystems.authenticator.service;

public interface TwoFactorAuthProvider {
    //生成密钥
    String getSecretKey();

    //校验密钥
    boolean checkCode(String secret, long code, long time);
}
