package com.example.mycollector.Security;


public class UserAccount {
    private long userSeq;        // admcd
    private String userId;       // admid
    private String passwordHash; // passwd (DB에 저장된 BCrypt 해시)
    private String userName;     // admnm
    private String userRole;     // rolecd

    public long getUserSeq() {
        return userSeq;
    }

    public void setUserSeq(long userSeq) {
        this.userSeq = userSeq;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }
}
