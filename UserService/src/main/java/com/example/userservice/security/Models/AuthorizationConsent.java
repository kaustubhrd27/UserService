package com.example.userservice.security.Models;

import java.io.Serializable;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

@Entity
@Table(name = "`authorizationConsent`")
@IdClass(AuthorizationConsent.AuthorizationConsentId.class)
public class AuthorizationConsent {
    // This code defines an AuthorizationConsent entity class,
    // which represents the consent that a user (the principal) has granted to a registered client in an OAuth 2.0 or OpenID Connect (OIDC) context.
    @Id
    private String registeredClientId;
    @Id
    private String principalName;
    @Column(length = 1000)
    private String authorities;

    public String getRegisteredClientId() {
        return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getAuthorities() {
        return authorities;
    }

    public void setAuthorities(String authorities) {
        this.authorities = authorities;
    }

    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;

        public String getRegisteredClientId() {
            return registeredClientId;
        }

        public void setRegisteredClientId(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public String getPrincipalName() {
            return principalName;
        }

        public void setPrincipalName(String principalName) {
            this.principalName = principalName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            //  Check if both references point to the same object
            if (o == null || getClass() != o.getClass()) return false;
            // Check if 'o' is null or if the objects are of different classes
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            // Cast the object to AuthorizationConsentId
            return registeredClientId.equals(that.registeredClientId) && principalName.equals(that.principalName);
        }

        @Override
        public int hashCode() {
            // This utility method generates a hash code by combining the hash codes of multiple fields
            // (registeredClientId and principalName in this case).
            return Objects.hash(registeredClientId, principalName);
        }
        // The hashCode method of String is used internally for both fields.
        // This ensures that if two objects have the same values for registeredClientId and principalName,
        // they will generate the same hash code.
    }
}