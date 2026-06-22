from __future__ import annotations

from ghostmirror.modules.api_security.oauth_intelligence import OAuthIntelligence


class TestOAuthIntelligence:
    def test_no_oauth(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/api/users"}])
        assert not result["detected"]

    def test_detects_keycloak(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/auth", "body": "keycloak"}])
        assert result["detected"]
        assert "keycloak" in result["providers"]

    def test_detects_auth0(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/login", "body": "auth0"}])
        assert "auth0" in result["providers"]

    def test_detects_azure_ad(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/login", "body": "login.microsoftonline.com"}])
        assert "azure_ad" in result["providers"]

    def test_detects_okta(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/login", "body": "okta"}])
        assert "okta" in result["providers"]

    def test_detects_cognito(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/login", "body": "cognito"}])
        assert "cognito" in result["providers"]

    def test_detects_authorize_endpoint(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/oauth/authorize"}])
        assert result["has_authorize"]
        assert "/oauth/authorize" in result["endpoints"]["authorize"]

    def test_detects_token_endpoint(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/oauth/token"}])
        assert result["has_token"]

    def test_detects_userinfo_endpoint(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/userinfo"}])
        assert result["has_userinfo"]

    def test_detects_jwks_endpoint(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/.well-known/openid-configuration"}])
        assert result["has_jwks"]

    def test_detects_google(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/auth", "body": "googleapis.com/auth"}])
        assert "google" in result["providers"]

    def test_detects_github(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([{"path": "/auth", "body": "github.com/login/oauth"}])
        assert "github" in result["providers"]

    def test_all_endpoint_types_detected(self):
        oauth = OAuthIntelligence()
        result = oauth.analyze([
            {"path": "/oauth/authorize"},
            {"path": "/oauth/token"},
            {"path": "/userinfo"},
            {"path": "/.well-known/jwks"},
        ])
        assert result["has_authorize"]
        assert result["has_token"]
        assert result["has_userinfo"]
        assert result["has_jwks"]
