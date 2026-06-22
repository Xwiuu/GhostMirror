from __future__ import annotations

from ghostmirror.modules.api_security.jwt_intelligence import JWTIntelligence


def _make_jwt(alg: str = "HS256", kid: bool = False, typ: bool = False,
              has_exp: bool = True, iss: str = "", aud: str = "",
              none_alg: bool = False) -> str:
    import base64, json
    header = {"alg": "none" if none_alg else alg}
    if kid:
        header["kid"] = "key1"
    if typ:
        header["typ"] = "JWT"
    payload = {"sub": "1234567890", "name": "Test User", "iat": 1516239022}
    if has_exp:
        payload["exp"] = 9999999999
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{b64(header)}.{b64(payload)}.signature"


class TestJWTIntelligence:
    def test_no_token(self):
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {}, "body": ""}])
        assert not result["detected"]

    def test_detects_jwt_in_authorization_header(self):
        token = _make_jwt()
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert result["detected"]
        assert result["total_tokens_found"] == 1

    def test_detects_jwt_in_body(self):
        token = _make_jwt()
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {}, "body": f'{{"token": "{token}"}}'}])
        assert result["detected"]
        assert result["total_tokens_found"] == 1

    def test_token_redaction(self):
        token = _make_jwt()
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert len(result["redacted_tokens"]) == 1
        redacted = result["redacted_tokens"][0]
        assert redacted.startswith("eyJ")
        assert "****" in redacted
        assert len(redacted) < len(token)

    def test_detects_algorithm(self):
        token = _make_jwt(alg="RS256")
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert "RS256" in result["algorithms"]

    def test_detects_kid(self):
        token = _make_jwt(kid=True)
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert result["has_kid"]

    def test_detects_exp(self):
        token = _make_jwt(has_exp=True)
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert result["has_exp"]

    def test_detects_missing_exp(self):
        token = _make_jwt(has_exp=False)
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert not result["has_exp"]

    def test_detects_none_algorithm(self):
        token = _make_jwt(none_alg=True)
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert result["has_none_alg_indicator"]
        assert "none" in result["weak_algorithms"]

    def test_detects_issuer(self):
        token = _make_jwt(iss="https://auth.example.com")
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert "https://auth.example.com" in result["issuers"]

    def test_detects_audience(self):
        token = _make_jwt(aud="api.example.com")
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert "api.example.com" in result["audiences"]

    def test_handles_typ(self):
        token = _make_jwt(typ=True)
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert result["has_typ"]

    def test_detects_jwt_in_x_api_key(self):
        token = _make_jwt()
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {"X-API-Key": f"Bearer {token}"}}])
        assert result["detected"]

    def test_no_false_positive_from_regular_text(self):
        jwt = JWTIntelligence()
        result = jwt.analyze([{"headers": {}, "body": "regular text without tokens"}])
        assert not result["detected"]
