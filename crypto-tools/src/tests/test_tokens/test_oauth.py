"""
OAuth Tests
"""

import pytest
from unittest.mock import Mock
from crypto_tools.tokens.oauth import OAuthClient

class TestOAuth:
    def test_authorization_url(self):
        client = OAuthClient(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://example.com/callback"
        )
        
        url = client.get_authorization_url(scope="profile email", state="123")
        assert "response_type=code" in url
        assert "client_id=test_client" in url
        assert "scope=profile+email" in url
        assert "state=123" in url

    def test_token_exchange(self, monkeypatch):
        client = OAuthClient(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://example.com/callback"
        )
        
        # Mock requests.post
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test_token",
            "refresh_token": "test_refresh"
        }
        mock_post = Mock(return_value=mock_response)
        monkeypatch.setattr("requests.post", mock_post)
        
        token = client.get_access_token("test_code")
        assert token["access_token"] == "test_token"
        assert token["refresh_token"] == "test_refresh"

    def test_token_refresh(self, monkeypatch):
        client = OAuthClient(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="http://example.com/callback"
        )
        
        # Mock requests.post
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "new_token",
            "refresh_token": "new_refresh"
        }
        mock_post = Mock(return_value=mock_response)
        monkeypatch.setattr("requests.post", mock_post)
        
        token = client.refresh_token("old_refresh")
        assert token["access_token"] == "new_token"
        assert token["refresh_token"] == "new_refresh"