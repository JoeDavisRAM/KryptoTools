"""
OAuth Utilities

Provides OAuth 2.0 client implementation.

Example:
    >>> oauth = OAuthClient(client_id, client_secret, redirect_uri)
    >>> auth_url = oauth.get_authorization_url()
    >>> token = oauth.get_access_token(authorization_code)
"""

import requests
from urllib.parse import urlencode
from exceptions import InvalidTokenError

class OAuthClient:
    """
    OAuth 2.0 client for authorization code flow.
    
    Args:
        client_id (str): OAuth client ID
        client_secret (str): OAuth client secret
        redirect_uri (str): Redirect URI registered with OAuth provider
        auth_endpoint (str): OAuth authorization endpoint
        token_endpoint (str): OAuth token endpoint
    """
    
    def __init__(self, client_id, client_secret, redirect_uri,
                 auth_endpoint="https://auth.example.com/authorize",
                 token_endpoint="https://auth.example.com/token"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint

    def get_authorization_url(self, scope="profile", state=None):
        """
        Get authorization URL to redirect user to OAuth provider.
        
        Args:
            scope (str): Requested scopes (space-separated)
            state (str, optional): CSRF protection state
            
        Returns:
            str: Authorization URL
        """
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope
        }
        
        if state is not None:
            params["state"] = state
            
        return f"{self.auth_endpoint}?{urlencode(params)}"

    def get_access_token(self, authorization_code):
        """
        Exchange authorization code for access token.
        
        Args:
            authorization_code (str): Authorization code from redirect
            
        Returns:
            dict: Token response (access_token, refresh_token, etc.)
        """
        try:
            data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            
            response = requests.post(
                self.token_endpoint,
                data=data,
                headers={"Accept": "application/json"}
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            raise InvalidTokenError(f"Failed to get access token: {str(e)}")

    def refresh_token(self, refresh_token):
        """
        Refresh an expired access token.
        
        Args:
            refresh_token (str): Refresh token from initial authorization
            
        Returns:
            dict: New token response
        """
        try:
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            
            response = requests.post(
                self.token_endpoint,
                data=data,
                headers={"Accept": "application/json"}
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            raise InvalidTokenError(f"Failed to refresh token: {str(e)}")