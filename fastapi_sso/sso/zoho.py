"""zoho SSO Login Helper."""

from typing import ClassVar, Optional

import httpx

from fastapi_sso.sso.base import DiscoveryDocument, OpenID, SSOBase, SSOLoginError


class ZohoSSO(SSOBase):
    """Class providing login via zoho OAuth."""

    discovery_url = "https://accounts.zoho.com/.well-known/openid-configuration"
    provider = "zoho"
    scope: ClassVar = ["openid", "email", "profile"]

    async def openid_from_response(self, response: dict, session: Optional["httpx.AsyncClient"] = None) -> OpenID:
        """Return OpenID from user information provided by zoho."""
        if response.get("email_verified"):
            return OpenID(
                email=response.get("email"),
                provider=self.provider,
                id=response.get("sub"),
                first_name=response.get("given_name"),
                last_name=response.get("family_name"),
                display_name=response.get("name"),
                picture=response.get("picture"),
            )
        raise SSOLoginError(401, f"User {response.get('email')} is not verified with zoho")

    async def get_discovery_document(self) -> DiscoveryDocument:
        """Get document containing handy urls."""
        async with httpx.AsyncClient() as session:
            response = await session.get(self.discovery_url)
            content = response.json()
            return content
