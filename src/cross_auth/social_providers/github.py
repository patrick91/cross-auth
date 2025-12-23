from __future__ import annotations

import logging
from datetime import datetime
from typing import Literal, TypedDict

import httpx
from pydantic import AnyUrl, BaseModel, EmailStr, Field

from .oauth import OAuth2Exception, OAuth2Provider

logger = logging.getLogger(__name__)


class GitHubConfig(TypedDict, total=False):
    """Configuration for GitHub email selection behavior."""

    # For LOGIN: "any_verified" or "stored_only"
    login_email_matching: Literal["any_verified", "stored_only"]

    # For SIGNUP: require primary email
    require_primary_for_signup: bool

    # Block noreply emails (e.g., 123+user@users.noreply.github.com)
    allow_noreply_emails: bool

    # If primary unverified, fall back to any verified email
    fallback_to_verified_if_primary_unverified: bool


class GitHubPlan(BaseModel):
    collaborators: int
    name: str
    space: int
    private_repos: int


class GitHubUser(BaseModel):
    login: str = Field(examples=["octocat"])
    id: int = Field(examples=[1])
    user_view_type: str | None = None
    node_id: str = Field(examples=["MDQ6VXNlcjE="])
    avatar_url: AnyUrl = Field(
        ..., examples=["https://github.com/images/error/octocat_happy.gif"]
    )
    gravatar_id: str | None = Field(examples=["41d064eb2195891e12d0413f63227ea7"])
    url: AnyUrl = Field(examples=["https://api.github.com/users/octocat"])
    html_url: AnyUrl = Field(examples=["https://github.com/octocat"])
    followers_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/followers"]
    )
    following_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/following{/other_user}"]
    )
    gists_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/gists{/gist_id}"]
    )
    starred_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/starred{/owner}{/repo}"]
    )
    subscriptions_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/subscriptions"]
    )
    organizations_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/orgs"]
    )
    repos_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/repos"]
    )
    events_url: str = Field(
        ..., examples=["https://api.github.com/users/octocat/events{/privacy}"]
    )
    received_events_url: AnyUrl = Field(
        ..., examples=["https://api.github.com/users/octocat/received_events"]
    )
    type: str = Field(examples=["User"])
    site_admin: bool
    name: str | None = Field(examples=["monalisa octocat"])
    company: str | None = Field(examples=["GitHub"])
    blog: str | None = Field(examples=["https://github.com/blog"])
    location: str | None = Field(examples=["San Francisco"])
    email: EmailStr | None = Field(examples=["octocat@github.com"])
    notification_email: EmailStr | None = Field(
        default=None, examples=["octocat@github.com"]
    )
    hireable: bool | None
    bio: str | None = Field(examples=["There once was..."])
    twitter_username: str | None = Field(default=None, examples=["monalisa"])
    public_repos: int = Field(examples=[2])
    public_gists: int = Field(examples=[1])
    followers: int = Field(examples=[20])
    following: int = Field(examples=[0])
    created_at: datetime = Field(examples=["2008-01-14T04:33:35Z"])
    updated_at: datetime = Field(examples=["2008-01-14T04:33:35Z"])

    plan: GitHubPlan | None = None
    business_plus: bool | None = None
    ldap_dn: str | None = None


class GitHubProvider(OAuth2Provider):
    id = "github"

    authorization_endpoint = "https://github.com/login/oauth/authorize"
    token_endpoint = "https://github.com/login/oauth/access_token"
    user_info_endpoint = "https://api.github.com/user"
    scopes = ["user:email"]
    supports_pkce = True

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        config: GitHubConfig | None = None,
    ):
        super().__init__(client_id, client_secret)
        self.config: GitHubConfig = config or {}
        self._pending_emails: list[dict] | None = None

    def _fetch_github_emails(self, token: str) -> list[dict]:
        """Fetch all emails from GitHub API."""
        try:
            response = httpx.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch user emails: {str(e)}")
            raise OAuth2Exception(
                error="server_error",
                error_description="Failed to fetch user emails from GitHub",
            )

    def fetch_user_info(self, token: str) -> dict:
        info = super().fetch_user_info(token)

        # Fetch and cache emails for later resolution by resolve_email
        self._pending_emails = self._fetch_github_emails(token)

        # Ensure name is always a string, falling back to login (username)
        if not info.get("name"):
            info["name"] = info["login"]

        return info

    def resolve_email(
        self,
        user_info: dict,
        is_login: bool,
        stored_email: str | None = None,
    ) -> str:
        """Select the appropriate email based on login/signup context."""
        emails = self._pending_emails
        self._pending_emails = None  # Clear after use

        if not emails:
            raise OAuth2Exception(
                error="server_error",
                error_description="No emails available from GitHub",
            )

        return self._select_email(emails, is_login, stored_email)

    def _select_email(
        self,
        emails: list[dict],
        is_login: bool,
        stored_email: str | None = None,
    ) -> str:
        """Select email based on config and flow type."""
        allow_noreply = self.config.get("allow_noreply_emails", False)

        # Filter out noreply emails if configured
        if not allow_noreply:
            emails = [
                e for e in emails
                if not e["email"].endswith("@users.noreply.github.com")
            ]

        # Get all verified emails
        verified_emails = [e for e in emails if e.get("verified")]

        if not verified_emails:
            raise OAuth2Exception(
                error="server_error",
                error_description="No verified email found on GitHub account",
            )

        if is_login:
            return self._select_email_for_login(verified_emails, stored_email)
        else:
            return self._select_email_for_signup(emails, verified_emails)

    def _select_email_for_login(
        self,
        verified_emails: list[dict],
        stored_email: str | None,
    ) -> str:
        """Select email for login flow."""
        login_matching = self.config.get("login_email_matching", "any_verified")

        if login_matching == "stored_only" and stored_email:
            # Only accept the stored email if it's still verified
            for email in verified_emails:
                if email["email"] == stored_email:
                    return stored_email
            raise OAuth2Exception(
                error="server_error",
                error_description="The email associated with your account is no longer verified on GitHub",
            )

        # "any_verified" - accept any verified email
        # Prefer stored email if available and verified
        if stored_email:
            for email in verified_emails:
                if email["email"] == stored_email:
                    return stored_email

        # Return any verified email (prefer primary)
        for email in verified_emails:
            if email.get("primary"):
                return email["email"]

        return verified_emails[0]["email"]

    def _select_email_for_signup(
        self,
        all_emails: list[dict],
        verified_emails: list[dict],
    ) -> str:
        """Select email for signup flow."""
        require_primary = self.config.get("require_primary_for_signup", True)
        allow_fallback = self.config.get(
            "fallback_to_verified_if_primary_unverified", True
        )

        if require_primary:
            # Find primary email
            primary = next((e for e in all_emails if e.get("primary")), None)

            if primary and primary.get("verified"):
                return primary["email"]

            if allow_fallback:
                # Primary not verified, fall back to any verified
                for email in verified_emails:
                    if not email.get("primary"):  # Skip primary since it's unverified
                        return email["email"]
                # If all verified emails are primary (edge case), use first verified
                if verified_emails:
                    return verified_emails[0]["email"]

            raise OAuth2Exception(
                error="server_error",
                error_description="Primary email must be verified for signup",
            )

        # Not requiring primary - use any verified email (prefer primary)
        for email in verified_emails:
            if email.get("primary"):
                return email["email"]

        return verified_emails[0]["email"]
