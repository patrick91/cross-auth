import pytest
import respx

from cross_auth.social_providers.github import GitHubConfig, GitHubProvider
from cross_auth.social_providers.oauth import OAuth2Exception

pytestmark = pytest.mark.asyncio


@pytest.fixture
def github_provider() -> GitHubProvider:
    return GitHubProvider(
        client_id="test_client_id", client_secret="test_client_secret"
    )


@pytest.fixture
def mock_user_info() -> dict:
    return {
        "login": "octocat",
        "id": 1,
        "node_id": "MDQ6VXNlcjE=",
        "avatar_url": "https://github.com/images/error/octocat_happy.gif",
        "gravatar_id": "41d064eb2195891e12d0413f63227ea7",
        "url": "https://api.github.com/users/octocat",
        "html_url": "https://github.com/octocat",
        "followers_url": "https://api.github.com/users/octocat/followers",
        "following_url": "https://api.github.com/users/octocat/following{/other_user}",
        "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
        "organizations_url": "https://api.github.com/users/octocat/orgs",
        "repos_url": "https://api.github.com/users/octocat/repos",
        "events_url": "https://api.github.com/users/octocat/events{/privacy}",
        "received_events_url": "https://api.github.com/users/octocat/received_events",
        "type": "User",
        "site_admin": False,
        "name": "monalisa octocat",
        "company": "GitHub",
        "blog": "https://github.com/blog",
        "location": "San Francisco",
        "email": "octocat@github.com",
        "hireable": None,
        "bio": "There once was...",
        "twitter_username": "monalisa",
        "public_repos": 2,
        "public_gists": 1,
        "followers": 20,
        "following": 0,
        "created_at": "2008-01-14T04:33:35Z",
        "updated_at": "2008-01-14T04:33:35Z",
    }


@pytest.fixture
def mock_emails() -> list[dict]:
    return [
        {
            "email": "octocat@github.com",
            "verified": True,
            "primary": True,
            "visibility": "public",
        },
        {
            "email": "octocat@example.com",
            "verified": True,
            "primary": False,
            "visibility": "private",
        },
    ]


@respx.mock
async def test_fetch_user_info_with_email(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = github_provider.fetch_user_info("test_token")

    assert user_info == mock_user_info
    assert user_info["email"] == "octocat@github.com"


@respx.mock
async def test_fetch_user_info_caches_emails(
    github_provider: GitHubProvider, mock_user_info: dict, mock_emails: list[dict]
):
    # Remove email from user info
    mock_user_info.pop("email")

    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(200, json=mock_emails)
    )

    user_info = github_provider.fetch_user_info("test_token")

    # Email is not set by fetch_user_info - it's set by resolve_email
    assert "email" not in user_info
    # But emails should be cached for resolve_email
    assert github_provider._pending_emails == mock_emails


@respx.mock
async def test_fetch_user_info_handles_email_fetch_error(
    github_provider: GitHubProvider, mock_user_info: dict
):
    # Remove email from user info
    mock_user_info.pop("email")

    # Mock the user info endpoint
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(200, json=mock_user_info)
    )

    # Mock the emails endpoint to fail
    respx.get("https://api.github.com/user/emails").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(Exception):
        github_provider.fetch_user_info("test_token")


@respx.mock
async def test_fetch_user_info_handles_user_info_error(github_provider: GitHubProvider):
    # Mock the user info endpoint to fail
    respx.get("https://api.github.com/user").mock(
        return_value=respx.MockResponse(500, json={"message": "Internal Server Error"})
    )

    with pytest.raises(Exception):
        github_provider.fetch_user_info("test_token")


# ============================================================================
# Tests for GitHubConfig and email selection
# ============================================================================


class TestGitHubConfig:
    def test_default_config(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        # Default config should be empty dict, methods use .get() with defaults
        assert provider.config == {}

    def test_custom_config(self):
        config: GitHubConfig = {
            "login_email_matching": "stored_only",
            "require_primary_for_signup": False,
            "allow_noreply_emails": True,
            "fallback_to_verified_if_primary_unverified": False,
        }
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        assert provider.config == config


class TestEmailSelectionForSignup:
    """Tests for _select_email with is_login=False (signup flow)."""

    def test_signup_uses_primary_verified_email(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {"email": "primary@example.com", "primary": True, "verified": True},
            {"email": "other@example.com", "primary": False, "verified": True},
        ]
        result = provider._select_email(emails, is_login=False)
        assert result == "primary@example.com"

    def test_signup_falls_back_when_primary_unverified(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {"email": "primary@example.com", "primary": True, "verified": False},
            {"email": "other@example.com", "primary": False, "verified": True},
        ]
        result = provider._select_email(emails, is_login=False)
        assert result == "other@example.com"

    def test_signup_fails_when_fallback_disabled_and_primary_unverified(self):
        config: GitHubConfig = {"fallback_to_verified_if_primary_unverified": False}
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        emails = [
            {"email": "primary@example.com", "primary": True, "verified": False},
            {"email": "other@example.com", "primary": False, "verified": True},
        ]
        with pytest.raises(OAuth2Exception) as exc:
            provider._select_email(emails, is_login=False)
        assert "Primary email must be verified" in exc.value.error_description

    def test_signup_blocks_noreply_emails_by_default(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {
                "email": "123+user@users.noreply.github.com",
                "primary": True,
                "verified": True,
            },
        ]
        with pytest.raises(OAuth2Exception) as exc:
            provider._select_email(emails, is_login=False)
        assert "No verified email found" in exc.value.error_description

    def test_signup_allows_noreply_when_configured(self):
        config: GitHubConfig = {"allow_noreply_emails": True}
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        emails = [
            {
                "email": "123+user@users.noreply.github.com",
                "primary": True,
                "verified": True,
            },
        ]
        result = provider._select_email(emails, is_login=False)
        assert result == "123+user@users.noreply.github.com"

    def test_signup_without_require_primary_uses_any_verified(self):
        config: GitHubConfig = {"require_primary_for_signup": False}
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        emails = [
            {"email": "primary@example.com", "primary": True, "verified": False},
            {"email": "other@example.com", "primary": False, "verified": True},
        ]
        result = provider._select_email(emails, is_login=False)
        assert result == "other@example.com"


class TestEmailSelectionForLogin:
    """Tests for _select_email with is_login=True (login flow)."""

    def test_login_accepts_any_verified_email_by_default(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {"email": "new@example.com", "primary": True, "verified": True},
        ]
        # Even with stored_email different, any_verified accepts new email
        result = provider._select_email(
            emails, is_login=True, stored_email="old@example.com"
        )
        assert result == "new@example.com"

    def test_login_prefers_stored_email_if_still_verified(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {"email": "new@example.com", "primary": True, "verified": True},
            {"email": "stored@example.com", "primary": False, "verified": True},
        ]
        result = provider._select_email(
            emails, is_login=True, stored_email="stored@example.com"
        )
        assert result == "stored@example.com"

    def test_login_stored_only_requires_stored_email(self):
        config: GitHubConfig = {"login_email_matching": "stored_only"}
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        emails = [
            {"email": "stored@example.com", "primary": False, "verified": True},
            {"email": "new@example.com", "primary": True, "verified": True},
        ]
        result = provider._select_email(
            emails, is_login=True, stored_email="stored@example.com"
        )
        assert result == "stored@example.com"

    def test_login_stored_only_fails_if_stored_not_verified(self):
        config: GitHubConfig = {"login_email_matching": "stored_only"}
        provider = GitHubProvider(
            client_id="id", client_secret="secret", config=config
        )
        emails = [
            {"email": "stored@example.com", "primary": False, "verified": False},
            {"email": "new@example.com", "primary": True, "verified": True},
        ]
        with pytest.raises(OAuth2Exception) as exc:
            provider._select_email(
                emails, is_login=True, stored_email="stored@example.com"
            )
        assert "no longer verified" in exc.value.error_description

    def test_login_blocks_noreply_by_default(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        emails = [
            {
                "email": "123+user@users.noreply.github.com",
                "primary": True,
                "verified": True,
            },
        ]
        with pytest.raises(OAuth2Exception) as exc:
            provider._select_email(emails, is_login=True)
        assert "No verified email found" in exc.value.error_description


class TestResolveEmail:
    """Tests for resolve_email method."""

    @respx.mock
    def test_resolve_email_uses_pending_emails(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        # Simulate what happens after fetch_user_info
        provider._pending_emails = [
            {"email": "test@example.com", "primary": True, "verified": True},
        ]
        user_info = {"id": 123, "email": "ignored@example.com"}

        result = provider.resolve_email(user_info, is_login=False)

        assert result == "test@example.com"
        assert provider._pending_emails is None  # Should be cleared

    def test_resolve_email_raises_when_no_pending_emails(self):
        provider = GitHubProvider(client_id="id", client_secret="secret")
        # No pending emails
        provider._pending_emails = None
        user_info = {"id": 123}

        with pytest.raises(OAuth2Exception) as exc:
            provider.resolve_email(user_info, is_login=False)
        assert "No emails available" in exc.value.error_description
