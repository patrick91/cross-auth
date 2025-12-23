Release type: patch

# GitHub provider: fallback to username when name is not set

Some GitHub users don't have a display name configured on their profile. Previously, this would result in `name` being `null` in the user info. Now, we fall back to using the GitHub username (`login`) when `name` is not set, ensuring users always have a display name.
