"""Reading configuration from the env files."""

import pytest

from entra_server.settings import ENV_FILES, Settings, env_files_found, load_settings

CONFIG = "ENTRA_TENANT_ID=from-env-file\nENTRA_CLIENT_ID=client-from-env-file\n"


@pytest.fixture
def project(tmp_path, monkeypatch):
    """An empty working directory with no ENTRA_* variables in the environment."""
    overridable = (
        "TENANT_ID", "CLIENT_ID", "BASE_URL", "SESSION_TTL", "COOKIE_SECRET", "BACKEND_CLIENT_SECRET"
    )
    for name in overridable:
        monkeypatch.delenv(f"ENTRA_{name}", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_values_are_read_from_the_env_file(project):
    (project / ".env").write_text(f"{CONFIG}ENTRA_SESSION_TTL=60\n")

    settings = load_settings()

    assert settings.tenant_id == "from-env-file"
    assert settings.session_ttl == 60
    assert settings.issuer == "https://login.microsoftonline.com/from-env-file/v2.0"


def test_defaults_apply_to_anything_the_env_file_omits(project):
    (project / ".env").write_text(CONFIG)

    settings = load_settings()

    assert settings.base_url == "http://localhost:3000"
    assert settings.session_ttl == 8 * 60 * 60
    assert not settings.backend_enabled


def test_env_local_wins_over_env(project):
    (project / ".env").write_text(f"{CONFIG}ENTRA_BASE_URL=http://localhost:3000\n")
    (project / ".env.local").write_text("ENTRA_BASE_URL=https://public.example.com\n")

    settings = load_settings()

    assert settings.base_url == "https://public.example.com"
    assert settings.redirect_uri == "https://public.example.com/oauth2/token"
    assert settings.cookies_are_secure


def test_the_environment_wins_over_both(project, monkeypatch):
    (project / ".env").write_text(f"{CONFIG}ENTRA_BASE_URL=http://localhost:3000\n")
    (project / ".env.local").write_text("ENTRA_BASE_URL=https://public.example.com\n")
    monkeypatch.setenv("ENTRA_BASE_URL", "http://from-the-environment:8080")

    assert load_settings().base_url == "http://from-the-environment:8080"


def test_the_secret_stays_out_of_reprs(project):
    (project / ".env").write_text(CONFIG)
    (project / ".env.local").write_text("ENTRA_BACKEND_CLIENT_SECRET=hunter2\n")

    settings = load_settings()

    assert settings.backend_client_secret.get_secret_value() == "hunter2"
    assert "hunter2" not in repr(settings)  # a stray log of the settings must not leak it


def test_the_cookie_secret_is_optional_and_stays_out_of_reprs(project):
    (project / ".env").write_text(CONFIG)
    assert load_settings().cookie_secret.get_secret_value() == ""  # a key per process

    (project / ".env.local").write_text("ENTRA_COOKIE_SECRET=signing-key\n")

    settings = load_settings()

    assert settings.cookie_secret.get_secret_value() == "signing-key"
    assert "signing-key" not in repr(settings)


def test_unknown_keys_are_ignored(project):
    # An env file is shared with other tooling; a stray key must not stop startup.
    (project / ".env").write_text(f"{CONFIG}SOME_OTHER_TOOL=1\nENTRA_NOT_A_SETTING=1\n")

    assert load_settings().tenant_id == "from-env-file"


def test_missing_configuration_is_reported_clearly(project):
    # No env file at all: the usual cause is starting from the wrong directory.
    with pytest.raises(SystemExit) as caught:
        load_settings()

    message = str(caught.value)
    assert "ENTRA_TENANT_ID" in message and "ENTRA_CLIENT_ID" in message
    assert str(project) in message  # says which directory was searched


def test_other_validation_errors_are_not_swallowed(project):
    (project / ".env").write_text(f"{CONFIG}ENTRA_SESSION_TTL=not-a-number\n")

    with pytest.raises(ValueError) as caught:
        load_settings()
    assert not isinstance(caught.value, SystemExit)


@pytest.mark.parametrize("present", [(), (".env",), (".env", ".env.local")])
def test_env_files_found_reports_what_exists(project, present):
    for name in present:
        (project / name).write_text(CONFIG)

    assert [str(path) for path in env_files_found()] == list(present)


def test_settings_declares_the_env_files_it_reads():
    assert Settings.model_config["env_file"] == ENV_FILES
