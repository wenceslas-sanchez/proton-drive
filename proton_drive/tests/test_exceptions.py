from proton_drive.exceptions import NotFoundError, ProtonDriveError, RateLimitError


def test_proton_drive_error_str_without_context() -> None:
    error = ProtonDriveError("Something failed")

    assert str(error) == "Something failed"


def test_proton_drive_error_str_with_context() -> None:
    error = ProtonDriveError("Failed", user_id="123", attempt=3)

    assert "Failed" in str(error)
    assert "user_id='123'" in str(error)
    assert "attempt=3" in str(error)


def test_not_found_error_has_code_404() -> None:
    error = NotFoundError("Resource not found")

    assert error.code == 404


def test_rate_limit_error_has_code_429() -> None:
    error = RateLimitError()

    assert error.code == 429
