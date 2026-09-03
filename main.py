from phish_guard_ai.crew import check_message


def run_message_investigation(message):

    return check_message(
        message=message
    )


def run_screenshot_investigation(image_path):

    return check_message(
        message="",
        image_path=image_path
    )


def run_combined_investigation(
    message="",
    image_path=None
):

    return check_message(
        message=message,
        image_path=image_path
    )


if __name__ == "__main__":

    sample = """
URGENT: Your account will be suspended in 30 minutes.

Verify your account immediately at:
http://example.com/login

Enter your username, password and OTP.
"""

    result = run_message_investigation(
        sample
    )

    print("\nCyberGuard Result:")
    print(result)