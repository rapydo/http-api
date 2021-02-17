from datetime import datetime

import pytz

from restapi.config import TESTING
from restapi.services.authentication import DEFAULT_GROUP_NAME, BaseAuthentication
from restapi.utilities.faker import get_faker


def initialize_testing_environment(auth: BaseAuthentication) -> None:

    assert TESTING

    faker = get_faker()
    email = faker.ascii_email()
    password = faker.password(strong=True)
    default_group = auth.get_group(name=DEFAULT_GROUP_NAME)
    user = auth.create_user(
        {
            "email": email,
            "name": "Default",
            "surname": "User",
            "password": password,
            "last_password_change": datetime.now(pytz.utc),
        },
        # It will be expanded with the default role
        roles=[],
    )
    auth.add_user_to_group(user, default_group)
    # This is required to execute the commit on sqlalchemy...
    auth.save_user(user)

    for _ in range(0, 20):
        payload, full_payload = auth.fill_payload(user)
        token = auth.create_token(payload)
        auth.save_token(user, token, full_payload)
