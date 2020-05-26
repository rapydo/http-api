import pytest
import string
import random
from faker import Faker
from faker.providers import BaseProvider
from restapi.server import create_app
from restapi.utilities.logs import log


@pytest.fixture
def app():
    app = create_app(testing_mode=True)
    return app


@pytest.fixture
def fake():
    fake = Faker()

    # Create a random password to be used to build data for tests
    class PasswordProvider(BaseProvider):
        def password(self, length,
                     strong=False,  # this enable all low, up, digits and symbols
                     low=True, up=False, digits=False, symbols=False):

            if strong:
                low = True
                up = True
                digits = True
                symbols = True

            charset = ""
            if low:
                charset += string.ascii_lowercase
            if up:
                charset += string.ascii_uppercase
            if digits:
                charset += string.digits
            if symbols:
                charset += string.punctuation

            rand = random.SystemRandom()

            randstr = ''.join(rand.choices(charset, k=length))
            if low and not any(s in randstr for s in string.ascii_lowercase):
                log.warning(
                    "String {} not strong enough, missing lower case characters".format(
                        randstr
                    )
                )
                return self.password(
                    length, strong=strong,
                    low=low, up=up, digits=digits, symbols=symbols
                )
            if up and not any(s in randstr for s in string.ascii_uppercase):
                log.warning(
                    "String {} not strong enough, missing upper case characters".format(
                        randstr
                    )
                )
                return self.password(
                    length, strong=strong,
                    low=low, up=up, digits=digits, symbols=symbols
                )
            if digits and not any(s in randstr for s in string.digits):
                log.warning(
                    "String {} not strong enough, missing digits".format(
                        randstr
                    )
                )
                return self.password(
                    length, strong=strong,
                    low=low, up=up, digits=digits, symbols=symbols
                )
            if symbols and not any(s in randstr for s in string.punctuation):
                log.warning(
                    "String {} not strong enough, missing symbols".format(
                        randstr
                    )
                )
                return self.password(
                    length, strong=strong,
                    low=low, up=up, digits=digits, symbols=symbols
                )

            return randstr

    fake.add_provider(PasswordProvider)
