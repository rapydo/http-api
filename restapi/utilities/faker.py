import secrets
import string

from faker import Faker
from faker.providers import BaseProvider

from restapi.utilities.logs import log

FAKER_LOCALES = {
    "ar_EG": "Arabic",
    "bg_BG": "Bulgarian",
    "bs_BA": "Bosnian",
    "cs_CZ": "Czech",
    "de_DE": "German",
    "dk_DK": "Danish",
    "el_GR": "Greek",
    "en_US": "English",
    "es_ES": "Spanish",
    "et_EE": "Estonian",
    "fa_IR": "Persian",
    "fi_FI": "Finnish",
    "fr_FR": "French",
    "hi_IN": "Hindi",
    "hr_HR": "Croatian",
    "hu_HU": "Hungarian",
    # 'hy_AM': 'Armenian',
    "it_IT": "Italian",
    "ja_JP": "Japanese",
    "ka_GE": "Georgian",
    "ko_KR": "Korean",
    "lt_LT": "Lithuanian",
    "lv_LV": "Latvian",
    "ne_NP": "Nepali",
    "nl_NL": "Dutch",
    "no_NO": "Norwegian",
    "pl_PL": "Polish",
    "pt_PT": "Portuguese",
    "ro_RO": "Romanian",
    "ru_RU": "Russian",
    "sl_SI": "Slovene",
    "sv_SE": "Swedish",
    "tr_TR": "Turkish",
    "uk_UA": "Ukrainian",
    "zh_CN": "Chinese",
}


# Create a random password to be used to build data for tests
class PasswordProvider(BaseProvider):
    def password(
        self,
        length: int = 8,
        strong: bool = False,  # this enables all low, up, digits and symbols
        low: bool = True,
        up: bool = False,
        digits: bool = False,
        symbols: bool = False,
    ) -> str:

        if strong:
            if length < 16:
                length = 16
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
            # Removed \ from allowed characters
            charset = charset.replace("\\", "")

        rand = secrets.SystemRandom()

        randstr = "".join(rand.choices(charset, k=length))
        # Password is randomly resampled, can't be sure that will be covered by tests
        if low and not any(
            s in randstr for s in string.ascii_lowercase
        ):  # pragma: no cover
            log.warning(
                "Password is not strong enough: missing lower case. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        # Password is randomly resampled, can't be sure that will be covered by tests
        if up and not any(
            s in randstr for s in string.ascii_uppercase
        ):  # pragma: no cover
            log.warning(
                "Password is not strong enough: missing upper case. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        # Password is randomly resampled, can't be sure that will be covered by tests
        if digits and not any(s in randstr for s in string.digits):  # pragma: no cover
            log.warning(
                "Password is not strong enough: missing digits. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )
        # Password is randomly resampled, can't be sure that will be covered by tests
        if symbols and not any(
            s in randstr for s in string.punctuation
        ):  # pragma: no cover
            log.warning(
                "Password is not strong enough: missing symbols. Sampling again..."
            )
            return self.password(
                length, strong=strong, low=low, up=up, digits=digits, symbols=symbols
            )

        return randstr


def get_faker() -> Faker:

    loc = secrets.choice(list(FAKER_LOCALES.keys()))
    log.warning(f"Today I'm {FAKER_LOCALES.get(loc)}")
    faker = Faker(loc)

    faker.add_provider(PasswordProvider)

    return faker
