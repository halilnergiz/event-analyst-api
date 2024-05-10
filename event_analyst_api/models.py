from django.contrib.auth.models import AbstractUser
from django.core.validators import (
    RegexValidator,
    MinLengthValidator,
)
from django.db import models


class CustomUser(AbstractUser):
    username = models.CharField(
        max_length=30,
        unique=True,
        validators=[
            RegexValidator(regex=r"^[a-zA-Z0-9]+$"),
            MinLengthValidator(
                4, message="Password must be at least 6 characters long"
            ),
        ],
    )
    email = models.EmailField(max_length=40, unique=True)
    is_verified = models.BooleanField(default=False)
    password = models.CharField(
        max_length=30,
        validators=[
            RegexValidator(r"^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&]+$"),
            MinLengthValidator(
                8, message="Password must be at least 8 characters long"
            ),
        ],
    )

    USERNAME_FIELD = "username"

    def __str__(self):
        return self.username
