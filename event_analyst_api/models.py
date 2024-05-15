from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import (
    RegexValidator,
    MinLengthValidator,
)

import uuid



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


class Event(models.Model):
    eventId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    start_date = models.DateTimeField(blank=True)
    end_date = models.DateTimeField(blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True)
    address = models.CharField(max_length=255, blank=True)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    event_owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return self.title  # TODO


class Photo(models.Model):
    photoId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    path = models.ImageField(upload_to="images/")
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Photo for {self.event}/{self.event_id} -> Photo ID: {self.photoId}"
