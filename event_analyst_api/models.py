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
                3, message="Username must be at least 3 characters long"
            ),
        ],
    )
    email = models.EmailField(max_length=50, unique=True)
    is_verified = models.BooleanField(default=False, blank=True)
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
    address = models.CharField(max_length=255, blank=True)
    longitude = models.DecimalField(max_digits=18, decimal_places=15, blank=True)
    latitude = models.DecimalField(max_digits=18, decimal_places=15, blank=True)
    start_date = models.DateTimeField(blank=True, null=True)
    end_date = models.DateTimeField(blank=True, null=True)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    event_owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

    def __str__(self):
        return self.title


class Photo(models.Model):
    photoId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    path = models.ImageField(upload_to="images/")
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Photo for {self.event}/{self.event_id} -> Photo ID: {self.photoId}"


class EventStatistic(models.Model):
    eventStatisticId = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    event = models.OneToOneField(Event, on_delete=models.CASCADE)

    genderAnalysis = models.JSONField(default=dict)
    raceAnalysis = models.JSONField(default=dict)
    ageAnalysis = models.JSONField(default=dict)

    def __str__(self):
        return f"Statistics for event {self.event.title}"
