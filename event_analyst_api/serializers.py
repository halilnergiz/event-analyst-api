from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password
from django.core.validators import RegexValidator, MinLengthValidator
from django.core.exceptions import ValidationError

from rest_framework import serializers

import os

from .models import CustomUser, Event, Photo


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["username", "email", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data["username"], email=validated_data["email"]
        )
        user.set_password(validated_data["password"])
        user.save()
        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(
        required=True,
        max_length=30,
        validators=[
            RegexValidator(r"^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&]+$"),
            MinLengthValidator(
                8, message="Password must be at least 8 characters long"
            ),
        ],
    )

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not check_password(value, user.password):
            raise serializers.ValidationError("old password is wrong")
        return value

    def update(self, instance, validated_data):
        new_password = validated_data["new_password"]
        instance.set_password(new_password)
        instance.save()
        return instance


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = CustomUser
        fields = ["token"]


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = (
            "eventId",
            "title",
            "description",
            "start_date",
            "end_date",
            "longitude",
            "latitude",
            "address",
            "createdAt",
            "updatedAt",
            "event_owner",
        )
        read_only_fields = ("event_owner",)

    def create(self, validated_data):
        validated_data["event_owner"] = self.context["request"].user
        return super().create(validated_data)


class PhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Photo
        fields = ["photoId", "event", "path", "createdAt", "updatedAt"]
        read_only_fields = ["photoId", "createdAt", "updatedAt"]

    def validate_path(self, value):
        valid_extensions = [".png", ".jpg", ".jpeg", ".svg"]
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in valid_extensions:
            raise ValidationError(
                f"Unsupported file extension: {ext}. Supported extensions are: {', '.join(valid_extensions)}"
            )
        return value
